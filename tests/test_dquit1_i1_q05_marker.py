"""D-QUIT-1 I1 (Q05): faulted/anchor-mismatched closes preserve the runtime
marker and normal open refuses a non-superseded prior runtime.

Fixtures follow test_q05_managed_wallet_session / test_q05_recovery_reference;
mocked Core here is never acceptance evidence.
"""
from contextlib import nullcontext
from types import SimpleNamespace
import os
import sys
import threading
import unittest
from unittest.mock import MagicMock, Mock, patch

import test_q05_core_supervisor as fixture
import test_q05_recovery_reference as references
from wam_regtest import managed_wallet_session as module
from wam_regtest import wallet_recovery as recovery
from wam_regtest.managed_wallet_checkpoint import (
    ManagedWalletError, _close_owned_runtime, _publish_reference,
    _remove_known_scanner_lock, _runtime,
)
from wam_regtest.supervisor_identity import directory_identity
from wam_regtest.wallet_session import WalletSession, WalletSessionError
from wam_regtest.wsp_live import REGTEST_GENESIS
from wam_sp.keystore import Keyring
from wam_sp.scanner import Scanner

PRIOR = 'MANAGED_WALLET_PRIOR_RUNTIME_PRESERVED'
PASSWORD = b'public-test-password'


class _GenesisRpc:
    """Genesis-only Core stub; real pinned Scanner still does the scanning."""

    def attest(self):
        return None

    def call(self, method, params=None):
        if method == 'getblockcount':
            return 0
        if method in ('getbestblockhash', 'getblockhash'):
            return REGTEST_GENESIS
        raise ValueError('TEST_GENESIS_RPC_DENIED')


def _close_quietly(obj):
    try:
        obj.close()
    except Exception:
        pass


def _anchor(value=None, error=None):
    anchor = Mock()
    if error is not None:
        anchor.read.side_effect = error
    else:
        anchor.read.return_value = value
    return anchor


class Q05MarkerCloseContracts(unittest.TestCase):
    setUp = fixture.SupervisorLifecycleUnit.setUp
    owner = fixture.SupervisorLifecycleUnit.owner

    def runtime(self):
        if sys.platform == 'linux':
            from wam_regtest import linux_private_storage
            self.stack.enter_context(patch.object(module.custody, 'storage', return_value=linux_private_storage))
        path = self.root / 'wallet-runtime.sqlite'
        if sys.platform == 'win32':
            from wam_regtest import windows_private_storage as native
            native.create_managed_runtime(path)
        path.write_bytes(b'owned-test-runtime')
        path.chmod(0o600)
        return path

    def session(self, guard, *, faulted=False, anchor_value=(1, 'a' * 64), expected=(1, 'a' * 64), anchor_error=None):
        vault = SimpleNamespace(anchor=_anchor(anchor_value, anchor_error), _expected=expected)
        return SimpleNamespace(
            _managed_thread=threading.get_ident(), locked=False,
            _managed_owner=Mock(), ring=Mock(), scanner=Mock(), vault=vault,
            faulted=faulted, _managed_checkpoint_uncertain=False,
            _managed_runtime_guard=guard, _managed_lease=MagicMock(),
            _disclosure_gate=None, _close_rpc=Mock(), _password=PASSWORD)

    def test_a_faulted_session_preserves_runtime_and_closes_keys(self):
        path = self.runtime()
        guard = module.RuntimeGuard(path)
        session = self.session(guard, faulted=True)
        ring, scanner, lease = session.ring, session.scanner, session._managed_lease
        with self.assertRaisesRegex(WalletSessionError, 'WALLET_MANAGED_RUNTIME_PRESERVED'):
            module.close_session(session)
        self.assertEqual(path.read_bytes(), b'owned-test-runtime')
        self.assertTrue(session.faulted)
        ring.close.assert_called_once()
        scanner.close.assert_called_once()
        lease.__exit__.assert_called_once()
        self.assertIsNone(session.ring)

    def test_b_anchor_mismatch_preserves_runtime(self):
        path = self.runtime()
        guard = module.RuntimeGuard(path)
        session = self.session(guard, faulted=False, anchor_value=(2, 'b' * 64), expected=(1, 'a' * 64))
        ring = session.ring
        with self.assertRaisesRegex(WalletSessionError, 'WALLET_MANAGED_RUNTIME_PRESERVED'):
            module.close_session(session)
        self.assertTrue(path.exists())
        self.assertTrue(session.faulted)
        ring.close.assert_called_once()

    def test_c_anchor_read_failure_preserves_runtime(self):
        path = self.runtime()
        guard = module.RuntimeGuard(path)
        session = self.session(guard, faulted=False, anchor_error=OSError('anchor-read-cut'))
        with self.assertRaisesRegex(WalletSessionError, 'WALLET_MANAGED_RUNTIME_PRESERVED'):
            module.close_session(session)
        self.assertTrue(path.exists())
        self.assertTrue(session.faulted)

    def test_d_clean_session_still_removes_runtime(self):
        path = self.runtime()
        guard = module.RuntimeGuard(path)
        session = self.session(guard, faulted=False)
        lease = session._managed_lease
        module.close_session(session)
        self.assertFalse(path.exists())
        self.assertFalse(session.faulted)
        self.assertIsNone(session.ring)
        lease.__exit__.assert_called_once()
        session._managed_owner.shutdown.assert_not_called()


class Q05MarkerOpenContracts(unittest.TestCase):
    setUp = fixture.SupervisorLifecycleUnit.setUp
    owner = fixture.SupervisorLifecycleUnit.owner
    target = references.RecoveryReferenceContracts.target
    begin = references.RecoveryReferenceContracts.begin
    commit = references.RecoveryReferenceContracts.commit

    def open_owned(self, owner):
        return WalletSession.open_owned(owner, self.core, PASSWORD, authorized=True)

    def assert_prior_blocked(self, owner):
        with self.assertRaises(ManagedWalletError) as direct:
            module._require_no_prior_runtime(owner, 'a' * 32)
        self.assertEqual(direct.exception.args, (PRIOR,))
        with patch.object(module, '_inputs'):
            with self.assertRaises(WalletSessionError) as caught:
                self.open_owned(owner)
        self.assertIsNotNone(caught.exception.__context__)
        self.assertEqual(caught.exception.__context__.args, (PRIOR,))

    def assert_reaches_runtime(self, owner):
        with patch.object(module, '_inputs'), \
                patch.object(module, '_runtime', side_effect=ManagedWalletError('TEST_REACHED_RUNTIME')):
            with self.assertRaises(WalletSessionError) as caught:
                self.open_owned(owner)
        self.assertEqual(caught.exception.__context__.args, ('TEST_REACHED_RUNTIME',))

    def test_e_leftover_runtime_scan_lock_and_wal_block_normal_open(self):
        owner = self.owner()
        _publish_reference(owner, 'a' * 32)
        for name in (
            'wallet-runtime.sqlite',
            'wallet-runtime.sqlite-journal',
            'wallet-runtime.sqlite-wal',
            'wallet-runtime.sqlite-shm',
        ):
            with self.subTest(artifact=name):
                leftover = owner.directory / name
                leftover.write_bytes(b'preserve-prior')
                self.assert_prior_blocked(owner)
                self.assertEqual(leftover.read_bytes(), b'preserve-prior')
                leftover.unlink()
        runtime = owner.directory / 'wallet-runtime.sqlite'
        lock = owner.directory / 'wallet-runtime.sqlite.scan.lock'
        runtime.write_bytes(b'preserve-prior')
        lock.write_bytes(b'preserve-lock')
        self.assert_prior_blocked(owner)
        self.assertEqual(runtime.read_bytes(), b'preserve-prior')
        self.assertEqual(lock.read_bytes(), b'preserve-lock')

    def test_f_completed_recovery_supersedes_old_runtime_and_preserves_it(self):
        owner = self.owner()
        _publish_reference(owner, 'a' * 32)
        # Uncommitted BEGIN / arbitrary active_name must not supersede base runtime.
        begin_action = '0011223344556677'
        begin_path = owner.directory / ('wallet-recovery-' + begin_action)
        self.create_private_directory(begin_path)
        recovery._append(owner, 'a' * 32, action=begin_action, state='BEGIN',
                         target_identity=directory_identity(begin_path), source_anchor=(1, 'a' * 64))
        leftover = owner.directory / 'wallet-runtime.sqlite'
        leftover.write_bytes(b'preserve-old-runtime')
        with self.assertRaisesRegex(ManagedWalletError, PRIOR):
            module._require_no_prior_runtime(
                owner, 'a' * 32, f'wallet-runtime-recovery-{begin_action}.sqlite')
        recovery._append(owner, 'a' * 32, action=begin_action, state='COMMIT',
                         target_identity=directory_identity(begin_path), source_anchor=(1, 'a' * 64),
                         target_anchor=(2, 'c' * 64))
        module._require_no_prior_runtime(owner, 'a' * 32)
        self.assert_reaches_runtime(owner)
        self.assertEqual(leftover.read_bytes(), b'preserve-old-runtime')
        # A second completed recovery supersedes the first recovery runtime too,
        # while the now-active recovery runtime still blocks normal open.
        action2 = 'fedcba0987654321'
        path2 = owner.directory / ('wallet-recovery-' + action2)
        self.create_private_directory(path2)
        identity2 = directory_identity(path2)
        recovery._append(owner, 'a' * 32, action=action2, state='BEGIN',
                         target_identity=identity2, source_anchor=(2, 'c' * 64))
        recovery._append(owner, 'a' * 32, action=action2, state='COMMIT',
                         target_identity=identity2, source_anchor=(2, 'c' * 64),
                         target_anchor=(3, 'e' * 64))
        old_recovery = owner.directory / ('wallet-runtime-recovery-' + begin_action + '.sqlite')
        old_recovery.write_bytes(b'preserve-older-recovery')
        module._require_no_prior_runtime(owner, 'a' * 32)
        self.assertEqual(old_recovery.read_bytes(), b'preserve-older-recovery')
        old_recovery.unlink()
        active = owner.directory / ('wallet-runtime-recovery-' + action2 + '.sqlite')
        active.write_bytes(b'preserve-active')
        with self.assertRaisesRegex(ManagedWalletError, PRIOR):
            module._require_no_prior_runtime(owner, 'a' * 32)
        self.assertEqual(active.read_bytes(), b'preserve-active')

    def test_g_explicit_recovery_path_still_succeeds_with_old_runtime(self):
        owner = self.owner()
        _publish_reference(owner, 'a' * 32)
        leftover = owner.directory / 'wallet-runtime.sqlite'
        leftover.write_bytes(b'preserve-old-runtime')
        # The fresh recovery runtime name is granted while the old one exists.
        fresh = _runtime(owner, 'wallet-runtime-recovery-0123456789abcdef.sqlite')
        self.assertEqual(fresh, owner.directory / 'wallet-runtime-recovery-0123456789abcdef.sqlite')
        self.assertFalse(fresh.exists())
        # Full explicit completion succeeds and never touches the old runtime.
        action, target_dir, _ = self.begin(owner)
        for generation in (1, 2):
            (target_dir / f'snapshot-{generation:09d}.enc').write_bytes(b'fixture-only')
        anchor = Mock()
        anchor.read.return_value = (2, 'c' * 64)
        anchor.lease.side_effect = lambda: nullcontext()
        vault = Mock()
        vault._expected = (2, 'c' * 64)

        def restore(runtime, password, **options):
            runtime.write_bytes(b'owned-fixture-runtime')
            return Mock(), Mock()
        vault.restore.side_effect = restore
        factory = Mock(return_value=vault)
        factory._filename.side_effect = lambda generation: f'snapshot-{generation:09d}.enc'
        with patch.object(recovery, '_owned'), \
                patch.object(recovery, 'require_recovery_source_equivalence'), \
                patch('wam_regtest.managed_wallet_checkpoint._owned'), \
                patch('wam_regtest.managed_wallet_checkpoint._pinned_source'), \
                patch.object(recovery.custody, 'anchor', return_value=anchor), \
                patch('wam_regtest.vault.CheckpointVault', factory), \
                patch('wam_regtest.wallet_session.WalletCoreCli'), \
                patch.object(recovery, '_snapshot', return_value={'reservation_sha256': 'd' * 64}):
            result = recovery.complete_recovery(owner, self.core, PASSWORD, authorized=True, action=action)
        self.assertTrue(result['explicit_recovery_completion'])
        self.assertEqual(leftover.read_bytes(), b'preserve-old-runtime')

    def _custody_for_unit(self):
        if sys.platform == 'linux':
            from wam_regtest import linux_private_storage
            self.stack.enter_context(patch.object(module.custody, 'storage', return_value=linux_private_storage))

    def _new_real_scanner_runtime(self, runtime):
        if sys.platform == 'win32':
            from wam_regtest import windows_private_storage as native
            native.create_managed_runtime(runtime)
        ring = Keyring()
        self.addCleanup(_close_quietly, ring)
        scanner = Scanner(runtime, ring.accounts())
        self.addCleanup(_close_quietly, scanner)
        scanner.sync(_GenesisRpc())
        return ring, scanner

    def _scanner_session(self, runtime, ring, scanner, *, faulted=False):
        guard = module.RuntimeGuard(runtime)
        self.addCleanup(guard.close)
        vault = SimpleNamespace(anchor=_anchor((1, 'a' * 64)), _expected=(1, 'a' * 64))
        return SimpleNamespace(
            _managed_thread=threading.get_ident(), locked=False,
            _managed_owner=Mock(), ring=ring, scanner=scanner, vault=vault,
            faulted=faulted, _managed_checkpoint_uncertain=False,
            _managed_runtime_guard=guard, _managed_lease=MagicMock(),
            _disclosure_gate=None, _close_rpc=Mock(), _password=PASSWORD)

    def test_h_real_scanner_clean_close_removes_runtime_and_scan_lock(self):
        self._custody_for_unit()
        owner = self.owner()
        _publish_reference(owner, 'a' * 32)
        runtime = _runtime(owner)
        ring, scanner = self._new_real_scanner_runtime(runtime)
        lock = runtime.with_name(runtime.name + '.scan.lock')
        self.assertTrue(runtime.exists())
        self.assertTrue(lock.exists())
        session = self._scanner_session(runtime, ring, scanner, faulted=False)
        module.close_session(session)
        self.assertFalse(session.faulted)
        self.assertFalse(runtime.exists())
        self.assertFalse(lock.exists())
        module._require_no_prior_runtime(owner, 'a' * 32)
        self.assert_reaches_runtime(owner)

    def test_i_legacy_scan_lock_without_sqlite_is_tolerated_and_kept(self):
        owner = self.owner()
        _publish_reference(owner, 'a' * 32)
        lock = owner.directory / 'wallet-runtime.sqlite.scan.lock'
        lock.write_bytes(b'legacy-scan-lock')
        lock.chmod(0o600)
        self.assertFalse((owner.directory / 'wallet-runtime.sqlite').exists())
        module._require_no_prior_runtime(owner, 'a' * 32)
        self.assert_reaches_runtime(owner)
        self.assertEqual(lock.read_bytes(), b'legacy-scan-lock')

    def test_j_real_scanner_post_recovery_close_allows_open_and_preserves_old(self):
        owner = self.owner()
        _publish_reference(owner, 'a' * 32)
        old_runtime = owner.directory / 'wallet-runtime.sqlite'
        old_lock = owner.directory / 'wallet-runtime.sqlite.scan.lock'
        old_runtime.write_bytes(b'preserve-old-runtime')
        old_lock.write_bytes(b'preserve-old-lock')
        action, target_dir, _ = self.begin(owner)
        rec_runtime = _runtime(owner, f'wallet-runtime-recovery-{action}.sqlite')
        ring, scanner = self._new_real_scanner_runtime(rec_runtime)
        rec_lock = rec_runtime.with_name(rec_runtime.name + '.scan.lock')
        self.assertTrue(rec_runtime.exists())
        self.assertTrue(rec_lock.exists())
        _close_owned_runtime(ring, scanner, rec_runtime)
        self.assertFalse(rec_runtime.exists())
        self.assertFalse(rec_lock.exists())
        recovery._append(owner, 'a' * 32, action=action, state='COMMIT',
                         target_identity=directory_identity(target_dir),
                         source_anchor=(1, 'b' * 64), target_anchor=(2, 'c' * 64))
        module._require_no_prior_runtime(owner, 'a' * 32)
        self.assert_reaches_runtime(owner)
        self.assertEqual(old_runtime.read_bytes(), b'preserve-old-runtime')
        self.assertEqual(old_lock.read_bytes(), b'preserve-old-lock')

    def test_k_faulted_real_scanner_close_preserves_runtime_and_scan_lock_and_blocks(self):
        self._custody_for_unit()
        owner = self.owner()
        _publish_reference(owner, 'a' * 32)
        runtime = _runtime(owner)
        ring, scanner = self._new_real_scanner_runtime(runtime)
        lock = runtime.with_name(runtime.name + '.scan.lock')
        runtime_bytes = runtime.read_bytes()
        lock_bytes = lock.read_bytes()
        session = self._scanner_session(runtime, ring, scanner, faulted=True)
        with self.assertRaisesRegex(WalletSessionError, 'WALLET_MANAGED_RUNTIME_PRESERVED'):
            module.close_session(session)
        self.assertTrue(session.faulted)
        self.assertEqual(runtime.read_bytes(), runtime_bytes)
        self.assertEqual(lock.read_bytes(), lock_bytes)
        self.assert_prior_blocked(owner)

    def test_l_remove_known_scanner_lock_refuses_symlink_and_foreign_mode(self):
        runtime = self.root / 'wallet-runtime.sqlite'
        lock = self.root / 'wallet-runtime.sqlite.scan.lock'
        target = self.root / 'keep-target'
        target.write_bytes(b'keep-target')
        lock.symlink_to(target)
        with self.assertRaisesRegex(ManagedWalletError, 'MANAGED_WALLET_SCAN_LOCK_UNCERTAIN'):
            _remove_known_scanner_lock(runtime)
        self.assertTrue(lock.is_symlink())
        self.assertEqual(target.read_bytes(), b'keep-target')
        lock.unlink()
        lock.symlink_to(self.root / 'missing-target')
        with self.assertRaisesRegex(ManagedWalletError, 'MANAGED_WALLET_SCAN_LOCK_UNCERTAIN'):
            _remove_known_scanner_lock(runtime)
        self.assertTrue(lock.is_symlink())
        lock.unlink()
        if sys.platform != 'win32':
            lock.write_bytes(b'keep-foreign-mode')
            lock.chmod(0o644)
            with self.assertRaisesRegex(ManagedWalletError, 'MANAGED_WALLET_SCAN_LOCK_UNCERTAIN'):
                _remove_known_scanner_lock(runtime)
            self.assertEqual(lock.read_bytes(), b'keep-foreign-mode')
            lock.unlink()
            lock.write_bytes(b'keep-hardlink')
            lock.chmod(0o600)
            other = self.root / 'other-link'
            os.link(lock, other)
            with self.assertRaisesRegex(ManagedWalletError, 'MANAGED_WALLET_SCAN_LOCK_UNCERTAIN'):
                _remove_known_scanner_lock(runtime)
            self.assertEqual(lock.read_bytes(), b'keep-hardlink')
            self.assertEqual(other.read_bytes(), b'keep-hardlink')


if __name__ == '__main__':
    unittest.main()
