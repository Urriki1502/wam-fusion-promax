"""D-QUIT-1 I3: durable quit-notice store, publish-before-release, and reader hooks.

Crash points (R-n1, R-n2) and write denials (N-d, double fault) are simulated
with monkeypatches between steps; mocked Core/owners here are never genuine-Core
proof.
"""
from contextlib import ExitStack, nullcontext
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from mnemonic import Mnemonic

import test_q05_core_supervisor as fixture
from wam_regtest import managed_wallet_session as q05_session
from wam_regtest import quit_notice as module
from wam_regtest.bip39_12 import Bip39Regtest12Keys
from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend, Q06ReadOnlyError
from wam_regtest.core_supervisor import CoreSupervisor, DIAGNOSTIC_CODES
from wam_regtest.quit_notice import (
    MAX_NOTICES,
    NOTICE_CODE_ALLOWLIST,
    NOTICE_SCHEMA,
    QuitNoticeError,
    acknowledge_unresolved,
    build_notice,
    parse_notice_bytes,
    publish_ack,
    publish_notice,
    read_store,
    unacknowledged,
    validate_notice_record,
)
from wam_regtest.supervisor_client import control
from wam_regtest.supervisor_store import create_once, exclusive_lease, read_exact
from wam_regtest.wallet_executor import (
    FrozenDict,
    ManagedWalletBackend,
    WalletExecutor,
    WalletExecutorError,
)
from wam_regtest.wallet_session import WalletSession, WalletSessionError

PASSWORD = b'public-test-password'
PHRASE = Mnemonic('english').to_mnemonic(bytes(16))
PROFILE_ID = 'a' * 32


def _private_core_root(parent):
    root = parent / 'wam-fusion-core-0123456789abcdef'
    root.mkdir(mode=0o700)
    return root


def _canonical_bytes(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True
    ).encode('ascii')


def _live_mock_owner(root, *, profile_id=PROFILE_ID):
    owner = Mock()
    owner.root = root
    owner.directory = root / 'chain'
    owner.directory.mkdir(mode=0o700, exist_ok=True)
    owner.profile = {'profile_id': profile_id}
    owner.journal = SimpleNamespace(events=[{'seq': 3, 'state': 'RUNNING'}])
    owner.process = Mock()
    owner.process.poll.return_value = None
    owner._faulted = False

    def stopped(*_a, **_kw):
        owner.process = None

    owner.shutdown.side_effect = stopped
    owner.recover_stop.side_effect = stopped
    return owner


class QuitNoticeStoreContracts(unittest.TestCase):
    def setUp(self):
        if sys.platform == 'darwin':
            from wam_regtest.custody import private_temporary_directory
            self.tmp = private_temporary_directory('wam-i3-notice-')
        else:
            self.tmp = tempfile.TemporaryDirectory(prefix='wam-i3-notice-')
        self.addCleanup(self.tmp.cleanup)
        self.root = _private_core_root(Path(self.tmp.name).resolve())

    def test_schema_and_privacy_validator_rejects_secrets_free_text_and_non_canonical(self):
        valid = build_notice(
            seq=1,
            profile_id=PROFILE_ID,
            session_kind='Q06',
            wallet_outcome='RUNTIME_PRESERVED',
            core_stop='CLEAN',
            codes=('Q06_SPEND_RUNTIME_PRESERVED', 'MANAGED_SHUTDOWN_UNCERTAIN'),
            journal_seq=4,
            created_utc='2026-11-15T08:00:00Z',
        )
        raw = _canonical_bytes(valid)
        self.assertLessEqual(len(raw), 4096)
        self.assertEqual(parse_notice_bytes(raw, expected_seq=1, expected_profile_id=PROFILE_ID), valid)

        # Allowlist is frozen and includes both Core and Q05/Q06 quit/lock codes.
        self.assertIsInstance(NOTICE_CODE_ALLOWLIST, frozenset)
        self.assertTrue(DIAGNOSTIC_CODES <= NOTICE_CODE_ALLOWLIST)
        self.assertIn('Q06_SPEND_RUNTIME_PRESERVED', NOTICE_CODE_ALLOWLIST)
        self.assertIn('WALLET_MANAGED_RUNTIME_PRESERVED', NOTICE_CODE_ALLOWLIST)

        # Reject non-canonical JSON formatting, duplicate keys, non-ASCII, constants.
        pretty = json.dumps(valid, sort_keys=True, indent=2).encode('ascii')
        with self.assertRaises(QuitNoticeError):
            parse_notice_bytes(pretty)
        unsorted = json.dumps(valid, sort_keys=False, separators=(',', ':')).encode('ascii')
        if unsorted != raw:
            with self.assertRaises(QuitNoticeError):
                parse_notice_bytes(unsorted)
        dup = raw[:-1] + b',"seq":1}'
        with self.assertRaises(QuitNoticeError):
            parse_notice_bytes(dup)
        with self.assertRaises(QuitNoticeError):
            parse_notice_bytes(raw + b'\n')
        with self.assertRaises(QuitNoticeError):
            parse_notice_bytes(b'{"schema":"\xc3\xa9"}')

        # Reject extra keys / txid / amount / address / secret / path / PID / free text.
        for bad_field in (
            {'txid': 'f' * 64},
            {'amount': 1000},
            {'address': 'wamrt1public'},
            {'secret': 'abandon ' * 11 + 'about'},
            {'path': '/Users/private/wallet'},
            {'pid': 12345},
            {'message': 'free text'},
        ):
            tampered = dict(valid, **bad_field)
            with self.subTest(bad_field=bad_field), self.assertRaises(QuitNoticeError):
                validate_notice_record(tampered)

        # Reject invalid values for valid keys (free text in codes, bool seq, >8 codes, bad date).
        nine_codes = sorted(NOTICE_CODE_ALLOWLIST)[:9]
        bad_cases = (
            {'schema': 'wam.fusion.quit-notice.v2'},
            {'seq': 0},
            {'seq': 65},
            {'seq': True},
            {'profile_id': 'not-a-profile-id'},
            {'session_kind': 'Q07'},
            {'created_utc': '2026-02-30T00:00:00Z'},
            {'created_utc': '2026-11-15T08:00:00.123456Z'},
            {'wallet_outcome': 'FREE_TEXT'},
            {'core_stop': 'KILLED'},
            {'codes': ['free text /Users/secret']},
            {'codes': nine_codes},
            {'codes': ['Q06_SPEND_RUNTIME_PRESERVED', 'Q06_SPEND_RUNTIME_PRESERVED']},
            {'journal_seq': True},
            {'journal_seq': -1},
            {'body_sha256': '0' * 64},
        )
        for patch_fields in bad_cases:
            candidate = dict(valid, **patch_fields)
            if 'body_sha256' not in patch_fields:
                body = {k: v for k, v in candidate.items() if k != 'body_sha256'}
                candidate['body_sha256'] = sha256(_canonical_bytes(body)).hexdigest()
            with self.subTest(patch_fields=patch_fields), self.assertRaises(QuitNoticeError):
                validate_notice_record(candidate)

    def test_canonical_round_trip_and_fullfsync(self):
        with exclusive_lease(self.root):
            with patch.object(module, '_fullfsync', wraps=module._fullfsync) as sync_spy:
                published = publish_notice(
                    self.root,
                    profile_id=PROFILE_ID,
                    session_kind='Q05',
                    wallet_outcome='RUNTIME_PRESERVED',
                    core_stop='CLEAN',
                    codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                    journal_seq=7,
                )
        # 1 file sync + 2 dir syncs (after link, after unlink).
        self.assertEqual(sync_spy.call_count, 3)
        path = self.root / 'supervisor.notice.000001'
        self.assertTrue(path.exists())
        st = path.lstat()
        self.assertEqual(st.st_mode & 0o777, 0o600)
        self.assertEqual(st.st_nlink, 1)
        self.assertEqual(
            parse_notice_bytes(path.read_bytes(), expected_seq=1, expected_profile_id=PROFILE_ID),
            published,
        )
        items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['kind'], 'notice')
        self.assertEqual(items[0]['seq'], 1)
        self.assertEqual(items[0]['notice'], published)
        # supervisor_store.read_exact also accepts the new name allowlist.
        self.assertEqual(read_exact(self.root, 'supervisor.notice.000001'), _canonical_bytes(published))

    def test_publish_without_lease_refused_and_does_not_create_lock(self):
        with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
            publish_notice(
                self.root,
                profile_id=PROFILE_ID,
                session_kind='Q06',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                journal_seq=1,
            )
        self.assertFalse((self.root / 'supervisor.lock').exists())
        self.assertEqual(list(self.root.iterdir()), [])

        # Even after supervisor.lock exists, an unheld lease still refuses.
        with exclusive_lease(self.root):
            pass
        with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
            publish_notice(
                self.root,
                profile_id=PROFILE_ID,
                session_kind='Q06',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                journal_seq=1,
            )
        with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
            publish_ack(self.root, {'kind': 'notice', 'seq': 1, 'body_sha256': '0' * 64})
        with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
            acknowledge_unresolved(self.root)

    def test_rn1_stage_without_link_is_unreadable_ackable_and_never_collides(self):
        real_link = os.link

        def crash_before_link(*args, **kwargs):
            raise RuntimeError('simulated-crash-before-link')

        with exclusive_lease(self.root):
            with patch.object(module.os, 'link', side_effect=crash_before_link):
                with self.assertRaises(QuitNoticeError):
                    publish_notice(
                        self.root,
                        profile_id=PROFILE_ID,
                        session_kind='Q06',
                        wallet_outcome='RUNTIME_PRESERVED',
                        core_stop='CLEAN',
                        codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                        journal_seq=2,
                    )
        stages = [p for p in self.root.iterdir() if p.name.startswith('supervisor.notice.stage-')]
        self.assertEqual(len(stages), 1)
        self.assertFalse((self.root / 'supervisor.notice.000001').exists())

        # Also add a 0-byte stage simulating an earlier crash right after O_CREAT.
        zero_stage = self.root / ('supervisor.notice.stage-' + '0' * 16)
        zero_stage.write_bytes(b'')
        zero_stage.chmod(0o600)

        unresolved = unacknowledged(self.root)
        self.assertEqual(len(unresolved), 2)
        self.assertTrue(all(item['kind'] == 'unreadable' for item in unresolved))
        self.assertEqual({item['name'] for item in unresolved}, {stages[0].name, zero_stage.name})
        self.assertIn(0, {item['size'] for item in unresolved})

        # Next publish uses a fresh random stage and seq 1 without colliding.
        with exclusive_lease(self.root):
            published = publish_notice(
                self.root,
                profile_id=PROFILE_ID,
                session_kind='Q06',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                journal_seq=3,
            )
            self.assertEqual(published['seq'], 1)
            self.assertTrue(stages[0].exists())
            self.assertTrue(zero_stage.exists())
            acknowledge_unresolved(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(unacknowledged(self.root, expected_profile_id=PROFILE_ID), ())
        # Neither the stage artifacts nor the final notice are ever deleted.
        self.assertTrue(stages[0].exists())
        self.assertTrue(zero_stage.exists())
        self.assertTrue((self.root / 'supervisor.notice.000001').exists())

    def test_rn2_link_done_stage_not_unlinked_accepted_and_completed_under_lease(self):
        with exclusive_lease(self.root):
            with patch.object(module.os, 'unlink', side_effect=RuntimeError('simulated-crash-after-link')):
                with self.assertRaises(QuitNoticeError):
                    publish_notice(
                        self.root,
                        profile_id=PROFILE_ID,
                        session_kind='Q05',
                        wallet_outcome='RUNTIME_PRESERVED',
                        core_stop='CLEAN',
                        codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                        journal_seq=5,
                    )
        final_path = self.root / 'supervisor.notice.000001'
        stages = [p for p in self.root.iterdir() if p.name.startswith('supervisor.notice.stage-')]
        self.assertTrue(final_path.exists())
        self.assertEqual(len(stages), 1)
        self.assertEqual(final_path.lstat().st_nlink, 2)
        self.assertEqual(
            (final_path.lstat().st_dev, final_path.lstat().st_ino),
            (stages[0].lstat().st_dev, stages[0].lstat().st_ino),
        )

        # Without lease (complete_staged=False), accepted without duplicate and stage untouched.
        ro_items = unacknowledged(self.root, expected_profile_id=PROFILE_ID, complete_staged=False)
        self.assertEqual(len(ro_items), 1)
        self.assertEqual(ro_items[0]['kind'], 'notice')
        self.assertTrue(stages[0].exists())

        # Explicitly requesting completion without lease refuses.
        with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
            read_store(self.root, expected_profile_id=PROFILE_ID, complete_staged=True)

        # Under lease, reader accepts AND completes publication (unlink stage + F_FULLFSYNC).
        with exclusive_lease(self.root):
            with patch.object(module, '_fullfsync', wraps=module._fullfsync) as sync_spy:
                items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['kind'], 'notice')
        self.assertEqual(items[0]['seq'], 1)
        self.assertFalse(stages[0].exists())
        self.assertEqual(final_path.lstat().st_nlink, 1)
        self.assertGreaterEqual(sync_spy.call_count, 1)

    def test_rn2_rejects_mismatched_hardlink_count_or_duplicate_stage_to_unreadable(self):
        with exclusive_lease(self.root):
            publish_notice(
                self.root,
                profile_id=PROFILE_ID,
                session_kind='Q05',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                journal_seq=1,
            )
        final_path = self.root / 'supervisor.notice.000001'
        extra_link = self.root / 'supervisor.notice.unexpected'
        os.link(final_path, extra_link)
        self.assertEqual(final_path.lstat().st_nlink, 2)
        with exclusive_lease(self.root):
            items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        # st_nlink==2 without a matching supervisor.notice.stage-* is unreadable!
        self.assertEqual({item['kind'] for item in items}, {'unreadable'})
        self.assertTrue(final_path.exists())
        self.assertTrue(extra_link.exists())

    def test_corrupt_and_unknown_schema_notices_are_unreadable_and_preserved(self):
        corrupt = self.root / 'supervisor.notice.000001'
        corrupt.write_bytes(b'{not-valid-json')
        corrupt.chmod(0o600)

        bad_schema = self.root / 'supervisor.notice.000002'
        payload = build_notice(
            seq=2,
            profile_id=PROFILE_ID,
            session_kind='Q06',
            wallet_outcome='RUNTIME_PRESERVED',
            core_stop='CLEAN',
            codes=('Q06_SPEND_RUNTIME_PRESERVED',),
            journal_seq=1,
        )
        payload['schema'] = 'wam.fusion.quit-notice.v99'
        bad_schema.write_bytes(_canonical_bytes(payload))
        bad_schema.chmod(0o600)

        items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items), 2)
        self.assertTrue(all(i['kind'] == 'unreadable' for i in items))
        self.assertEqual({i['name'] for i in items}, {corrupt.name, bad_schema.name})

        # Acking unreadable artifacts unblocks without deleting them.
        with exclusive_lease(self.root):
            acks = acknowledge_unresolved(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(acks), 2)
        self.assertEqual(unacknowledged(self.root, expected_profile_id=PROFILE_ID), ())
        self.assertTrue(corrupt.exists())
        self.assertTrue(bad_schema.exists())
        self.assertTrue((self.root / 'supervisor.notice-ack.000001').exists())
        self.assertTrue((self.root / 'supervisor.notice-ack.000002').exists())

    def test_capacity_64_fails_closed_and_ack_cap_exceeds_64(self):
        with exclusive_lease(self.root):
            for seq in range(1, MAX_NOTICES + 1):
                published = publish_notice(
                    self.root,
                    profile_id=PROFILE_ID,
                    session_kind='Q06',
                    wallet_outcome='RUNTIME_PRESERVED',
                    core_stop='CLEAN',
                    codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                    journal_seq=seq,
                )
                self.assertEqual(published['seq'], seq)
            with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_CAPACITY_REACHED'):
                publish_notice(
                    self.root,
                    profile_id=PROFILE_ID,
                    session_kind='Q06',
                    wallet_outcome='RUNTIME_PRESERVED',
                    core_stop='CLEAN',
                    codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                    journal_seq=65,
                )
            # Also add an R-n1 orphan stage so ack count > 64.
            orphan = self.root / ('supervisor.notice.stage-' + 'f' * 16)
            orphan.write_bytes(b'partial')
            orphan.chmod(0o600)
            acks = acknowledge_unresolved(self.root, expected_profile_id=PROFILE_ID)
            self.assertEqual(len(acks), 65)
            self.assertTrue((self.root / 'supervisor.notice-ack.000065').exists())
            self.assertEqual(unacknowledged(self.root, expected_profile_id=PROFILE_ID), ())


class QuitNoticeExecutorAndHooksContracts(unittest.TestCase):
    setUp = fixture.SupervisorLifecycleUnit.setUp
    owner = fixture.SupervisorLifecycleUnit.owner

    def _executor(self, backend):
        executor = WalletExecutor(lambda: backend)
        executor._backend = backend
        backend.attach_executor(executor)
        self.addCleanup(self._close_executor, executor, backend)
        return executor

    def _close_executor(self, executor, backend):
        try:
            if not executor.closed:
                backend._notice_persist_failed = False
                owner = getattr(backend, 'owner', None)
                if owner is not None:
                    owner.process = None
                try:
                    executor.request('quit', timeout=5)
                except Exception:
                    pass
        finally:
            executor.join(5)

    def test_nd_publish_denied_refuses_release_and_blocks_later_quit_and_control_release(self):
        for kind, cls, err in (
            ('Q05', ManagedWalletBackend, WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')),
            ('Q06', Bip39ReadOnlyBackend, ValueError('Q06_SPEND_RUNTIME_PRESERVED')),
        ):
            with self.subTest(kind=kind):
                sub_root = self.root if kind == 'Q05' else _private_core_root(self.root.parent / 'q06')
                if not sub_root.parent.exists():
                    sub_root.parent.mkdir(mode=0o700)
                    sub_root.mkdir(mode=0o700)
                backend = cls(sub_root, self.core, self.core)
                owner = _live_mock_owner(sub_root)
                backend.owner = owner
                if kind == 'Q05':
                    session = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
                    session.lock.side_effect = err
                    backend.session = session
                else:
                    spend = Mock(locked=False, faulted=True, _q06_uncertain=True, _core_reauthentication_required=False)
                    spend.lock.side_effect = err
                    backend._spend_session = spend
                    backend._secret = bytearray(PASSWORD)
                executor = self._executor(backend)
                with exclusive_lease(sub_root), \
                        patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                        patch('wam_regtest.quit_notice.publish_notice', side_effect=OSError('ENOSPC')):
                    with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                        executor.request('quit', timeout=5)
                    self.assertTrue(backend._notice_persist_failed)
                    self.assertFalse(executor.closed)
                    owner.release.assert_not_called()
                    owner.close.assert_not_called()

                    # Subsequent quit refuses even if publish_notice would now work.
                with exclusive_lease(sub_root), \
                        patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)):
                    with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                        executor.request('quit', timeout=5)
                    owner.release.assert_not_called()
                    owner.close.assert_not_called()
                    self.assertFalse(executor.closed)

                    # Subsequent control('release') also refuses with NOTICE_PERSIST_FAILED.
                    with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                        executor.request('control', 'release', timeout=5)
                    owner.control_operation.assert_not_called()
                    self.assertFalse(executor.closed)

    def test_nd_ipc_serve_control_release_refused_while_notice_persist_failed(self):
        # Exercise the real CoreSupervisor socket + _serve_control bridge.
        with patch.object(CoreSupervisor, 'start'), \
                patch.object(CoreSupervisor, 'recover_stop') as rec_stop:
            executor = WalletExecutor(lambda: ManagedWalletBackend(self.root, self.core, self.core))
            self.addCleanup(self._close_executor_real, executor)
            executor.request('core_start', timeout=5)
            backend = executor._backend
            owner = backend.owner
            owner.process = Mock()
            owner.process.poll.return_value = None

            def stop_clears():
                owner.process = None

            rec_stop.side_effect = stop_clears
            session = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
            session.lock.side_effect = WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')
            backend.session = session

            with patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                    patch('wam_regtest.quit_notice.publish_notice', side_effect=OSError('ENOSPC')):
                with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                    executor.request('quit', timeout=5)
            self.assertTrue(backend._notice_persist_failed)
            self.assertFalse(executor.closed)
            self.assertFalse(owner._release_requested)

            # IPC control('release') hits _control_bridge -> execute('control', ('release',)) and fails.
            with self.assertRaises(Exception):
                control(self.root, 'release', authorized=True)
            time.sleep(0.05)
            self.assertFalse(owner._release_requested)
            self.assertFalse(executor.closed)

    def _close_executor_real(self, executor):
        try:
            if not executor.closed and executor._backend is not None:
                executor._backend._notice_persist_failed = False
                if executor._backend.owner is not None:
                    executor._backend.owner.process = None
                try:
                    executor.request('quit', timeout=5)
                except Exception:
                    pass
        finally:
            executor.join(5)

    def test_stop_failure_publishes_notice_and_double_fault_refuses_blocked(self):
        # Single stop failure (Core alive) publishes notice with UNCERTAIN/BLOCKED, keeps owner.
        backend = ManagedWalletBackend(self.root, self.core, self.core)
        owner = _live_mock_owner(self.root)
        owner.recover_stop.side_effect = ValueError('MANAGED_SHUTDOWN_UNCERTAIN')
        backend.owner = owner
        backend._faulted_test = True
        owner._faulted = True
        executor = self._executor(backend)
        with exclusive_lease(self.root), \
                patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)):
            with self.assertRaisesRegex(WalletExecutorError, '^MANAGED_SHUTDOWN_UNCERTAIN$'):
                executor.request('quit', timeout=5)
        self.assertFalse(executor.closed)
        self.assertTrue(executor.state.core_alive)
        owner.release.assert_not_called()
        owner.close.assert_not_called()
        items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['notice']['wallet_outcome'], 'NONE')
        self.assertEqual(items[0]['notice']['core_stop'], 'UNCERTAIN')
        self.assertEqual(items[0]['notice']['codes'], ['MANAGED_SHUTDOWN_UNCERTAIN'])

        # Double fault: Core alive + notice publish failure -> refused, BLOCKED, owner kept.
        backend2 = ManagedWalletBackend(self.root, self.core, self.core)
        owner2 = _live_mock_owner(self.root)
        owner2._faulted = True
        owner2.recover_stop.side_effect = ValueError('CORE_RPC_PROCESS_IDENTITY_DENIED')
        backend2.owner = owner2
        executor2 = self._executor(backend2)
        with exclusive_lease(self.root), \
                patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                patch('wam_regtest.quit_notice.publish_notice', side_effect=OSError('EIO')):
            with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                executor2.request('quit', timeout=5)
        self.assertFalse(executor2.closed)
        self.assertTrue(executor2.state.core_alive)
        owner2.release.assert_not_called()
        owner2.close.assert_not_called()

    def test_q05_open_refused_with_unresolved_notice_and_allowed_after_ack(self):
        owner = self.owner()
        profile_id = owner.profile['profile_id']
        publish_notice(
            self.root,
            profile_id=profile_id,
            session_kind='Q05',
            wallet_outcome='RUNTIME_PRESERVED',
            core_stop='CLEAN',
            codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
            journal_seq=2,
        )
        with patch.object(q05_session, '_inputs'):
            with self.assertRaisesRegex(WalletSessionError, '^QUIT_NOTICE_REVIEW_REQUIRED$'):
                WalletSession.open_owned(owner, self.core, PASSWORD, authorized=True)

        # Acknowledge via backend method under owner's held lease.
        backend = ManagedWalletBackend(self.root, self.core, self.core)
        backend.owner = owner
        ack_result = backend.acknowledge_quit_notices()
        self.assertEqual(ack_result['count'], 1)
        self.assertTrue((self.root / 'supervisor.notice.000001').exists())
        self.assertTrue((self.root / 'supervisor.notice-ack.000001').exists())

        # Now open_owned proceeds past the notice gate.
        with patch.object(q05_session, '_inputs'), \
                patch.object(q05_session, '_read_reference', side_effect=ValueError('TEST_REACHED_AFTER_NOTICE')):
            with self.assertRaises(WalletSessionError) as caught:
                WalletSession.open_owned(owner, self.core, PASSWORD, authorized=True)
        self.assertEqual(caught.exception.args, ('WALLET_MANAGED_OPEN_DENIED',))

    def test_q06_reopen_exposes_notices_and_activate_refused_until_ack(self):
        owner = self.owner()
        profile_id = owner.profile['profile_id']
        seed_folder = owner.directory / ('bip39-12-' + 'a' * 32)
        seed_folder.mkdir()
        published = publish_notice(
            self.root,
            profile_id=profile_id,
            session_kind='Q06',
            wallet_outcome='RUNTIME_PRESERVED',
            core_stop='CLEAN',
            codes=('Q06_SPEND_RUNTIME_PRESERVED',),
            journal_seq=4,
        )
        backend = Bip39ReadOnlyBackend(self.root, self.core, self.core)
        backend.owner = owner
        backend._core = lambda: owner

        keys = Bip39Regtest12Keys(PHRASE, source=self.core, authorized_disposable=True)
        keys._q06_generation = 1
        with patch('wam_regtest.bip39_seed_vault.open_owned_seed_container') as opened:
            opened.return_value.__enter__ = lambda *a, **kw: keys
            opened.return_value.__exit__ = lambda *a, **kw: None
            reopened = backend.execute('open', (PASSWORD, 'reopen', ''), {})

        self.assertEqual(reopened['status'], 'Q06_REGTEST_READ_ONLY_OWNER_OPENED')
        self.assertEqual(len(reopened['unresolved_notices']), 1)
        self.assertEqual(reopened['unresolved_notices'][0]['notice'], published)

        # Spend activation is refused until acknowledged.
        with patch('wam_regtest.bip39_spend_session.open_owned_spend_session') as spend_open:
            with self.assertRaisesRegex(Q06ReadOnlyError, '^QUIT_NOTICE_REVIEW_REQUIRED$'):
                backend.execute('activate', (), {})
            spend_open.assert_not_called()

        # Acknowledge through backend method under lease.
        ack_result = backend.acknowledge_quit_notices()
        self.assertEqual(ack_result['count'], 1)
        self.assertTrue((self.root / 'supervisor.notice.000001').exists())
        self.assertTrue((self.root / 'supervisor.notice-ack.000001').exists())

        # Reopen now has no unresolved notices and spend activation proceeds past the gate.
        backend.execute('lock', (), {})
        with patch('wam_regtest.bip39_seed_vault.open_owned_seed_container') as opened:
            opened.return_value.__enter__ = lambda *a, **kw: keys
            opened.return_value.__exit__ = lambda *a, **kw: None
            reopened2 = backend.execute('open', (PASSWORD, 'reopen', ''), {})
        self.assertEqual(reopened2['unresolved_notices'], ())
        with patch('wam_regtest.bip39_spend_session.open_owned_spend_session',
                   side_effect=ValueError('TEST_REACHED_SPEND_OPEN')) as spend_open:
            with self.assertRaisesRegex(ValueError, '^TEST_REACHED_SPEND_OPEN$'):
                backend.execute('activate', (), {})
            spend_open.assert_called_once()

    def test_supervisor_failure_only_is_unresolved_and_ack_preserves_failure_file(self):
        owner = self.owner()
        from wam_regtest.core_supervisor import ManagedCoreError
        owner._record_failure('start', ManagedCoreError('MANAGED_START_TIMEOUT'))
        failure_path = self.root / 'supervisor.failure'
        self.assertTrue(failure_path.exists())
        before_bytes = failure_path.read_bytes()

        unresolved = unacknowledged(self.root, expected_profile_id=owner.profile['profile_id'])
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0]['kind'], 'failure')
        self.assertEqual(unresolved[0]['code'], 'MANAGED_START_TIMEOUT')
        self.assertEqual(unresolved[0]['stage'], 'start')

        # Q05 refuses normal open.
        with patch.object(q05_session, '_inputs'):
            with self.assertRaisesRegex(WalletSessionError, '^QUIT_NOTICE_REVIEW_REQUIRED$'):
                WalletSession.open_owned(owner, self.core, PASSWORD, authorized=True)

        # Q06 read-only reopen exposes it and spend activation refuses.
        seed_folder = owner.directory / ('bip39-12-' + 'b' * 32)
        seed_folder.mkdir()
        q06_backend = Bip39ReadOnlyBackend(self.root, self.core, self.core)
        q06_backend.owner = owner
        q06_backend._core = lambda: owner
        keys = Bip39Regtest12Keys(PHRASE, source=self.core, authorized_disposable=True)
        keys._q06_generation = 1
        with patch('wam_regtest.bip39_seed_vault.open_owned_seed_container') as opened:
            opened.return_value.__enter__ = lambda *a, **kw: keys
            opened.return_value.__exit__ = lambda *a, **kw: None
            reopened = q06_backend.execute('open', (PASSWORD, 'reopen', ''), {})
        self.assertEqual(len(reopened['unresolved_notices']), 1)
        self.assertEqual(reopened['unresolved_notices'][0]['name'], 'supervisor.failure')
        with self.assertRaisesRegex(Q06ReadOnlyError, '^QUIT_NOTICE_REVIEW_REQUIRED$'):
            q06_backend.execute('activate', (), {})

        # Ack unblocks without deleting supervisor.failure.
        ack_result = q06_backend.acknowledge_quit_notices()
        self.assertEqual(ack_result['count'], 1)
        self.assertEqual(failure_path.read_bytes(), before_bytes)
        self.assertEqual(unacknowledged(self.root, expected_profile_id=owner.profile['profile_id']), ())

        with patch('wam_regtest.bip39_spend_session.open_owned_spend_session',
                   side_effect=ValueError('TEST_REACHED_SPEND_OPEN')):
            with self.assertRaisesRegex(ValueError, '^TEST_REACHED_SPEND_OPEN$'):
                q06_backend.execute('activate', (), {})
        with patch.object(q05_session, '_inputs'), \
                patch.object(q05_session, '_read_reference', side_effect=ValueError('TEST_REACHED_Q05')):
            with self.assertRaises(WalletSessionError) as caught:
                WalletSession.open_owned(owner, self.core, PASSWORD, authorized=True)
        self.assertEqual(caught.exception.args, ('WALLET_MANAGED_OPEN_DENIED',))


if __name__ == '__main__':
    unittest.main()
