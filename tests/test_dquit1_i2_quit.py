"""D-QUIT-1 I2: a faulted Quit makes one authenticated stop.

Stop delivery and exit observation are separated in the supervisor, and a
failed wallet lock leaves a sticky cleanup outcome that later Quits still
report. Mocked Core and owners here are never genuine-Core proof.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_q05_core_supervisor as fixture
from wam_regtest import core_supervisor as module
from wam_regtest import custody
from wam_regtest.core import CoreSmokeError
from wam_regtest.core_supervisor import ManagedCoreError, STOP_EXIT_BUDGET
from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend
from wam_regtest.supervisor_store import exclusive_lease
from wam_regtest.wallet_executor import (
    FrozenDict, ManagedWalletBackend, WalletExecutor,
)
from wam_regtest.wallet_session import WalletSessionError


def _live_owner(root=None):
    owner = Mock()
    owner.process = Mock()
    owner.process.poll.return_value = None
    owner._faulted = False
    owner.directory = Path.cwd()
    if root is not None:
        owner.root = root
        owner.profile = {'profile_id': 'a' * 32}
        owner.journal = SimpleNamespace(events=[])
    return owner


def _clears_process(owner):
    def stopped(*_args, **_kwargs):
        owner.process = None
    return stopped


class QuitRoutingContracts(unittest.TestCase):
    def setUp(self):
        if sys.platform == 'darwin':
            self._tmpdir = custody.private_temporary_directory('dquit1_i2_')
        else:
            self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.root = Path(self._tmpdir.name) / 'wam-fusion-core-0123456789abcdef'
        self.root.mkdir(mode=0o700)
        self._lease = exclusive_lease(self.root)
        self._lease.__enter__()
        self.addCleanup(self._lease.__exit__, None, None, None)

    def _executor(self, backend):
        executor = WalletExecutor(lambda: backend)
        executor._backend = backend
        backend.attach_executor(executor)
        self.addCleanup(self._close_executor, executor, backend)
        return executor

    def _close_executor(self, executor, backend):
        try:
            if not executor.closed:
                owner = getattr(backend, 'owner', None)
                if owner is not None:
                    owner.process = None
                try:
                    executor.request('quit', timeout=5)
                except Exception:
                    pass
        finally:
            executor.join(5)

    def _q05_backend(self, lock_error=None):
        backend = ManagedWalletBackend(self.root, None, None)
        session = Mock()
        session.locked = False
        session.faulted = lock_error is not None
        session._core_reauthentication_required = False
        if lock_error is not None:
            session.lock.side_effect = lock_error
        backend.session = session
        owner = _live_owner(self.root)
        owner.shutdown.side_effect = _clears_process(owner)
        owner.recover_stop.side_effect = _clears_process(owner)
        backend.owner = owner
        return backend, session, owner

    def _q06_backend(self, lock_error=None):
        backend = Bip39ReadOnlyBackend(
            self.root, self.root, self.root)
        backend._secret = bytearray(b'public-test-secret')
        spend = Mock()
        spend.locked = False
        spend.faulted = lock_error is not None
        spend._q06_uncertain = lock_error is not None
        spend._core_reauthentication_required = False
        if lock_error is not None:
            spend.lock.side_effect = lock_error
        backend._spend_session = spend
        backend._public = {
            'profile': 'q06', 'account_id': 'fixture',
            'receive_code': 'wamrtsp1fixture',
        }
        backend._seed_folder = self.root / ('bip39-12-' + 'a' * 32)
        owner = _live_owner(self.root)
        owner.shutdown.side_effect = _clears_process(owner)
        owner.recover_stop.side_effect = _clears_process(owner)
        backend.owner = owner
        return backend, spend, owner

    def test_faulted_q06_quit_uses_recover_stop_once_and_closes(self):
        # S-a: the spend lock always raises on a faulted session, yet Quit
        # must still make exactly one authenticated stop on the owner.
        backend, spend, owner = self._q06_backend(
            ValueError('Q06_SPEND_RUNTIME_PRESERVED'))
        executor = self._executor(backend)
        with patch('wam_regtest.rpc_scope.identity',
                   return_value=SimpleNamespace(faulted=False)):
            result = executor.request('quit', timeout=5)
        owner.recover_stop.assert_called_once_with()
        owner.shutdown.assert_not_called()
        self.assertTrue(executor.closed)
        self.assertTrue(executor.join(5))
        self.assertIsInstance(result, FrozenDict)
        self.assertIs(result['runtime_preserved'], True)
        self.assertEqual(result['codes'], ('Q06_SPEND_RUNTIME_PRESERVED',))
        self.assertTrue(backend._quit_cleanup_uncertain)
        with self.assertRaises(TypeError):
            result['runtime_preserved'] = False

    def test_faulted_q05_quit_uses_recover_stop_once_and_closes(self):
        # S-a-Q05: a Q05 close that preserves the runtime must not prevent
        # the authenticated stop, and the outcome is reported as preserved.
        backend, session, owner = self._q05_backend(
            WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED'))
        executor = self._executor(backend)
        with patch('wam_regtest.rpc_scope.identity',
                   return_value=SimpleNamespace(faulted=False)):
            result = executor.request('quit', timeout=5)
        owner.recover_stop.assert_called_once_with()
        owner.shutdown.assert_not_called()
        self.assertTrue(executor.closed)
        self.assertTrue(executor.join(5))
        self.assertIs(result['runtime_preserved'], True)
        self.assertEqual(
            result['codes'], ('WALLET_MANAGED_RUNTIME_PRESERVED',))
        self.assertTrue(backend._quit_cleanup_uncertain)

    def test_healthy_quit_uses_shutdown_and_reports_not_preserved(self):
        backend, session, owner = self._q05_backend()
        executor = self._executor(backend)
        with patch('wam_regtest.rpc_scope.identity',
                   return_value=SimpleNamespace(faulted=False)):
            result = executor.request('quit', timeout=5)
        owner.shutdown.assert_called_once_with()
        owner.recover_stop.assert_not_called()
        self.assertTrue(executor.closed)
        self.assertIs(result['runtime_preserved'], False)
        self.assertEqual(result['codes'], ())
        self.assertFalse(backend._quit_cleanup_uncertain)

    def test_sticky_first_failure_survives_a_later_clean_lock(self):
        # S-sticky (LIFE-01): the first lock fails and the stop fails, so a
        # second Quit whose lock now succeeds must still route to the
        # authenticated stop and still report the preserved runtime.
        backend, session, owner = self._q05_backend()
        session.lock.side_effect = [
            WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED'), None]
        owner.recover_stop.side_effect = [
            ValueError('MANAGED_SHUTDOWN_UNCERTAIN'), None]
        with patch('wam_regtest.rpc_scope.identity',
                   return_value=SimpleNamespace(faulted=False)):
            with self.assertRaisesRegex(
                    ValueError, 'MANAGED_SHUTDOWN_UNCERTAIN'):
                backend.execute('quit', (), {})
            self.assertTrue(backend._quit_cleanup_uncertain)
            owner.release.assert_not_called()
            owner.close.assert_not_called()
            result = backend.execute('quit', (), {})
        self.assertEqual(owner.recover_stop.call_count, 2)
        owner.shutdown.assert_not_called()
        self.assertIs(result['runtime_preserved'], True)
        self.assertEqual(
            result['codes'], ('WALLET_MANAGED_RUNTIME_PRESERVED',))
        owner.release.assert_called_once_with()
        owner.close.assert_called_once_with()

    def test_q06_control_non_status_survives_lock_failure(self):
        backend, spend, owner = self._q06_backend(
            ValueError('Q06_SPEND_RUNTIME_PRESERVED'))
        owner.control_operation.return_value = {'state': 'stopped'}
        result = backend.execute('control', ('shutdown',), {})
        self.assertEqual(result, {'state': 'stopped'})
        owner.control_operation.assert_called_once_with('shutdown')
        self.assertTrue(backend._quit_cleanup_uncertain)

    def test_q06_control_status_never_locks(self):
        backend, spend, owner = self._q06_backend(
            ValueError('Q06_SPEND_RUNTIME_PRESERVED'))
        owner.control_operation.return_value = {'state': 'stopped'}
        backend.execute('control', ('status',), {})
        spend.lock.assert_not_called()
        self.assertFalse(backend._quit_cleanup_uncertain)


class StopSeparationContracts(unittest.TestCase):
    setUp = fixture.SupervisorLifecycleUnit.setUp
    owner = fixture.SupervisorLifecycleUnit.owner
    runtime = fixture.SupervisorLifecycleUnit.runtime

    def test_stop_timeout_then_exit_records_clean_after_wait(self):
        # S-c1: the stop may have been delivered, so a timeout still waits
        # for the exit and only then records CLEAN.
        owner = self.owner()
        self.runtime(owner)
        process = owner.process
        read = owner.read
        process.wait.return_value = 0
        with patch.object(
                module, '_read_cli',
                side_effect=CoreSmokeError('CORE_RPC_TIMEOUT_UNCERTAIN')), \
                patch.object(module, 'unregister'):
            owner.shutdown()
        process.wait.assert_called_once_with(timeout=STOP_EXIT_BUDGET)
        self.assertEqual(owner.journal.state, 'CLEAN')
        self.assertIsNone(owner.process)
        self.assertEqual(owner.state, 'stopped')
        read.close.assert_called_once_with()

    def test_stop_timeout_without_exit_is_shutdown_uncertain(self):
        # S-c2: no exit within the budget keeps the original Popen and
        # never records CLEAN.
        owner = self.owner()
        self.runtime(owner)
        process = owner.process
        process.wait.side_effect = subprocess.TimeoutExpired('wam-cli', 20)
        with patch.object(
                module, '_read_cli',
                side_effect=CoreSmokeError('CORE_RPC_TIMEOUT_UNCERTAIN')), \
                patch.object(module, 'unregister'):
            with self.assertRaisesRegex(
                    ManagedCoreError, '^MANAGED_SHUTDOWN_UNCERTAIN$'):
                owner.shutdown()
        self.assertIs(owner.process, process)
        self.assertTrue(owner._faulted)
        self.assertEqual(owner.state, 'recovery-needed')
        self.assertEqual(owner.journal.state, 'STOPPING')
        owner.read.close.assert_not_called()
        process.kill.assert_not_called()
        process.terminate.assert_not_called()

    def test_stop_not_delivered_with_live_process_never_waits(self):
        # S-c3: a non-delivery error is not an uncertain delivery, so the
        # exit budget is never spent and the Popen is kept.
        owner = self.owner()
        self.runtime(owner)
        process = owner.process
        with patch.object(
                module, '_read_cli',
                side_effect=CoreSmokeError('CORE_RPC_UNAVAILABLE')), \
                patch.object(module, 'unregister'):
            with self.assertRaisesRegex(
                    ManagedCoreError, '^MANAGED_STOP_NOT_DELIVERED$'):
                owner.shutdown()
        process.wait.assert_not_called()
        self.assertIs(owner.process, process)
        self.assertTrue(owner._faulted)
        self.assertEqual(owner.journal.state, 'STOPPING')
        process.kill.assert_not_called()
        process.terminate.assert_not_called()

    def test_stop_not_delivered_after_exit_still_records_clean(self):
        # S-c4: the same non-delivery error with an already-exited child is
        # confirmed by the exit observation and records CLEAN.
        owner = self.owner()
        self.runtime(owner)
        process = owner.process
        process.poll.return_value = 0
        process.wait.return_value = 0
        with patch.object(
                module, '_read_cli',
                side_effect=OSError('fixture transport closed')), \
                patch.object(module, 'unregister'):
            owner.shutdown()
        process.wait.assert_called_once_with(timeout=STOP_EXIT_BUDGET)
        self.assertEqual(owner.journal.state, 'CLEAN')
        self.assertIsNone(owner.process)

    def _real_child(self, owner):
        child = subprocess.Popen(
            [sys.executable, '-c', 'import sys;sys.stdin.buffer.read()'],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)

        def cleanup():
            if child.poll() is None:
                if not child.stdin.closed:
                    child.stdin.close()
                child.wait(timeout=5)
        self.addCleanup(cleanup)
        owner.process = child
        owner._registered = True
        owner._faulted = True
        owner.journal.append('STARTING')
        owner.journal.append('FAULT', child.pid)
        return child

    def test_recover_stop_timeout_then_exit_records_clean(self):
        owner = self.owner()
        child = self._real_child(owner)
        owner.read = Mock()
        binding = Mock(spec=module.OwnedCoreBinding)

        def delivered_but_timed_out(*_args):
            child.stdin.close()
            raise CoreSmokeError('CORE_RPC_TIMEOUT_UNCERTAIN')
        with patch.object(module, 'OwnedCoreBinding', return_value=binding), \
                patch.object(module, 'reauthenticate_owned'), \
                patch.object(module, '_read_cli',
                             side_effect=delivered_but_timed_out), \
                patch.object(module, 'unregister'):
            owner.recover_stop()
        self.assertIsNotNone(child.poll())
        self.assertIsNone(owner.process)
        self.assertEqual(owner.journal.state, 'CLEAN')
        self.assertTrue(owner._faulted)


if __name__ == '__main__':
    unittest.main()
