"""D-QUIT-1 I4: executor runtime_preserved, quit_ack_unrecorded, GUI acknowledgement, closeEvent guard, dead-owner action, and test-only N03 SIGSTOP hang.

Simulated owners/backends and disposable test subprocesses here are never
genuine-Core proof. No kill/SIGTERM/PID adoption in product code.
"""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from mnemonic import Mnemonic

HAVE_QT = importlib.util.find_spec('PySide6') is not None
if HAVE_QT:
    from PySide6.QtCore import QEvent
    from PySide6.QtGui import QCloseEvent
    from PySide6.QtWidgets import QDialog, QWidget
    from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
    from wam_regtest.bip39_owner_gui import Bip39TrialWindow
    from wam_regtest.desktop import qt_application
    from wam_regtest.managed_gui import ManagedWalletWindow

import test_q05_core_supervisor as sup_fixture
from wam_regtest import bip39_locale, core_supervisor as sup_mod
from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend
from wam_regtest.core_supervisor import CoreSupervisor, ManagedCoreError
from wam_regtest.presentation.strings import CATALOG, SUPPORTED_LANGUAGES, text
from wam_regtest.quit_notice import publish_notice, unacknowledged
from wam_regtest.supervisor_client import control
from wam_regtest.supervisor_store import exclusive_lease
from wam_regtest.wallet_executor import (
    COMMANDS,
    ExecutorState,
    ManagedWalletBackend,
    ManagedWalletProxy,
    WalletExecutor,
    WalletExecutorError,
)
from wam_regtest.wallet_session import WalletSessionError

PASSWORD = b'public-test-password'
PHRASE = Mnemonic('english').to_mnemonic(bytes(16))
PROFILE_ID = 'a' * 32
SOURCE = Path(importlib.util.find_spec('wam_sp').origin).resolve().parents[2]


def _private_dir(prefix):
    if sys.platform == 'darwin':
        from wam_regtest.custody import private_temporary_directory
        return private_temporary_directory(prefix)
    return tempfile.TemporaryDirectory(prefix=prefix)


def _private_core_root(parent):
    root = parent / 'wam-fusion-core-0123456789abcdef'
    root.mkdir(mode=0o700)
    return root


def _live_mock_owner(root, *, profile_id=PROFILE_ID):
    owner = Mock()
    owner.root = root
    owner.directory = root / 'chain'
    owner.directory.mkdir(mode=0o700, exist_ok=True)
    owner.profile = {'profile_id': profile_id}
    owner.status.return_value = {'state': 'running'}
    owner.journal = SimpleNamespace(events=[{'seq': 3, 'state': 'RUNNING'}])
    owner.process = Mock()
    owner.process.poll.return_value = None
    owner._faulted = False

    def stopped(*_a, **_kw):
        owner.process = None

    owner.shutdown.side_effect = stopped
    owner.recover_stop.side_effect = stopped
    return owner


class ExecutorI4Contracts(unittest.TestCase):
    setUp = sup_fixture.SupervisorLifecycleUnit.setUp

    def _executor(self, backend):
        executor = WalletExecutor(lambda: backend)
        executor._backend = backend
        backend.attach_executor(executor)

        def cleanup():
            if not executor.closed and executor._backend is not None:
                executor._backend._notice_persist_failed = False
                executor._backend._quit_cleanup_uncertain = False
                executor._backend.session = None
                if hasattr(executor._backend, '_spend_session'):
                    executor._backend._spend_session = None
                if executor._backend.owner is not None:
                    executor._backend.owner.process = None
                try:
                    executor.request('quit', timeout=5)
                except Exception:
                    pass
            executor.join(5)

        self.addCleanup(cleanup)
        return executor

    def test_executor_state_surfaces_runtime_preserved_for_q05_and_q06(self):
        self.assertFalse(ExecutorState().runtime_preserved)
        self.assertTrue(
            {'acknowledge_quit_notices', 'quit_ack_unrecorded', 'retry_quit_notice', 'quit_notices'}
            <= COMMANDS
        )

        for idx, (kind, cls, err) in enumerate((
            ('Q05', ManagedWalletBackend, WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')),
            ('Q06', Bip39ReadOnlyBackend, ValueError('Q06_SPEND_RUNTIME_PRESERVED')),
        )):
            with self.subTest(kind=kind):
                parent = self.root.parent / f'state_{idx}'
                parent.mkdir(mode=0o700)
                sub_root = _private_core_root(parent)
                backend = cls(sub_root, self.core, SOURCE)
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
                        patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)):
                    res = executor.request('quit', timeout=5)
                self.assertTrue(res['runtime_preserved'])
                self.assertTrue(executor.closed)
                self.assertIs(executor.state.runtime_preserved, True)
                self.assertIs(executor.state.core_alive, False)

    def test_quit_ack_unrecorded_requires_pending_state_never_constructs_backend_and_checks_live_core(self):
        # Fresh executor with _backend is None: never constructs backend and refuses.
        constructed = []

        def factory():
            constructed.append(1)
            return ManagedWalletBackend(self.root, self.core, SOURCE)

        fresh = WalletExecutor(factory)
        self.addCleanup(lambda: (fresh.request('quit') if not fresh.closed else None, fresh.join(5)))
        with self.assertRaisesRegex(WalletExecutorError, '^QUIT_ACK_UNRECORDED_NOT_PENDING$'):
            fresh.request('quit_ack_unrecorded', timeout=5)
        self.assertEqual(constructed, [])
        self.assertFalse(fresh.closed)
        fresh.request('quit', timeout=5)
        self.assertEqual(constructed, [])

        # Constructed backend without _notice_persist_failed refuses without releasing.
        backend = ManagedWalletBackend(self.root, self.core, SOURCE)
        owner = _live_mock_owner(self.root)
        backend.owner = owner
        executor = self._executor(backend)
        executor.request('core_status', timeout=5)
        with self.assertRaisesRegex(WalletExecutorError, '^QUIT_ACK_UNRECORDED_NOT_PENDING$'):
            executor.request('quit_ack_unrecorded', timeout=5)
        self.assertFalse(executor.closed)
        owner.release.assert_not_called()
        owner.close.assert_not_called()

        # Double fault: _notice_persist_failed=True AND core_alive=True refuses exit.
        owner.recover_stop.side_effect = ValueError('CORE_RPC_PROCESS_IDENTITY_DENIED')
        owner._faulted = True
        with exclusive_lease(self.root), \
                patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                patch('wam_regtest.quit_notice.publish_notice', side_effect=OSError('ENOSPC')):
            with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                executor.request('quit', timeout=5)
        self.assertTrue(backend._notice_persist_failed)
        self.assertTrue(executor.state.core_alive)
        with self.assertRaisesRegex(WalletExecutorError, '^MANAGED_LIVE_OWNER_CLOSE_DENIED$'):
            executor.request('quit_ack_unrecorded', timeout=5)
        self.assertFalse(executor.closed)
        owner.release.assert_not_called()
        owner.close.assert_not_called()

        # Once Core is stopped (core_alive=False), bad args are refused, valid ack closes.
        owner.process = None
        with self.assertRaisesRegex(WalletExecutorError, '^QUIT_ACK_UNRECORDED_ARGUMENTS_DENIED$'):
            executor.request('quit_ack_unrecorded', acknowledged=False, timeout=5)
        self.assertFalse(executor.closed)
        res = executor.request('quit_ack_unrecorded', timeout=5)
        self.assertIs(res['unrecorded_acknowledged'], True)
        self.assertTrue(executor.closed)
        owner.release.assert_called_once_with()
        owner.close.assert_called_once_with()

    def test_retry_quit_notice_recovers_and_avoids_duplicate_on_quit_for_q05_and_q06(self):
        for idx, (kind, cls, err) in enumerate((
            ('Q05', ManagedWalletBackend, WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')),
            ('Q06', Bip39ReadOnlyBackend, ValueError('Q06_SPEND_RUNTIME_PRESERVED')),
        )):
            with self.subTest(kind=kind):
                parent = self.root.parent / f'retry_{idx}'
                parent.mkdir(mode=0o700)
                sub_root = _private_core_root(parent)
                backend = cls(sub_root, self.core, SOURCE)
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
                        patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)):
                    with patch('wam_regtest.quit_notice.publish_notice', side_effect=OSError('ENOSPC')):
                        with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                            executor.request('quit', timeout=5)
                    self.assertTrue(backend._notice_persist_failed)
                    self.assertFalse(executor.closed)
                    # Both quit and control('release') refuse until retried or unrecorded-acked.
                    with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                        executor.request('quit', timeout=5)
                    with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                        executor.request('control', 'release', timeout=5)

                    # Retry succeeds, clears _notice_persist_failed, then quit closes without duplicate notice.
                    retried = executor.request('retry_quit_notice', timeout=5)
                    self.assertIs(retried['recorded'], True)
                    self.assertIs(retried['core_alive'], False)
                    self.assertFalse(backend._notice_persist_failed)
                    quit_res = executor.request('quit', timeout=5)
                self.assertTrue(quit_res['runtime_preserved'])
                self.assertTrue(executor.closed)
                items = unacknowledged(sub_root, expected_profile_id=PROFILE_ID)
                self.assertEqual(len(items), 1)
                self.assertEqual(items[0]['notice']['core_stop'], 'CLEAN')

    def test_acknowledge_quit_notices_dispatch_on_q05_and_q06_executors(self):
        for idx, cls in enumerate((ManagedWalletBackend, Bip39ReadOnlyBackend)):
            with self.subTest(backend=cls.__name__):
                parent = self.root.parent / f'ack_cmd_{idx}'
                parent.mkdir(mode=0o700)
                sub_root = _private_core_root(parent)
                backend = cls(sub_root, self.core, SOURCE)
                owner = _live_mock_owner(sub_root)
                owner.process = None
                backend.owner = owner
                executor = self._executor(backend)
                with exclusive_lease(sub_root):
                    publish_notice(
                        sub_root,
                        profile_id=PROFILE_ID,
                        session_kind=backend._session_kind,
                        wallet_outcome='RUNTIME_PRESERVED',
                        core_stop='CLEAN',
                        codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                        journal_seq=2,
                    )
                    listed = executor.request('quit_notices', timeout=5)
                    self.assertEqual(listed['count'], 1)
                    acked = executor.request('acknowledge_quit_notices', timeout=5)
                    self.assertEqual(acked['count'], 1)
                    self.assertEqual(executor.request('quit_notices', timeout=5)['count'], 0)

    def test_q06_core_restart_dispatches_recover_dead_when_child_exited(self):
        backend = Bip39ReadOnlyBackend(self.root, self.core, SOURCE)
        owner = _live_mock_owner(self.root)
        owner.process.poll.return_value = 9
        backend.owner = owner
        executor = self._executor(backend)
        with self.assertRaisesRegex(WalletExecutorError, '^MANAGED_DEAD_OWNER_RECOVERY_REQUIRED$'):
            executor.request('quit', timeout=5)
        executor.request('core_restart', timeout=5)
        owner.recover_dead.assert_called_once_with(authorized=True)
        owner.process = None


@unittest.skipUnless(HAVE_QT, 'Requires PySide6 for GUI lifecycle contracts')
class GuiLifecycleI4Contracts(unittest.TestCase):
    setUp = sup_fixture.SupervisorLifecycleUnit.setUp

    @classmethod
    def setUpClass(cls):
        cls.app = qt_application()
        cls.app.setQuitOnLastWindowClosed(False)

    def wait(self, condition, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.app.processEvents()
            if condition():
                return
            time.sleep(0.002)
        self.fail('Qt condition did not complete')

    def _cleanup_window(self, window, executor):
        for attr in ('_poll', '_executor_poll', '_theme_timer', '_sync_timer'):
            timer = getattr(window, attr, None)
            if timer is not None:
                timer.stop()
        for dlg_attr in (
            '_runtime_preserved_dialog',
            '_quit_notice_dialog',
            '_notice_persist_dialog',
            '_unrecorded_confirm_dialog',
            '_dead_owner_dialog',
        ):
            dlg = getattr(window, dlg_attr, None)
            if dlg is not None:
                dlg._acknowledged = True
                dlg.hide()
                dlg.deleteLater()
        if hasattr(window, '_invalidate_payment_decision'):
            window._invalidate_payment_decision()
        self.wait(lambda: getattr(window, '_worker', None) is None and not executor.busy)
        if not executor.closed and executor._backend is not None:
            executor._backend._notice_persist_failed = False
            executor._backend._quit_cleanup_uncertain = False
            executor._backend.session = None
            if hasattr(executor._backend, '_spend_session'):
                executor._backend._spend_session = None
            if executor._backend.owner is not None:
                executor._backend.owner.process = None
            try:
                executor.request('quit', timeout=5)
            except Exception:
                pass
        executor.join(5)
        window.hide()
        window.deleteLater()
        self.app.processEvents()

    def _q06_window(self, backend, *, bind_backend=True):
        executor = WalletExecutor(lambda: backend)
        if bind_backend:
            executor._backend = backend
            backend.attach_executor(executor)
        window = Bip39FusionWindow(executor)
        window.show()
        self.addCleanup(self._cleanup_window, window, executor)
        return executor, window

    def _q05_window(self, backend, *, bind_backend=True):
        executor = WalletExecutor(lambda: backend)
        if bind_backend:
            executor._backend = backend
            backend.attach_executor(executor)
        proxy = ManagedWalletProxy(executor, self.root, self.core, SOURCE)
        window = ManagedWalletWindow(proxy)
        window.background_available = True
        window.show()
        self.addCleanup(self._cleanup_window, window, executor)
        return executor, window

    def test_sb_se_sf_runtime_preserved_nonblocking_ack_race_and_close_event_guard_both_guis(self):
        for kind in ('Q06', 'Q05'):
            with self.subTest(kind=kind):
                parent = self.root.parent / f'sb_se_sf_{kind}'
                parent.mkdir(mode=0o700)
                sub_root = _private_core_root(parent)
                owner = _live_mock_owner(sub_root)
                if kind == 'Q06':
                    backend = Bip39ReadOnlyBackend(sub_root, self.core, SOURCE)
                    spend = Mock(locked=False, faulted=True, _q06_uncertain=True, _core_reauthentication_required=False)
                    spend.lock.side_effect = ValueError('Q06_SPEND_RUNTIME_PRESERVED')
                    backend._spend_session = spend
                    backend._secret = bytearray(PASSWORD)
                    backend.owner = owner
                    executor, window = self._q06_window(backend)
                    check_poll = window._check_quit
                else:
                    backend = ManagedWalletBackend(sub_root, self.core, SOURCE)
                    session = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
                    session.lock.side_effect = WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')
                    backend.session = session
                    backend.owner = owner
                    executor, window = self._q05_window(backend)
                    check_poll = window._poll_owner

                with exclusive_lease(sub_root), \
                        patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                        patch.object(type(self.app), 'quit') as app_quit:
                    # S-b: One Quit writes durable notice before owner.close(), closes executor, keeps Qt open.
                    window.request_quit()
                    self.wait(lambda: executor.closed and window._worker is None)
                    self.assertTrue(executor.state.runtime_preserved)
                    self.assertEqual(len(unacknowledged(sub_root, expected_profile_id=PROFILE_ID)), 1)
                    owner.release.assert_called_once_with()
                    owner.close.assert_called_once_with()
                    app_quit.assert_not_called()
                    self.assertNotIn('success', window.status.text().lower())

                    # S-e: Poll ticks before/while awaiting acknowledgement never quit Qt.
                    window._delivering_result = True
                    check_poll()
                    app_quit.assert_not_called()
                    window._delivering_result = False
                    check_poll()
                    self.app.processEvents()
                    app_quit.assert_not_called()
                    dlg = window._runtime_preserved_dialog
                    self.assertIsNotNone(dlg)
                    self.assertTrue(dlg.isVisible())

                    # Attempting to reject/escape the mandatory ack dialog does not close it or quit.
                    dlg.reject()
                    self.app.processEvents()
                    self.assertTrue(dlg.isVisible())
                    app_quit.assert_not_called()

                    # S-f: closeEvent while awaiting ack is ignored; no zero-window zombie app.exec().
                    ev = QCloseEvent()
                    window.closeEvent(ev)
                    self.assertFalse(ev.isAccepted())
                    self.assertTrue(window.isVisible())
                    app_quit.assert_not_called()

                    # Clicking explicit Acknowledge closes dialog and allows Qt exit.
                    dlg.ack_button.click()
                    self.app.processEvents()
                    app_quit.assert_called_once_with()
                    self.assertTrue(window._runtime_preserved_acknowledged)

                    # After acknowledgement, closeEvent accepts cleanly.
                    ev2 = QCloseEvent()
                    window.closeEvent(ev2)
                    self.assertTrue(ev2.isAccepted())

    def test_sg_serve_control_release_surfaces_runtime_preserved_and_keeps_qt_open(self):
        for idx, kind in enumerate(('Q06', 'Q05')):
            with self.subTest(kind=kind):
                parent = self.root.parent / f'sg_{idx}'
                parent.mkdir(mode=0o700)
                sub_root = _private_core_root(parent)
                with patch.object(CoreSupervisor, 'start'), \
                        patch.object(CoreSupervisor, 'recover_stop') as rec_stop:
                    cls = Bip39ReadOnlyBackend if kind == 'Q06' else ManagedWalletBackend
                    backend = cls(sub_root, self.core, SOURCE)
                    executor, window = (
                        self._q06_window(backend) if kind == 'Q06' else self._q05_window(backend)
                    )
                    executor.request('core_start', timeout=5)
                    owner = backend.owner
                    owner.process = Mock()
                    owner.process.poll.return_value = None
                    rec_stop.side_effect = lambda: setattr(owner, 'process', None)
                    if kind == 'Q06':
                        spend = Mock(locked=False, faulted=True, _q06_uncertain=True, _core_reauthentication_required=False)
                        spend.lock.side_effect = ValueError('Q06_SPEND_RUNTIME_PRESERVED')
                        backend._spend_session = spend
                        backend._secret = bytearray(PASSWORD)
                    else:
                        session = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
                        session.lock.side_effect = WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')
                        backend.session = session

                    with patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                            patch.object(type(self.app), 'quit') as app_quit:
                        if kind == 'Q06':
                            from wam_regtest.fusion_pages import PaymentApproval
                            from wam_regtest.wallet_session import PaymentReview
                            review = PaymentReview('wamrtsp1public', 100000, 10000, 400000, 1, 'a' * 64)
                            window._ready = True
                            window._spend_enabled = True
                            window._approved_commitment = review.commitment
                            window._payment_decision = PaymentApproval(review, 'sign', window)
                            window._payment_decision.open()
                        control(sub_root, 'recover-stop', authorized=True)
                        control(sub_root, 'release', authorized=True)
                        self.wait(lambda: executor.closed)
                        self.assertTrue(executor.state.runtime_preserved)
                        self.wait(lambda: window._runtime_preserved_dialog is not None
                                  and window._runtime_preserved_dialog.isVisible())
                        if kind == 'Q06':
                            self.assertIsNone(window._payment_decision)
                        app_quit.assert_not_called()
                        window._runtime_preserved_dialog.ack_button.click()
                        self.app.processEvents()
                        app_quit.assert_called_once_with()

    def test_launch_entrypoints_enter_exec_when_closed_with_unacked_runtime_preserved(self):
        from wam_regtest import bip39_owner_gui as owner_gui
        from wam_regtest import managed_gui

        fake_app = Mock()
        fake_executor = Mock(
            closed=True,
            state=ExecutorState(runtime_preserved=True),
        )
        fake_window = Mock(_runtime_preserved_acknowledged=False)

        with patch.object(owner_gui, 'qt_application', return_value=fake_app), \
                patch.object(owner_gui, 'WalletExecutor', return_value=fake_executor), \
                patch('wam_regtest.bip39_fusion_gui.Bip39FusionWindow', return_value=fake_window), \
                patch.object(owner_gui, '_onboarding_password', return_value=('', False)):
            owner_gui.launch_bip39_trial(self.root, self.core, SOURCE, mode='reopen', authorized=True)
        fake_app.exec.assert_called_once_with()

        fake_app2 = Mock()
        fake_qwidget = QWidget()
        fake_qwidget._runtime_preserved_acknowledged = False
        fake_qwidget.open_wallet = Mock()
        fake_qwidget.request_quit = Mock()
        self.addCleanup(lambda: (fake_qwidget.hide(), fake_qwidget.deleteLater(), self.app.processEvents()))
        with patch.object(managed_gui, 'qt_application', return_value=fake_app2), \
                patch.object(managed_gui, 'WalletExecutor', return_value=fake_executor), \
                patch.object(managed_gui, 'ManagedWalletProxy'), \
                patch.object(managed_gui, 'ManagedWalletWindow', return_value=fake_qwidget), \
                patch.object(managed_gui.QSystemTrayIcon, 'isSystemTrayAvailable', return_value=False), \
                patch.object(managed_gui, 'get_secret_text', return_value=('', False)):
            managed_gui.launch_managed(self.root, self.core, SOURCE, authorized=True)
        fake_app2.exec.assert_called_once_with()

    def test_gui_unresolved_notice_ack_and_dead_owner_recovery_for_q05_and_q06(self):
        # Q06: reopen exposes unresolved notice -> dialog opens -> ack unblocks.
        q06_parent = self.root.parent / 'gui_ack_q06'
        q06_parent.mkdir(mode=0o700)
        q06_root = _private_core_root(q06_parent)
        with patch.object(CoreSupervisor, 'start'):
            backend = Bip39ReadOnlyBackend(q06_root, self.core, SOURCE)
            executor, window = self._q06_window(backend)
            executor.request('core_start', timeout=5)
            owner = backend.owner
            owner.process = Mock()
            owner.process.poll.return_value = None
            seed_folder = owner.directory / ('bip39-12-' + 'a' * 32)
            seed_folder.mkdir()
            publish_notice(
                q06_root,
                profile_id=owner.profile['profile_id'],
                session_kind='Q06',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                journal_seq=2,
            )
            from wam_regtest.bip39_12 import Bip39Regtest12Keys
            keys = Bip39Regtest12Keys(PHRASE, source=SOURCE, authorized_disposable=True)
            keys._q06_generation = 2
            backend._q06_write_ack(seed_folder, True, secret=keys.backup_ack_key())
            with patch('wam_regtest.bip39_seed_vault.open_owned_seed_container') as opened:
                opened.return_value.__enter__ = lambda *a, **kw: keys
                opened.return_value.__exit__ = lambda *a, **kw: None
                window.start(PASSWORD, 'reopen', '')
                self.wait(lambda: window._quit_notice_dialog is not None
                          and window._quit_notice_dialog.isVisible())
            window._quit_notice_dialog.ack_button.click()
            self.wait(lambda: window._worker is None and window._unresolved_quit_notices == ())
            self.assertEqual(unacknowledged(q06_root, expected_profile_id=owner.profile['profile_id']), ())

            # Dead owner on Quit -> dead-owner dialog -> Recover & Restart runs recover_dead.
            owner.process.poll.return_value = 9
            with patch.object(owner, 'recover_dead') as rec_dead:
                rec_dead.side_effect = lambda authorized=False: setattr(owner, 'process', None)
                window.request_quit()
                self.wait(lambda: window._dead_owner_dialog is not None
                          and window._dead_owner_dialog.isVisible())
                window._dead_owner_dialog.recover_button.click()
                self.wait(lambda: window._worker is None and rec_dead.called)
                rec_dead.assert_called_once_with(authorized=True)

        # Q05: open fails QUIT_NOTICE_REVIEW_REQUIRED -> fetches quit_notices -> ack unblocks.
        q05_parent = self.root.parent / 'gui_ack_q05'
        q05_parent.mkdir(mode=0o700)
        q05_root = _private_core_root(q05_parent)
        with patch.object(CoreSupervisor, 'start'):
            q05_backend = ManagedWalletBackend(q05_root, self.core, SOURCE)
            q05_exec, q05_win = self._q05_window(q05_backend)
            q05_exec.request('core_start', timeout=5)
            q05_owner = q05_backend.owner
            q05_owner.process = Mock()
            q05_owner.process.poll.return_value = None
            publish_notice(
                q05_root,
                profile_id=q05_owner.profile['profile_id'],
                session_kind='Q05',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                journal_seq=2,
            )
            with patch('wam_regtest.wallet_session.WalletSession.open_owned',
                       side_effect=WalletSessionError('QUIT_NOTICE_REVIEW_REQUIRED')):
                q05_win.open_wallet(PASSWORD, create=False)
                self.wait(lambda: q05_win._quit_notice_dialog is not None
                          and q05_win._quit_notice_dialog.isVisible())
            q05_win._quit_notice_dialog.ack_button.click()
            self.wait(lambda: q05_win._worker is None
                      and unacknowledged(q05_root, expected_profile_id=q05_owner.profile['profile_id']) == ())

            # Q05 dead owner on Quit -> dead-owner dialog -> Recover & Restart.
            q05_owner.process.poll.return_value = 9
            with patch.object(q05_owner, 'recover_dead') as rec_dead:
                rec_dead.side_effect = lambda authorized=False: setattr(q05_owner, 'process', None)
                q05_win.request_quit()
                self.wait(lambda: q05_win._dead_owner_dialog is not None
                          and q05_win._dead_owner_dialog.isVisible())
                q05_win._dead_owner_dialog.recover_button.click()
                self.wait(lambda: q05_win._worker is None and rec_dead.called)
                rec_dead.assert_called_once_with(authorized=True)

    def test_gui_notice_persist_failed_retry_unrecorded_and_double_fault_blocked(self):
        # Stopped Core: retry button OR unrecorded two-step confirmation exits.
        parent = self.root.parent / 'gui_persist_unrec'
        parent.mkdir(mode=0o700)
        sub_root = _private_core_root(parent)
        owner = _live_mock_owner(sub_root)
        backend = Bip39ReadOnlyBackend(sub_root, self.core, SOURCE)
        spend = Mock(locked=False, faulted=True, _q06_uncertain=True, _core_reauthentication_required=False)
        spend.lock.side_effect = ValueError('Q06_SPEND_RUNTIME_PRESERVED')
        backend._spend_session = spend
        backend._secret = bytearray(PASSWORD)
        backend.owner = owner
        executor, window = self._q06_window(backend)
        with exclusive_lease(sub_root), \
                patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                patch('wam_regtest.quit_notice.publish_notice', side_effect=OSError('ENOSPC')), \
                patch.object(type(self.app), 'quit') as app_quit:
            window.request_quit()
            self.wait(lambda: window._notice_persist_dialog is not None
                      and window._notice_persist_dialog.isVisible())
            dlg = window._notice_persist_dialog
            self.assertTrue(dlg.retry_button.isEnabled())
            self.assertTrue(dlg.unrecorded_button.isEnabled())
            dlg.unrecorded_button.click()
            self.wait(lambda: window._unrecorded_confirm_dialog is not None
                      and window._unrecorded_confirm_dialog.isVisible())
            app_quit.assert_not_called()
            window._unrecorded_confirm_dialog.confirm_button.click()
            self.wait(lambda: executor.closed)
            self.wait(lambda: app_quit.called)

        # Double fault (Core alive + persist failed): unrecorded exit button is DISABLED.
        parent2 = self.root.parent / 'gui_persist_live'
        parent2.mkdir(mode=0o700)
        sub_root2 = _private_core_root(parent2)
        owner2 = _live_mock_owner(sub_root2)
        owner2._faulted = True
        owner2.recover_stop.side_effect = ValueError('CORE_RPC_PROCESS_IDENTITY_DENIED')
        backend2 = ManagedWalletBackend(sub_root2, self.core, SOURCE)
        backend2.owner = owner2
        exec2, win2 = self._q05_window(backend2)
        with exclusive_lease(sub_root2), \
                patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                patch('wam_regtest.quit_notice.publish_notice', side_effect=OSError('EIO')), \
                patch.object(type(self.app), 'quit') as app_quit2:
            win2.request_quit()
            self.wait(lambda: win2._notice_persist_dialog is not None
                      and win2._notice_persist_dialog.isVisible())
            self.assertFalse(win2._notice_persist_dialog.unrecorded_button.isEnabled())
            self.assertFalse(exec2.closed)
            app_quit2.assert_not_called()

        # Stopped Core: retry button retries publish, then finishes quit -> runtime_preserved ack.
        parent3 = self.root.parent / 'gui_persist_retry'
        parent3.mkdir(mode=0o700)
        sub_root3 = _private_core_root(parent3)
        owner3 = _live_mock_owner(sub_root3)
        backend3 = ManagedWalletBackend(sub_root3, self.core, SOURCE)
        session3 = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
        session3.lock.side_effect = WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')
        backend3.session = session3
        backend3.owner = owner3
        exec3, win3 = self._q05_window(backend3)
        with exclusive_lease(sub_root3), \
                patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                patch.object(type(self.app), 'quit') as app_quit3:
            with patch('wam_regtest.quit_notice.publish_notice', side_effect=OSError('ENOSPC')):
                win3.request_quit()
                self.wait(lambda: win3._notice_persist_dialog is not None
                          and win3._notice_persist_dialog.isVisible())
            win3._notice_persist_dialog.retry_button.click()
            self.wait(lambda: exec3.closed)
            self.wait(lambda: win3._runtime_preserved_dialog is not None
                      and win3._runtime_preserved_dialog.isVisible())
            app_quit3.assert_not_called()
            win3._runtime_preserved_dialog.ack_button.click()
            self.app.processEvents()
            app_quit3.assert_called_once_with()
            self.assertEqual(len(unacknowledged(sub_root3, expected_profile_id=PROFILE_ID)), 1)

    def test_dead_owner_dialog_closes_on_subsequent_clean_quit_and_exits_event_loop(self):
        from PySide6.QtCore import QCoreApplication, QTimer
        for idx, kind in enumerate(('Q06', 'Q05')):
            with self.subTest(kind=kind):
                parent = self.root.parent / f'dead_then_quit_{idx}'
                parent.mkdir(mode=0o700)
                sub_root = _private_core_root(parent)
                owner = _live_mock_owner(sub_root)
                owner.process.poll.return_value = 9
                backend = (
                    Bip39ReadOnlyBackend(sub_root, self.core, SOURCE)
                    if kind == 'Q06'
                    else ManagedWalletBackend(sub_root, self.core, SOURCE)
                )
                backend.owner = owner
                executor, window = (
                    self._q06_window(backend)
                    if kind == 'Q06'
                    else self._q05_window(backend)
                )
                window.request_quit()
                self.wait(lambda: window._dead_owner_dialog is not None
                          and window._dead_owner_dialog.isVisible())
                self.assertFalse(executor.closed)

                # Subsequent clean quit must close the dead-owner dialog and exit app.exec().
                owner.process = None
                seen = {}

                def watchdog():
                    seen['watchdog'] = True
                    QCoreApplication.exit(99)

                dog = QTimer()
                dog.setSingleShot(True)
                dog.timeout.connect(watchdog)
                dog.start(4000)
                QTimer.singleShot(50, window.request_quit)
                rc = self.app.exec()
                dog.stop()
                self.assertNotIn('watchdog', seen)
                self.assertEqual(rc, 0)
                self.assertTrue(executor.closed)
                self.assertIsNone(window._dead_owner_dialog)

    def test_all_six_locales_render_quit_lifecycle_copy_without_raw_keys(self):
        for lang in SUPPORTED_LANGUAGES:
            with self.subTest(language=lang), patch.object(bip39_locale, '_lang', return_value=lang):
                for key in CATALOG['en']:
                    if key.startswith('quit_lifecycle.') or key in (
                        'errors.QUIT_NOTICE_REVIEW_REQUIRED',
                        'errors.NOTICE_PERSIST_FAILED',
                        'errors.MANAGED_DEAD_OWNER_RECOVERY_REQUIRED',
                        'errors.MANAGED_SHUTDOWN_UNCERTAIN',
                    ):
                        rendered = bip39_locale.t(key)
                        self.assertEqual(rendered, text(key, lang))
                        self.assertNotEqual(rendered, key)


@unittest.skipIf(sys.platform == 'win32', 'N03 uses POSIX SIGSTOP in a disposable subprocess fixture')
class DisposableSigstopHangN03Contracts(unittest.TestCase):
    """Test-only N03 SIGSTOP hang in a disposable subprocess fixture."""

    setUp = sup_fixture.SupervisorLifecycleUnit.setUp
    owner = sup_fixture.SupervisorLifecycleUnit.owner
    runtime = sup_fixture.SupervisorLifecycleUnit.runtime

    def test_n03_sigstop_hang_keeps_owner_blocked_then_sigcont_exit_allows_recover_dead(self):
        owner = self.owner()
        child = subprocess.Popen(
            [sys.executable, '-c', 'import sys;sys.stdin.buffer.read()'],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        def cleanup():
            if child.poll() is None:
                try:
                    os.kill(child.pid, signal.SIGCONT)
                except OSError:
                    pass
                if child.stdin is not None and not child.stdin.closed:
                    child.stdin.close()
                child.wait(timeout=5)
            owner.process = None

        self.addCleanup(cleanup)
        owner.process = child
        owner._registered = True
        owner._faulted = True
        owner.binding = Mock(process=child)
        owner.read = Mock()
        owner.journal.append('STARTING')
        owner.journal.append('RUNNING', child.pid)

        backend = ManagedWalletBackend(owner.root, owner.core, SOURCE)
        backend.owner = owner
        executor = WalletExecutor(lambda: backend)
        executor._backend = backend
        backend.attach_executor(executor)
        self.addCleanup(lambda: (
            setattr(owner, 'process', None) if not executor.closed else None,
            executor.request('quit') if not executor.closed else None,
            executor.join(5),
        ))

        # Freeze the disposable child with SIGSTOP (test fixture only).
        os.kill(child.pid, signal.SIGSTOP)
        binding = Mock(spec=sup_mod.OwnedCoreBinding)
        with patch.object(sup_mod, 'OwnedCoreBinding', return_value=binding), \
                patch.object(sup_mod, 'reauthenticate_owned'), \
                patch.object(sup_mod, '_read_cli', side_effect=sup_mod.CoreSmokeError('CORE_RPC_TIMEOUT_UNCERTAIN')), \
                patch.object(sup_mod, 'STOP_EXIT_BUDGET', 0.2), \
                patch.object(sup_mod, 'identity', return_value=SimpleNamespace(binding=SimpleNamespace(process=child), faulted=False)), \
                patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(binding=SimpleNamespace(process=child), faulted=False)):
            with self.assertRaisesRegex(WalletExecutorError, '^MANAGED_SHUTDOWN_UNCERTAIN$'):
                executor.request('quit', timeout=5)

        # Hung child stays owned, executor open, journal STOPPING, notice recorded.
        self.assertFalse(executor.closed)
        self.assertTrue(executor.state.core_alive)
        self.assertIs(owner.process, child)
        self.assertEqual(owner.journal.state, 'STOPPING')
        notices = unacknowledged(owner.root, expected_profile_id=owner.profile['profile_id'])
        notice_items = [n for n in notices if n['kind'] == 'notice']
        failure_items = [n for n in notices if n['kind'] == 'failure']
        self.assertEqual(len(notice_items), 1)
        self.assertEqual(notice_items[0]['notice']['core_stop'], 'UNCERTAIN')
        self.assertEqual(len(failure_items), 1)
        self.assertEqual(failure_items[0]['code'], 'MANAGED_SHUTDOWN_UNCERTAIN')

        # Resume disposable child and let it exit -> dead-owner gate -> explicit recover_dead restarts.
        os.kill(child.pid, signal.SIGCONT)
        child.stdin.close()
        child.wait(timeout=5)
        with self.assertRaisesRegex(WalletExecutorError, '^MANAGED_DEAD_OWNER_RECOVERY_REQUIRED$'):
            executor.request('quit', timeout=5)
        self.assertFalse(executor.closed)

        with patch.object(sup_mod, 'identity', return_value=SimpleNamespace(binding=SimpleNamespace(process=child))), \
                patch.object(owner, 'start') as restarted:
            restarted.side_effect = lambda _recovering=False: owner.journal.append('STARTING')
            executor.request('core_restart', timeout=5)
        restarted.assert_called_once_with(_recovering=True)
        self.assertIn('RECOVERING', [e['state'] for e in owner.journal.events])
        owner.process = None


if __name__ == '__main__':
    unittest.main()
