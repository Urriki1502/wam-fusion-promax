"""PM-019: application Quit vs the BIP39 wallet owner lifetime.

W-QUIT-01 (characterization): an application-level Quit, which is what macOS
Command+Q and the application menu deliver, must never end app.exec() while
the real WalletExecutor owner is still open: idle, busy, or with a modal open.

W-QUIT-02 (fix): a refused owner shutdown must not be resubmitted
automatically. Before PM-019 the GUI re-sent "quit" after every refusal with
no bound (about 550 attempts per second against a refusing backend).

These tests use the real WalletExecutor and the real Bip39FusionWindow; only
the backend is a stub. No Core, keys or profiles are involved.
"""
import sys
import threading
import time
import unittest
import unittest.mock

from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from wam_regtest.desktop import qt_application
from wam_regtest.bip39_locale import t
from wam_regtest.wallet_executor import WalletExecutor, WalletExecutorError


class _Backend:
    """Stub owner. quit succeeds unless refuse_quit is set."""

    def __init__(self, busy_s=0.0, refuse_quit=None):
        self.busy_s = busy_s
        self.refuse_quit = refuse_quit  # None, 'alive' or a public error code
        self.calls = []
        self._lock = threading.Lock()

    def execute(self, action, args, kwargs):
        with self._lock:
            self.calls.append(action)
        if action == 'snapshot' and self.busy_s:
            time.sleep(self.busy_s)
        if action == 'quit' and self.refuse_quit not in (None, 'alive'):
            raise WalletExecutorError(self.refuse_quit)
        return None if action == 'quit' else {}

    def public_state(self):
        return dict(locked=True, faulted=False, reauthentication_required=False,
                    core_alive=self.refuse_quit == 'alive')

    def quits(self):
        with self._lock:
            return self.calls.count('quit')


def _post_quit():
    QApplication.postEvent(QApplication.instance(), QEvent(QEvent.Type.Quit))


class QuitLifetimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = qt_application()
        cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        self.backend = None
        self.executor = WalletExecutor(self._factory)
        self.executor.request('snapshot', timeout=10)  # owner open, like a real session
        self.window = Bip39FusionWindow(self.executor)
        self.window.show()
        self.addCleanup(self._cleanup)

    def _factory(self):
        self.backend = _Backend()
        return self.backend

    def _cleanup(self):
        backend = self.backend
        backend.busy_s = 0
        backend.refuse_quit = None
        deadline = time.monotonic() + 10
        while not self.executor.closed and time.monotonic() < deadline:
            if not self.executor.busy:
                try:
                    self.executor.request('quit', timeout=5)
                except Exception:
                    pass
            time.sleep(0.02)
        self.executor.join(5)
        self.window._poll.stop()
        self.window.close()
        self.window.deleteLater()
        # A delivered Quit leaves Qt's "quit now" flag set for this shared
        # QApplication; spin one empty loop to reset it for the next test.
        QTimer.singleShot(0, self.app.quit)
        self.app.exec()

    def _exec(self, watchdog_s):
        seen = {}

        def watchdog():
            seen['watchdog'] = True
            QCoreApplication.exit(99)  # test-only, unconditional escape

        dog = QTimer()
        dog.setSingleShot(True)
        dog.timeout.connect(watchdog)
        dog.start(int(watchdog_s * 1000))
        started = time.monotonic()
        rc = self.app.exec()
        dog.stop()
        seen.update(rc=rc, seconds=time.monotonic() - started,
                    closed_at_return=self.executor.closed)
        return seen

    # W-QUIT-01 characterization -------------------------------------------
    def test_quit_with_idle_owner_returns_only_after_owner_closed(self):
        QTimer.singleShot(50, _post_quit)
        seen = self._exec(6)
        self.assertNotIn('watchdog', seen)
        self.assertTrue(seen['closed_at_return'])
        self.assertEqual(self.backend.quits(), 1)

    def test_quit_with_busy_owner_waits_for_the_operation_then_closes(self):
        self.backend.busy_s = 1.0
        self.executor.submit('snapshot')
        QTimer.singleShot(50, _post_quit)
        seen = self._exec(8)
        self.assertNotIn('watchdog', seen)
        self.assertTrue(seen['closed_at_return'])
        self.assertGreaterEqual(seen['seconds'], 0.9)
        self.assertEqual(self.backend.calls, ['snapshot', 'snapshot', 'quit'])

    def test_quit_while_a_modal_is_open_still_closes_the_owner_first(self):
        def modal():
            QTimer.singleShot(150, _post_quit)
            QMessageBox(QMessageBox.Icon.Information, 'REGTEST', 'modal',
                        QMessageBox.StandardButton.Ok, self.window).exec()
        QTimer.singleShot(50, modal)
        seen = self._exec(6)
        self.assertNotIn('watchdog', seen)
        self.assertTrue(seen['closed_at_return'])
        self.assertEqual(self.backend.quits(), 1)

    def test_two_quits_make_one_owner_shutdown(self):
        QTimer.singleShot(50, _post_quit)
        QTimer.singleShot(60, _post_quit)
        seen = self._exec(6)
        self.assertNotIn('watchdog', seen)
        self.assertTrue(seen['closed_at_return'])
        self.assertEqual(self.backend.quits(), 1)

    # W-QUIT-02 fix ----------------------------------------------------------
    def _refused_quit_is_attempted_once(self, refusal):
        self.backend.refuse_quit = refusal
        QTimer.singleShot(50, _post_quit)
        seen = self._exec(1.5)
        # The owner stays open, so the event loop must still be running.
        self.assertTrue(seen.get('watchdog'))
        self.assertFalse(seen['closed_at_return'])
        self.assertEqual(self.backend.quits(), 1)
        self.assertFalse(self.window._quit_requested)
        self.assertTrue(self.window.status.text().startswith(t('owner.refused_prefix'))
                        or self.window.status.text() == t('owner.faulted'))
        self.assertTrue(self.window.quit.isEnabled())
        # A further EXPLICIT Quit is exactly one new attempt; here it succeeds.
        self.backend.refuse_quit = None
        QTimer.singleShot(50, self.window.request_quit)
        seen = self._exec(6)
        self.assertNotIn('watchdog', seen)
        self.assertTrue(seen['closed_at_return'])
        self.assertEqual(self.backend.quits(), 2)

    def test_refused_quit_with_core_still_alive_is_not_retried(self):
        self._refused_quit_is_attempted_once('alive')

    def test_refused_quit_with_dead_owner_is_not_retried(self):
        self._refused_quit_is_attempted_once('MANAGED_DEAD_OWNER_RECOVERY_REQUIRED')

    def test_refused_quit_then_window_close_is_one_new_attempt(self):
        self.backend.refuse_quit = 'alive'
        QTimer.singleShot(50, _post_quit)
        self._exec(1.0)
        self.assertEqual(self.backend.quits(), 1)
        QTimer.singleShot(50, self.window.close)  # closeEvent -> request_quit
        seen = self._exec(1.0)
        self.assertTrue(seen.get('watchdog'))
        self.assertEqual(self.backend.quits(), 2)
        self.assertFalse(self.executor.closed)

    # Window destroyed right after Quit ----------------------------------------
    def test_pending_overview_fade_is_dropped_when_the_window_is_destroyed(self):
        import contextlib
        import io
        from PySide6.QtCore import QEventLoop
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        window = Bip39FusionWindow(self.executor)
        window._poll.stop()
        window.reduce_motion.setChecked(False)
        window._overview_intro = False
        with unittest.mock.patch('wam_regtest.bip39_fusion_gui.motion_reduced', return_value=False):
            window._play_overview_intro()
        window.deleteLater()
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            deadline = time.monotonic() + 0.4
            while time.monotonic() < deadline:
                self.app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 20)
                QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        self.assertNotIn('already deleted', errors.getvalue())
        self.assertNotIn('Traceback', errors.getvalue())

    # Native macOS Command+Q (cocoa only) -----------------------------------
    @unittest.skipUnless(sys.platform == 'darwin', 'AppKit application menu')
    def test_macos_command_q_with_busy_owner_closes_owner_before_exec_returns(self):
        if QApplication.platformName() != 'cocoa':
            self.skipTest('Requires the native cocoa platform plugin')
        from test_jeeves_onboarding_regression import _macos_send_command_q
        self.window.raise_()
        self.window.activateWindow()
        self.backend.busy_s = 1.0
        self.executor.submit('snapshot')
        QTimer.singleShot(100, _macos_send_command_q)
        seen = self._exec(8)
        self.assertNotIn('watchdog', seen, 'Command+Q did not end the session')
        self.assertTrue(seen['closed_at_return'])
        self.assertEqual(self.backend.quits(), 1)


if __name__ == '__main__':
    unittest.main()
