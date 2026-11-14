"""Real window/ControlWorker/WalletExecutor with recording, synthetic backend.

No Core/process/miner command is implemented; no wallet/profile or secrets read.
Cleanup quit is outside measured command intervals. Late-result probes inject
public delivery deliberately; they do not prove executor concurrency reachable.
"""
import threading
import time
import unittest
from unittest.mock import patch
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QLabel
from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
from wam_regtest.wallet_executor import WalletExecutor, ExecutorState
from wam_regtest.bip39_locale import t
from test_pm060_d2a_overview_state import snapshot, result


class OverviewCommands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def setUp(self):
        self.calls = []
        self.gate = threading.Event()
        self.gate.set()
        case = self

        class Backend:
            core_alive = True
            locked = False
            faulted = False
            def public_state(self):
                return dict(locked=self.locked, faulted=self.faulted, core_alive=self.core_alive)
            def execute(self, action, args, kwargs):
                case.calls.append(action)
                if action == 'snapshot':
                    case.gate.wait(3)
                    return result()
                if action == 'quit': self.core_alive = False
                if action == 'lock': self.locked = True
                return None

        self.owner = WalletExecutor(Backend)
        self.w = Bip39FusionWindow(self.owner)
        self.w._poll.stop()
        self.owner.request('core_status')
        self.calls.clear()
        self.w._ready = self.w._spend_enabled = True
        self.w._on_ready('snapshot', result())
        self.w.show()
        self.app.processEvents()

    def tearDown(self):
        self.gate.set()
        self.wait(lambda: self.w._worker is None)
        self.w._poll.stop()
        if not self.owner.closed: self.owner.request('quit')
        self.assertTrue(self.owner.join())
        self.w.hide()
        self.w.deleteLater()
        self.app.processEvents()

    def wait(self, predicate):
        until = time.monotonic() + 5
        while not predicate() and time.monotonic() < until:
            self.app.processEvents()
            QTest.qWait(5)
        self.assertTrue(predicate(), 'bounded synthetic worker deadline')

    def test_navigation_copy_and_qr_have_zero_dispatch_and_exact_payload(self):
        import qrcode
        original = qrcode.QRCode.add_data
        payloads = []
        def capture(qr, data, *args, **kwargs):
            payloads.append(data)
            return original(qr, data, *args, **kwargs)
        with patch.object(self.w, '_command', wraps=self.w._command) as command, \
                patch.object(qrcode.QRCode, 'add_data', capture):
            self.w.receive_page.render_snapshot(snapshot())
            for button, row in ((self.w.overview.go_receive, 1),
                                (self.w.overview.open_history, 2),
                                (self.w.overview.go_send, 3),
                                (self.w.overview.open_security, 4)):
                self.w.navigation.setCurrentRow(0)
                button.click()
                self.assertEqual(self.w.navigation.currentRow(), row)
            self.w.navigation.setCurrentRow(1)
            self.w.receive_page.copy_button.click()
            self.assertEqual(payloads, [snapshot().receive_code])
            self.assertEqual(self.w.receive_page.receive_code.text(), payloads[0])
            self.assertEqual(self.app.clipboard().text(), payloads[0])
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4, box_size=1)
            qr.add_data(payloads[0], optimize=0)
            qr.make(fit=True)
            self.assertEqual(self.w.receive_page.qr.matrix, qr.get_matrix())
            command.assert_not_called()
            self.assertEqual(self.calls, [])

    def test_rapid_refresh_one_snapshot_and_disabled_refresh_zero(self):
        self.gate.clear()
        with patch.object(self.w, '_command', wraps=self.w._command) as command:
            for _ in range(6): self.w.sync.click()
            self.wait(lambda: self.calls == ['snapshot'])
            self.assertEqual([c.args[0] for c in command.call_args_list], ['snapshot'])
            self.assertFalse(self.w.sync.isEnabled())
            self.gate.set()
            self.wait(lambda: self.w._worker is None)
            self.assertEqual(self.calls, ['snapshot'])
        self.w._on_ready('lock', None)
        self.calls.clear()
        with patch.object(self.w, '_command') as command:
            self.w.sync.click()
            command.assert_not_called()
        self.assertEqual(self.calls, [])

    def clear_event(self, event):
        if event == 'lock':
            self.w._on_ready('lock', None)
        elif event == 'fault':
            self.owner._state = ExecutorState(locked=True, faulted=True, core_alive=False)
            self.w._on_denied('WALLET_CORE_UNAVAILABLE')
        else:
            # Deliver public open result only. No actual profile opened or remembered.
            self.w._on_ready('open', dict(receive_code='', account_id='new-public-account',
                                         checkpoint_present=True))

    def assert_financial_clear(self):
        self.assertIsNone(self.w._last_verified)
        self.assertEqual(self.w.overview.balance_value.text(), '—')
        self.assertTrue(self.w.overview.balance_unit.isHidden())
        self.assertTrue(self.w.overview.fund_details.isHidden())
        self.assertEqual(self.w.overview._txids, [])
        self.assertEqual(self.w.overview.activity_table.rowCount(), 0)
        self.assertIsNone(self.w.receive_page.code)
        self.assertIsNone(self.w.receive_page.qr.matrix)
        self.assertEqual(self.w.receive_page.receive_code.text(), '—')
        self.assertFalse(self.w.receive_page.copy_button.isEnabled())
        self.assertEqual(self.w.history_page.rows, ())
        self.assertFalse(self.w.history_page.copy_button.isEnabled())

    def test_lock_fault_profile_clear_financials_no_synthetic_zero(self):
        for event in ('lock', 'fault', 'profile'):
            with self.subTest(event=event):
                self.owner._state = ExecutorState(locked=False, core_alive=True)
                self.w._on_ready('snapshot', result())
                self.w.receive_page.copy_button.click()  # pending feedback timer
                self.clear_event(event)
                self.assert_financial_clear()
                # Explicit timer delivery avoids a 2.2 second sleep per fixture.
                self.w.receive_page._copy_timer.timeout.emit()
                self.assertEqual(self.w.receive_page.copy_status.text(), t('pages.address_locked'))
                # Public clipboard is deliberately not auto-cleared by lock.
                self.assertEqual(self.app.clipboard().text(), snapshot().receive_code)

    @unittest.expectedFailure
    def test_refresh_failure_has_visible_stale_signal(self):
        """D2A-2: stale signal exists as text but is on hidden live_badge."""
        self.w._on_denied('WALLET_READ_DENIED')
        self.assertIsNotNone(self.w._last_verified)
        self.assertEqual(self.w.overview.live_badge.text(), t('wallet.refresh_required'))
        self.assertTrue(any(x.isVisible() and x.text() == t('wallet.refresh_required')
                            for x in self.w.overview.findChildren(QLabel)), 'D2A-2 hidden stale signal')

    @unittest.expectedFailure
    def test_lock_clears_network_cache(self):
        """D2A-3: last network survives lock and still classifies connected."""
        self.w._last_network = dict(connected=True, peer_count=2, height=112, tip='34'*32)
        self.clear_event('lock')
        self.assertNotIn('peer_count', self.w._network_view(None), 'D2A-3 stale network after lock')

    @unittest.expectedFailure
    def test_profile_clears_network_cache(self):
        """D2A-3: previous profile peer observation survives public open delivery."""
        self.w._last_network = dict(connected=True, peer_count=2, height=112, tip='34'*32)
        self.clear_event('profile')
        self.assertNotIn('peer_count', self.w._network_view(None), 'D2A-3 stale network after profile switch')

    @unittest.expectedFailure
    def test_profile_clears_old_error(self):
        """D2A-4: a delivered open does not clear previous diagnostic code."""
        self.w._on_denied('WALLET_CORE_UNAVAILABLE')
        self.clear_event('profile')
        self.assertIsNone(self.w._last_error_code, 'D2A-4 old profile error retained')

    @unittest.expectedFailure
    def test_fault_clears_session_labels(self):
        """D2A-5: inherited advanced account/balance/tip labels survive fault."""
        self.w.account.setText('public-account-before-fault')
        self.clear_event('fault')
        self.assert_financial_clear()
        self.assertNotIn('public-account-before-fault', self.w.account.text(), 'D2A-5 stale account label')
        self.assertNotIn('100000', self.w.balance.text(), 'D2A-5 stale balance label')

    @unittest.expectedFailure
    def test_late_snapshot_after_lock_not_repainted(self):
        """D2A-6: direct public delivery lacks locked/generation guard.

        Reachability through serialized owner worker is UNKNOWN, not a proven
        custody bypass. Deliberate delivery probe only.
        """
        self.clear_event('lock')
        self.owner._state = ExecutorState(locked=True, core_alive=True)
        self.w._on_ready('snapshot', result())
        self.assertIsNone(self.w._last_verified, 'D2A-6 late snapshot repaints locked window')

    @unittest.expectedFailure
    def test_late_old_profile_snapshot_not_repainted(self):
        """D2A-6: public result has no profile generation comparison."""
        self.clear_event('profile')
        self.w._on_ready('snapshot', result())
        self.assertIsNone(self.w._last_verified, 'D2A-6 old profile snapshot accepted')

    def test_diagnostic_and_session_label_lifetimes_today(self):
        for event in ('lock', 'fault', 'profile'):
            with self.subTest(event=event):
                self.owner._state = ExecutorState(locked=False, core_alive=True)
                self.w._on_ready('snapshot', result())
                self.w.account.setText('public-account-before-event')
                before = (self.w.account.text(), self.w.balance.text(), self.w.tip.text())
                net = dict(connected=True, peer_count=2, height=112, tip='34'*32)
                self.w._last_network = net
                self.w._last_error_code = 'WALLET_READ_DENIED'
                self.clear_event(event)
                self.assertIsNone(self.w._last_verified)
                self.assertIs(self.w._last_network, net)
                if event == 'fault':
                    self.assertEqual(self.w._last_error_code, 'WALLET_CORE_UNAVAILABLE')
                    self.assertEqual((self.w.account.text(), self.w.balance.text(), self.w.tip.text()), before)
                else:
                    self.assertEqual(self.w._last_error_code, 'WALLET_READ_DENIED')
                    self.assertNotIn('public-account-before-event', self.w.account.text())
                    self.assertNotIn('100000', self.w.balance.text())

    def test_actual_lock_command_resets_old_error_and_rejects_faulted_late_snapshot(self):
        self.w._last_error_code = 'WALLET_READ_DENIED'
        self.assertTrue(self.w._command('lock'))
        self.assertIsNone(self.w._last_error_code)
        self.wait(lambda: self.w._worker is None)
        self.assert_financial_clear()
        self.owner._state = ExecutorState(locked=True, faulted=True, core_alive=False)
        self.w._on_ready('snapshot', result())
        self.assert_financial_clear()

    @unittest.expectedFailure
    def test_lock_clears_hidden_balance_text_buffers(self):
        """D2A-7: fund_details is hidden but retains previous wallet amounts."""
        self.clear_event('lock')
        self.assert_financial_clear()
        self.assertNotIn('0.00007000 WAM', self.w.overview.fund_details.text(),
                         'D2A-7 wallet-linked hidden label retained')

    def test_core_loss_and_identity_mismatch_clear_without_zero(self):
        for refusal in ('WALLET_CORE_AUTHENTICATION_DENIED', 'WALLET_CORE_IDENTITY_DENIED',
                        'WALLET_CORE_UNAVAILABLE', 'WALLET_CORE_UNVERIFIED'):
            with self.subTest(refusal=refusal):
                self.w._on_ready('snapshot', result())
                self.w._on_denied(refusal)
                self.assert_financial_clear()
        self.w._on_ready('snapshot', result())
        wrong = result()
        wrong['receive_code'] = 'different-public-address'
        self.w._on_ready('snapshot', wrong)
        self.assert_financial_clear()

    @unittest.expectedFailure
    def test_busy_retained_snapshot_has_visible_last_verified_signal(self):
        """D2A-2: busy retains verified facts without visible currentness signal."""
        self.gate.clear()
        self.w.sync.click()
        self.wait(lambda: self.calls == ['snapshot'])
        self.assertIsNotNone(self.w._last_verified)
        self.assertTrue(any(x.isVisible() and 'Last verified' in x.text()
                            for x in self.w.overview.findChildren(QLabel)),
                        'D2A-2 busy snapshot lacks last-verified signal')
