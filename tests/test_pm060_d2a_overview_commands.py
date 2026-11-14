"""Real window/ControlWorker/WalletExecutor with recording, synthetic backend.

No Core/process/miner command is implemented; no wallet/profile or secrets read.
Cleanup quit is outside measured command intervals. Late results use real Qt
workers/executor generations; the control-bridge lock ordering is reachable.
"""
import threading
import time
import unittest
from unittest.mock import patch
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QLabel, QLineEdit, QWidget
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
                if action == 'open':
                    return dict(receive_code='', account_id='new-public-account', checkpoint_present=True)
                if action == 'quit': self.core_alive = False
                if action == 'lock' or action == 'control' and args == ('stop',): self.locked = True
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

    def test_refresh_failure_has_visible_stale_signal(self):
        """D2A-2: stale signal exists as text but is on hidden live_badge."""
        self.w._on_denied('WALLET_READ_DENIED')
        self.assertIsNotNone(self.w._last_verified)
        self.assertEqual(self.w.overview.live_badge.text(), t('wallet.refresh_required'))
        self.assertTrue(any(x.isVisible() and x.text() == t('wallet.refresh_required')
                            for x in self.w.overview.findChildren(QLabel)), 'D2A-2 hidden stale signal')

    def test_lock_clears_network_cache(self):
        """D2A-3: lock must revoke the previous peer observation."""
        self.w._last_network = dict(connected=True, peer_count=2, height=112, tip='34'*32)
        self.clear_event('lock')
        self.assertNotIn('peer_count', self.w._network_view(None), 'D2A-3 stale network after lock')

    def test_profile_clears_network_cache(self):
        """D2A-3: profile delivery must revoke the previous peer observation."""
        self.w._last_network = dict(connected=True, peer_count=2, height=112, tip='34'*32)
        self.clear_event('profile')
        self.assertNotIn('peer_count', self.w._network_view(None), 'D2A-3 stale network after profile switch')

    def test_profile_clears_old_error(self):
        """D2A-4: delivered open must clear the previous diagnostic code."""
        self.w._on_denied('WALLET_CORE_UNAVAILABLE')
        self.clear_event('profile')
        self.assertIsNone(self.w._last_error_code, 'D2A-4 old profile error retained')

    def test_fault_clears_session_labels(self):
        """D2A-5: fault must clear inherited advanced account/balance/tip."""
        self.w.account.setText('public-account-before-fault')
        self.clear_event('fault')
        self.assert_financial_clear()
        self.assertNotIn('public-account-before-fault', self.w.account.text(), 'D2A-5 stale account label')
        self.assertNotIn('100000', self.w.balance.text(), 'D2A-5 stale balance label')

    def test_late_snapshot_after_lock_not_repainted(self):
        """D2A-6: authenticated control can lock after Future, before Qt delivery."""
        self.assertTrue(self.w._command('snapshot'))
        self.assertTrue(self.w._worker.wait(2000))
        self.assertFalse(self.owner.busy)
        self.owner.request('control', 'stop')
        self.assertTrue(self.owner.state.locked)
        self.wait(lambda: self.w._worker is None)
        self.assert_financial_clear()
        self.assertEqual(self.w._last_error_code, 'WALLET_CORE_UNVERIFIED')

    def test_late_open_after_control_lock_cannot_expose_account(self):
        """Open must share the existing worker-generation denial boundary."""
        self.assertTrue(self.w._command('open', b'synthetic-password', 'reopen', None))
        self.assertTrue(self.w._worker.wait(2000))
        self.owner.request('control', 'stop')
        self.assertTrue(self.owner.state.locked)
        self.wait(lambda: self.w._worker is None)
        self.assert_financial_clear()
        self.assertNotIn('new-public-account', self.w.account.text())
        self.assertEqual(self.w._last_error_code, 'WALLET_CORE_UNVERIFIED')
        self.assertEqual(self.calls, ['open', 'control'])

    def test_late_old_profile_snapshot_not_repainted(self):
        """D2A-6: delivery must reject an older executor generation.

        GUI Open is serialized (tested below). A synthetic public Open through
        the real executor tests the guard's profile boundary without claiming
        a production external Open route or opening any profile.
        """
        self.assertTrue(self.w._command('snapshot'))
        self.assertTrue(self.w._worker.wait(2000))
        opened = self.owner.request('open', b'synthetic-password', 'reopen', None)
        self.w._on_ready('open', opened)
        self.wait(lambda: self.w._worker is None)
        self.assert_financial_clear()
        self.assertEqual(self.w._last_error_code, 'WALLET_CORE_UNVERIFIED')

    def test_diagnostic_and_session_label_lifetimes(self):
        for event in ('lock', 'fault', 'profile'):
            with self.subTest(event=event):
                self.owner._state = ExecutorState(locked=False, core_alive=True)
                self.w._on_ready('snapshot', result())
                self.w.account.setText('public-account-before-event')
                net = dict(connected=True, peer_count=2, height=112, tip='34'*32)
                self.w._last_network = net
                self.w._last_error_code = 'WALLET_READ_DENIED'
                self.clear_event(event)
                self.assertIsNone(self.w._last_verified)
                self.assertIsNone(self.w._last_network)
                self.assertFalse(self.w._shared_connected)
                if event == 'fault':
                    self.assertEqual(self.w._last_error_code, 'WALLET_CORE_UNAVAILABLE')
                    self.assertEqual(self.w.account.text(), t('owner.account_locked'))
                    self.assertEqual(self.w.balance.text(), t('owner.balance_unverified'))
                    self.assertEqual(self.w.tip.text(), t('owner.chain_unverified'))
                    self.assertEqual(self.w.status.text(), t('owner.faulted'))
                else:
                    self.assertEqual(self.w._last_error_code,
                                     None if event == 'profile' else 'WALLET_READ_DENIED')
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

    def test_lock_clears_hidden_balance_text_buffers(self):
        """D2A-7: hidden fund_details must contain no previous wallet amount."""
        self.clear_event('lock')
        self.assert_financial_clear()
        self.assertNotIn('0.00007000 WAM', self.w.overview.fund_details.text(),
                         'D2A-7 wallet-linked hidden label retained')

    def test_fault_clears_network_and_preserves_mapped_warning(self):
        self.w._last_network = dict(connected=True, peer_count=2, height=112, tip='34'*32)
        self.w._shared_connected = True
        self.w._on_denied('WALLET_CORE_UNAVAILABLE')
        self.assertIsNone(self.w._last_network)
        self.assertFalse(self.w._shared_connected)
        self.assertNotIn('connected', self.w._network_view(None))
        self.assertNotIn('peer_count', self.w._network_view(None))
        from wam_regtest.gui_errors import error_text
        self.assertEqual(self.w.status.text(), t('owner.refused_prefix') + error_text('WALLET_CORE_UNAVAILABLE'))
        self.assertTrue(self.w.status.isVisible())

    def test_lock_scrubs_hidden_wallet_text_and_accessibility_buffers(self):
        # Metadata on value-bearing widgets must have the same lifetime as text.
        secret = 'public-wallet-link-before-lock'
        fields = (self.w.overview.balance_value, self.w.overview.balance_unit,
                  self.w.overview.fund_details, self.w.account, self.w.balance,
                  self.w.tip, self.w.receive, self.w.history,
                  self.w.receive_page.receive_code, self.w.history_page.detail_id)
        for field in fields:
            field.setToolTip(secret)
            field.setAccessibleName(secret)
            field.setAccessibleDescription(secret)
        self.w.account.setText(secret)
        self.w.receive.setText(snapshot().receive_code)
        self.clear_event('lock')
        forbidden = (secret, snapshot().receive_code, '0.00100000', '0.00007000',
                     '100000', '34'*32, 'ab'*32)
        for widget in self.w.findChildren(QWidget):
            buffers = [widget.toolTip(), widget.accessibleName(), widget.accessibleDescription()]
            if isinstance(widget, (QLabel, QLineEdit)):
                buffers.append(widget.text())
            if hasattr(widget, 'toPlainText'):
                buffers.append(widget.toPlainText())
            for value in forbidden:
                self.assertTrue(all(value not in text for text in buffers),
                                (widget.objectName(), type(widget).__name__, value, buffers))

    def test_unlock_preserves_new_authenticated_account_after_clear(self):
        self.clear_event('lock')
        fresh = result(snapshot(signer_allowed=False, broadcast_allowed=False),
                       account_id='new-authenticated-account', checkpoint_present=True)
        self.w._on_ready('unlock', fresh)
        self.assertEqual(self.w.account.text(), t('owner.account_prefix') + 'new-authenticated-account')
        self.assertEqual(self.w.receive.text(), snapshot().receive_code)
        self.assertIsNotNone(self.w._last_verified)

    def test_profile_clears_before_new_account_is_exposed(self):
        from wam_regtest.bip39_owner_gui import Bip39TrialWindow
        original = Bip39TrialWindow._on_ready
        self.w._last_network = dict(connected=True, peer_count=2)
        self.w._last_error_code = 'WALLET_READ_DENIED'
        self.w.account.setText('previous-account')
        def inspect(window, action, data):
            self.assertEqual(action, 'open')
            self.assert_financial_clear()
            self.assertIsNone(window._last_network)
            self.assertIsNone(window._last_error_code)
            self.assertNotIn('previous-account', window.account.text())
            original(window, action, data)
        with patch.object(Bip39TrialWindow, '_on_ready', inspect):
            self.clear_event('profile')
        self.assertIn('new-public-account', self.w.account.text())
        self.assert_financial_clear()

    def test_shared_network_returns_to_unknown_after_each_invalidation(self):
        from types import SimpleNamespace
        self.w.shared_profile = SimpleNamespace(coordinator=False)
        for event in ('lock', 'profile', 'fault'):
            with self.subTest(event=event):
                self.owner._state = ExecutorState(locked=False, core_alive=True)
                self.w._last_network = dict(connected=True, peer_count=2, height=112, tip='34'*32)
                self.w._shared_connected = True
                self.clear_event(event)
                self.assertIsNone(self.w._last_network)
                self.assertFalse(self.w._shared_connected)
                self.assertEqual(self.w.overview.network_card.value.text(), t('status.awaiting_peer_check'))
                self.assertNotIn('peer_count', self.w._network_view(None))
                self.assertNotIn('connected', self.w._network_view(None))

    def test_real_worker_serializes_snapshot_before_lock_or_profile(self):
        # D2A-6: cover both backend-in-flight and backend-idle/Qt-undelivered.
        for boundary, args in (('lock', ()), ('open', (b'synthetic-password', 'reopen', None))):
            with self.subTest(boundary=boundary):
                self.calls.clear()
                self.gate.clear()
                self.assertTrue(self.w._command('snapshot'))
                self.wait(lambda: self.calls == ['snapshot'])
                self.assertFalse(self.w._command(boundary, *args))
                self.gate.set()
                worker = self.w._worker
                self.assertTrue(worker.wait(2000))  # Do not drain Qt delivery.
                self.assertFalse(self.owner.busy)
                self.assertFalse(self.w._command(boundary, *args))
                delivered = []
                original = self.w._on_ready
                def record(action, data):
                    delivered.append(action)
                    # _finished sets _worker=None before delivery; this guard matters.
                    self.assertFalse(self.w._command(boundary, *args))
                    original(action, data)
                with patch.object(self.w, '_on_ready', side_effect=record):
                    self.wait(lambda: self.w._worker is None)
                self.assertEqual(delivered, ['snapshot'])
                self.assertIsNotNone(self.w._last_verified)
                self.assertTrue(self.w._command(boundary, *args))
                self.wait(lambda: self.w._worker is None)
                self.assertEqual(self.calls, ['snapshot', boundary])
                self.assert_financial_clear()
                for _ in range(4): self.app.processEvents()
                self.assert_financial_clear()

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

    def test_busy_retained_snapshot_has_visible_last_verified_signal(self):
        """D2A-2: busy retains verified facts without visible currentness signal."""
        self.gate.clear()
        self.w.sync.click()
        self.wait(lambda: self.calls == ['snapshot'])
        self.assertIsNotNone(self.w._last_verified)
        self.assertTrue(any(x.isVisible() and 'Last verified' in x.text()
                            for x in self.w.overview.findChildren(QLabel)),
                        'D2A-2 busy snapshot lacks last-verified signal')

    def test_verified_snapshot_hides_refresh_required_signal(self):
        self.w._on_denied('WALLET_READ_DENIED')
        self.assertEqual(self.w.overview.currentness.text(), t('wallet.refresh_required'))
        self.assertTrue(self.w.overview.currentness.isVisible())
        self.w._on_ready('snapshot', result())
        self.assertTrue(self.w.overview.currentness.isHidden())
        self.assertFalse(any(x.isVisible() and x.text() == t('wallet.refresh_required')
                             for x in self.w.overview.findChildren(QLabel)))

    def test_lock_hides_refresh_required_signal_and_balance(self):
        self.w._on_denied('WALLET_READ_DENIED')
        self.assertTrue(self.w.overview.currentness.isVisible())
        self.w._on_ready('lock', None)
        self.assertTrue(self.w.overview.currentness.isHidden())
        self.assert_financial_clear()
        self.assertFalse(any(x.isVisible() and 'Last verified' in x.text()
                             for x in self.w.overview.findChildren(QLabel)))

    def test_fresh_verified_snapshot_never_shows_currentness(self):
        self.w._on_ready('snapshot', result())
        self.assertTrue(self.w.overview.currentness.isHidden())
        self.assertNotIn('—', self.w.overview.balance_value.text())
        self.assertFalse(any(x.isVisible() and 'Last verified' in x.text()
                             for x in self.w.overview.findChildren(QLabel)))
