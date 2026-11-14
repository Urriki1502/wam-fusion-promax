"""D3-A: real Fusion decisions, ControlWorker and WalletExecutor; synthetic backend.

No Core/profile/native custody is opened. Backend calls here are dispatch evidence,
not cryptographic or durable-state proof (see the separate session probes).
"""
import threading
import time
import unittest
from unittest.mock import patch

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog
from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
from wam_regtest.fusion_pages import PaymentApproval, describe_broadcast_result
from wam_regtest.wallet_executor import WalletExecutor, immutable
from wam_regtest.wallet_session import PaymentReview

REVIEW = PaymentReview('wamrtsp1public', 50000, 1000, 49000, 1, 'a' * 64)
TXID = 'b' * 64


class SendCommands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.calls = []
        self.gate = threading.Event()
        self.gate.set()
        case = self

        class Backend:
            locked = False
            core_alive = True
            def public_state(self):
                return dict(locked=self.locked, faulted=False, core_alive=self.core_alive)
            def execute(self, action, args, kwargs):
                case.calls.append((action, args))
                if action == 'quit':
                    self.core_alive = False
                if action == 'prepare_auto':
                    case.gate.wait(3)
                    return REVIEW
                if action == 'sign':
                    return REVIEW
                if action == 'lock':
                    self.locked = True
                if action == 'broadcast':
                    return TXID
                if action == 'snapshot':
                    return case.snapshot()
                return None

        self.owner = WalletExecutor(Backend)
        self.window = Bip39FusionWindow(self.owner)
        self.window._poll.stop()
        self.window._ready = self.window._spend_enabled = True
        # Publish the synthetic healthy executor state before controls are read.
        self.owner.request('core_status')
        self.calls.clear()
        self.window.navigation.setCurrentRow(3)
        self.window._set_actions()
        self.window.show()
        self.app.processEvents()
        self.trace = patch.object(self.window, '_command', wraps=self.window._command)
        self.command = self.trace.start()

    def tearDown(self):
        self.gate.set()
        for dialog in self.window.findChildren(PaymentApproval):
            dialog.blockSignals(True)
            dialog.hide()
        self.wait_for(lambda: self.window._worker is None)
        self.trace.stop()
        self.window._poll.stop()
        if not self.owner.closed:
            self.owner.request('quit')
        self.assertTrue(self.owner.join())
        self.window.hide()
        self.window.deleteLater()
        self.app.processEvents()

    def wait_for(self, predicate):
        deadline = time.monotonic() + 4
        while not predicate() and time.monotonic() < deadline:
            self.app.processEvents()
            QTest.qWait(5)
        self.assertTrue(predicate(), 'bounded Qt delivery deadline')

    def snapshot(self, review=None, signed=False, pending=None):
        return immutable(dict(signer_allowed=True, broadcast_allowed=True,
            mainnet_allowed=False, receive_code='wamrtsp1public', confirmed_atoms=100000,
            available_atoms=0, height=1, tip='c'*64, history=(), reservation_count=1,
            payment_review=review, payment_signed=signed, pending_confirm_txid=pending))

    def actions(self):
        return [a for a, _ in self.calls]

    def dialog(self):
        visible = [d for d in self.window.findChildren(PaymentApproval) if d.isVisible()]
        self.assertEqual(len(visible), 1)
        return visible[0]

    def prepare(self):
        self.window.recipient_input.setText(REVIEW.code)
        self.window.amount_input.setText('0.00050000')
        self.window.send.click()
        self.wait_for(lambda: self.window._last_review == REVIEW)
        return self.dialog()

    def signed(self):
        self.prepare().approve.click()
        self.wait_for(lambda: self.window._signed_ready and self.window._worker is None)
        self.assertEqual(self.actions(), ['prepare_auto', 'sign'])
        self.assertFalse(self.window.cancel.isEnabled())
        return self.window

    def test_review_rapid_clicks_prepare_once_and_no_sign_before_approval(self):
        self.gate.clear()
        self.window.recipient_input.setText(REVIEW.code)
        self.window.amount_input.setText('0.00050000')
        for _ in range(4):
            self.window.send.click()
        self.wait_for(lambda: self.actions() == ['prepare_auto'])
        self.assertFalse(self.window.send.isEnabled())
        self.gate.set()
        self.wait_for(lambda: self.window._last_review == REVIEW)
        self.assertEqual(self.actions(), ['prepare_auto'])
        self.assertTrue(self.dialog().cancel.isDefault())
        self.assertFalse(self.dialog().approve.autoDefault())

    def test_empty_partial_invalid_inputs_emit_no_prepare(self):
        for code, amount in (('', ''), (REVIEW.code, ''), ('mainnet', '1'),
                             (REVIEW.code, '-1'), (REVIEW.code, 'nan'),
                             (REVIEW.code, '0.000000001')):
            with self.subTest(code=code, amount=amount):
                self.window.recipient_input.setText(code)
                self.window.amount_input.setText(amount)
                self.assertFalse(self.window.send.isEnabled())
                self.window.send.click()
                self.window._prepare_send()
                self.assertEqual(self.actions(), [])
                self.command.assert_not_called()

    def _decline_sign(self, method):
        dialog = self.prepare()
        self.assertTrue(dialog.cancel.isDefault())
        if method == 'cancel':
            dialog.cancel.click()
        elif method == 'close':
            dialog.close()
        else:
            QTest.keyClick(dialog, method)
        self.wait_for(lambda: self.window._worker is None and 'cancel' in self.actions())
        self.assertEqual(self.actions(), ['prepare_auto', 'cancel'])
        self.assertIsNone(self.window._approved_commitment)

    def test_sign_cancel_no_sign_or_submission(self):
        self._decline_sign('cancel')

    def test_sign_default_return_no_sign_or_submission(self):
        self._decline_sign(Qt.Key.Key_Return)

    def test_sign_escape_no_sign_or_submission(self):
        self._decline_sign(Qt.Key.Key_Escape)

    def test_sign_close_no_sign_or_submission(self):
        self._decline_sign('close')

    def test_broadcast_declines_keep_signed_and_never_enqueue_cancel(self):
        self.signed()
        for method in ('cancel', Qt.Key.Key_Return, Qt.Key.Key_Escape, 'close'):
            with self.subTest(method=method):
                self.window.broadcast.click()
                dialog = self.dialog()
                self.assertTrue(dialog.cancel.isDefault())
                if method == 'cancel':
                    dialog.cancel.click()
                elif method == 'close':
                    dialog.close()
                else:
                    QTest.keyClick(dialog, method)
                self.app.processEvents()
                self.assertTrue(self.window._signed_ready)
                self.assertEqual(self.window._approved_commitment, REVIEW.commitment)
                self.assertEqual(self.actions(), ['prepare_auto', 'sign'])

    def test_rapid_explicit_approvals_submit_once(self):
        self.signed()
        self.window.broadcast.click()
        dialog = self.dialog()
        dialog.approve.click()
        dialog.approve.click()
        self.wait_for(lambda: self.window._worker is None and 'broadcast' in self.actions())
        self.assertEqual(self.actions().count('broadcast'), 1)
        self.assertEqual(self.actions().count('sign'), 1)
        self.assertEqual(self.window._pending_confirm_txid, TXID)
        self.assertNotIn('resume_intent', self.actions())
        self.assertNotIn('cancel', self.actions())

    def test_rapid_sign_clicks_dispatch_one_sign_and_no_broadcast(self):
        dialog = self.prepare()
        dialog.approve.click()
        dialog.approve.click()
        self.wait_for(lambda: self.window._signed_ready and self.window._worker is None)
        self.assertEqual(self.actions(), ['prepare_auto', 'sign'])

    def test_stale_broadcast_dialog_and_signed_result_are_refused(self):
        self.signed()
        self.window.broadcast.click()
        dialog = self.dialog()
        self.window._approved_commitment = 'd' * 64
        dialog.approve.click()
        self.app.processEvents()
        self.assertNotIn('broadcast', self.actions())
        self.window._on_ready('sign', REVIEW)
        self.assertFalse(self.window._signed_ready)
        self.assertFalse(self.window.broadcast.isEnabled())

    def test_lock_then_late_approval_does_not_enqueue_sign_or_broadcast(self):
        for kind in ('sign', 'broadcast'):
            with self.subTest(kind=kind):
                self.window._ready = self.window._spend_enabled = True
                self.window._approved_commitment = None
                self.window._set_actions()
                dialog = self.prepare()
                if kind == 'broadcast':
                    dialog.approve.click()
                    self.wait_for(lambda: self.window._signed_ready and self.window._worker is None)
                    self.window._confirm_broadcast()
                    dialog = self.dialog()
                self.window._on_ready('lock', None)
                before = list(self.calls)
                self.command.reset_mock()
                dialog.approve.click()
                self.app.processEvents()
                self.assertEqual(self.calls, before)
                self.command.assert_not_called()
                self.calls.clear()

    def test_lock_invalidates_open_decision_sheet(self):
        """D3A-1: lock rejects the interactive Sign sheet (§7)."""
        dialog = self.prepare()
        self.window._on_ready('lock', None)
        self.app.processEvents()
        self.assertFalse(dialog.isVisible() and dialog.approve.isEnabled(),
                         'D3A-1: stale approval remains visibly enabled after lock')
        self.assertFalse(dialog.isVisible())
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)

    def test_late_decline_after_lock_enqueues_no_write_command(self):
        """D3A-2: stale Sign rejection cannot queue cancel after lock (§7/§8).

        This proves command enqueue, not a durable release; real backend custody
        must still refuse the locked session.
        """
        dialog = self.prepare()
        self.window._on_ready('lock', None)
        self.command.reset_mock()
        dialog.cancel.click()
        self.wait_for(lambda: self.window._worker is None)
        self.command.assert_not_called()

    def test_invalid_form_disables_review(self):
        """D3A-3: empty/invalid input disables Review (§3/§7)."""
        self.window.recipient_input.clear()
        self.window.amount_input.clear()
        self.window._set_actions()
        self.assertFalse(self.window.send.isEnabled(), 'D3A-3: invalid form still actionable')

    def test_disconnect_disables_open_broadcast_approval(self):
        """D3A-4: Shared disconnect disables modal Approve Broadcast (§2/§7)."""
        from types import SimpleNamespace
        self.signed()
        self.window.shared_profile = SimpleNamespace(coordinator=True)
        self.window._shared_connected = True
        self.window._confirm_broadcast()
        dialog = self.dialog()
        self.window._on_ready('network_status', immutable(dict(
            connected=False, peer_count=0, height=1, tip='c' * 64)))
        self.assertFalse(self.window.broadcast.isEnabled())
        self.assertFalse(dialog.approve.isEnabled(),
                         'D3A-4: disconnected modal approval still enabled')

    def test_review_reenabled_on_valid_edits_and_disabled_again_on_invalid_edit(self):
        self.assertFalse(self.window.send.isEnabled())
        self.window.recipient_input.setText(REVIEW.code)
        self.assertFalse(self.window.send.isEnabled())
        self.window.amount_input.setText('0.00050000')
        self.assertTrue(self.window.send.isEnabled())
        self.window.amount_input.setText('0')
        self.assertFalse(self.window.send.isEnabled())
        self.window.amount_input.setText('0.00050000')
        self.assertTrue(self.window.send.isEnabled())
        self.window.recipient_input.setText('mainnet')
        self.assertFalse(self.window.send.isEnabled())
        self.window.recipient_input.setText(REVIEW.code)
        self.assertTrue(self.window.send.isEnabled())
        self.command.assert_not_called()

    def test_lock_request_rejects_sheet_before_worker_result(self):
        dialog = self.prepare()
        self.wait_for(lambda: self.window._worker is None)
        self.assertTrue(self.window._command('lock'))
        self.assertFalse(dialog.isVisible())
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)
        self.wait_for(lambda: self.window._worker is None)
        self.assertEqual(self.actions(), ['prepare_auto', 'lock'])

    def test_late_accept_signal_after_lock_enqueues_zero_commands(self):
        dialog = self.prepare()
        self.window._on_ready('lock', None)
        self.command.reset_mock()
        before = list(self.calls)
        dialog.finished.emit(QDialog.DialogCode.Accepted)
        self.app.processEvents()
        self.command.assert_not_called()
        self.assertEqual(self.calls, before)

    def test_rapid_lock_during_sheet_show_rejects_without_command(self):
        original = PaymentApproval.showEvent
        observed = []
        def show_and_lock(dialog, event):
            original(dialog, event)
            self.window._on_ready('lock', None)
            observed.append(dialog)
        with patch.object(PaymentApproval, 'showEvent', show_and_lock):
            self.window._on_ready('prepare_auto', REVIEW)
        self.assertEqual(len(observed), 1)
        dialog = observed[0]
        self.assertFalse(dialog.isVisible())
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)
        dialog.finished.emit(QDialog.DialogCode.Accepted)
        dialog.finished.emit(QDialog.DialogCode.Rejected)
        self.app.processEvents()
        self.command.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_disconnect_then_reconnect_never_approves_stale_sign_or_broadcast(self):
        from types import SimpleNamespace
        for kind in ('sign', 'broadcast'):
            with self.subTest(kind=kind):
                self.window.shared_profile = SimpleNamespace(coordinator=True)
                self.window._shared_connected = True
                self.window._approved_commitment = None
                self.window._signed_ready = False
                self.window._last_review = None
                self.window._set_actions()
                dialog = self.prepare()
                if kind == 'broadcast':
                    dialog.approve.click()
                    self.wait_for(lambda: self.window._signed_ready and self.window._worker is None)
                    self.window._confirm_broadcast()
                    dialog = self.dialog()
                before = list(self.calls)
                self.command.reset_mock()
                for connected in (False, True):
                    self.window._on_ready('network_status', immutable(dict(
                        connected=connected, peer_count=int(connected), height=1, tip='c'*64)))
                self.assertFalse(dialog.isVisible())
                self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)
                dialog.finished.emit(QDialog.DialogCode.Accepted)
                dialog.finished.emit(QDialog.DialogCode.Rejected)
                self.app.processEvents()
                self.command.assert_not_called()
                self.assertEqual(self.calls, before)
                self.calls.clear()

    def test_replaced_session_commitment_rejects_sheet_without_cancel(self):
        dialog = self.prepare()
        self.window._approved_commitment = 'd' * 64
        self.window._set_actions()
        self.assertFalse(dialog.isVisible())
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)
        self.command.reset_mock()
        dialog.finished.emit(QDialog.DialogCode.Rejected)
        self.app.processEvents()
        self.command.assert_not_called()
        self.assertEqual(self.actions(), ['prepare_auto'])

    def test_session_invalidation_rejects_sheet_and_late_decline_has_no_command(self):
        dialog = self.prepare()
        self.window._spend_enabled = False
        self.window._set_actions()
        self.assertFalse(dialog.isVisible())
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)
        self.command.reset_mock()
        dialog.finished.emit(QDialog.DialogCode.Rejected)
        dialog.finished.emit(QDialog.DialogCode.Accepted)
        self.app.processEvents()
        self.command.assert_not_called()
        self.assertEqual(self.actions(), ['prepare_auto'])

    def test_disconnected_backend_refuses_payment_before_session_write(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend
        backend = object.__new__(Bip39ReadOnlyBackend)
        backend.shared_profile = SimpleNamespace(coordinator=True)
        backend._core = lambda: SimpleNamespace(directory='/disposable-not-opened')
        backend._spend_session = Mock()
        with patch('wam_regtest.shared_regtest.peer_status',
                   side_effect=ValueError('SHARED_PEER_DISCONNECTED')) as peer:
            for action, args in (('prepare_auto', (REVIEW.code, 50000)),
                                 ('sign', (REVIEW.commitment,)),
                                 ('broadcast', (REVIEW.commitment,))):
                with self.subTest(action=action):
                    with self.assertRaisesRegex(ValueError, 'SHARED_PEER_DISCONNECTED'):
                        backend.execute(action, args, {})
            self.assertEqual(peer.call_count, 3)
            backend._spend_session.assert_not_called()
            self.assertEqual(backend._spend_session.mock_calls, [])

    def test_reopen_signed_pending_and_uncertain_navigation_has_no_write(self):
        for review, signed, pending in ((REVIEW, True, None), (None, False, TXID),
                                        (None, False, None)):
            with self.subTest(signed=signed, pending=pending):
                self.window._on_ready('snapshot', self.snapshot(review, signed, pending))
                self.assertIsNone(self.window._pending_action)
                for row in (0, 2, 3):
                    self.window.navigation.setCurrentRow(row)
                self.assertEqual(self.actions(), [])
                self.command.assert_not_called()

    def test_uncertain_with_without_txid_and_verified_results_never_write(self):
        for txid, facts, fragment in (
            (None, None, 'uncertain'),
            (TXID, dict(status='Q06_TX_NOT_IN_CONFIRMED_HISTORY', in_mempool=False), 'uncertain'),
            (TXID, dict(status='Q06_TX_NOT_IN_CONFIRMED_HISTORY', in_mempool=True), 'pending'),
            (TXID, dict(status='Q06_CONFIRMED_IN_VERIFIED_HISTORY'), 'Confirmed')):
            with self.subTest(txid=txid, facts=facts):
                text = describe_broadcast_result(txid, facts)
                self.assertIn(fragment, text)
                if facts:
                    self.window._on_ready('inspect_confirmed', immutable(dict(facts, txid=txid)))
                self.assertEqual(self.actions(), [])
                self.command.assert_not_called()

    def _close_result(self, pending, facts):
        self.window._on_ready('snapshot', self.snapshot(pending=pending))
        if facts is None:
            self.window.send_result.setText(describe_broadcast_result(None))
        else:
            self.window._on_ready('inspect_confirmed', immutable(dict(facts, txid=TXID)))
        for row in (0, 2, 3):
            self.window.navigation.setCurrentRow(row)
        self.window.close()
        self.wait_for(lambda: self.window._worker is None)
        self.assertTrue(set(self.actions()) <= {'quit'})
        self.assertEqual(self.window._pending_action, None)

    def test_pending_navigation_close_no_retry_resume_or_release(self):
        self._close_result(TXID, dict(status='Q06_TX_NOT_IN_CONFIRMED_HISTORY', in_mempool=True))

    def test_uncertain_known_txid_navigation_close_no_retry_resume_or_release(self):
        self._close_result(TXID, dict(status='Q06_TX_NOT_IN_CONFIRMED_HISTORY', in_mempool=False))

    def test_uncertain_missing_txid_navigation_close_no_retry_resume_or_release(self):
        self._close_result(None, None)

    def test_signed_navigation_and_window_close_do_not_retry_or_release(self):
        self.signed()
        self.calls.clear()
        for row in (0, 2, 3):
            self.window.navigation.setCurrentRow(row)
        self.window.close()
        self.wait_for(lambda: self.window._worker is None)
        self.assertTrue(set(self.actions()) <= {'quit'})
        self.assertFalse({'prepare_auto', 'sign', 'broadcast', 'cancel', 'resume_intent', 'mine'} & set(self.actions()))
