"""Actual Qt surface contracts; genuine Core proof is separate native/frozen."""
from types import SimpleNamespace
import importlib.util,os,sys,unittest
if sys.platform=='linux' and not os.environ.get('DISPLAY'):
    os.environ.setdefault('QT_QPA_PLATFORM','offscreen')

@unittest.skipUnless(importlib.util.find_spec('PySide6') is not None,'Qt controls only; native/frozen proof separate')
class UnsignedDraftControls(unittest.TestCase):
    def setUp(self):
        from PySide6.QtWidgets import QApplication
        from wam_regtest.wallet_executor import ExecutorState
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        self.app=QApplication.instance() or QApplication([])
        self.owner=SimpleNamespace(state=ExecutorState(locked=False,core_alive=True),busy=False,closed=False)
        self.window=Bip39FusionWindow(self.owner)
        self.window._ready=self.window._spend_enabled=True
        self.calls=[]
        self.window._command=lambda *args:self.calls.append(args)
    def tearDown(self):
        self.window._poll.stop();self.window.hide();self.window.deleteLater();self.app.processEvents()
    def test_unsigned_cancel_eligibility_and_irreversible_denial(self):
        from wam_regtest.wallet_executor import ExecutorState
        w=self.window
        for name,commit,signed,busy,state,expected in [
            ('empty',None,False,False,ExecutorState(locked=False,core_alive=True),False),
            ('preparing',None,False,True,ExecutorState(locked=False,core_alive=True),False),
            ('review','a'*64,False,False,ExecutorState(locked=False,core_alive=True),True),
            ('signing','a'*64,False,True,ExecutorState(locked=False,core_alive=True),False),
            ('signed','a'*64,True,False,ExecutorState(locked=False,core_alive=True),False),
            ('uncertain','a'*64,False,False,ExecutorState(locked=False,core_alive=True,faulted=True),False),
            ('locked','a'*64,False,False,ExecutorState(locked=True,core_alive=True),False),
            ('reauth','a'*64,False,False,ExecutorState(locked=False,core_alive=True,reauthentication_required=True),False),
            ('confirmed',None,False,False,ExecutorState(locked=False,core_alive=True),False)]:
            with self.subTest(state=name):
                w._approved_commitment=commit;w._signed_ready=signed;self.owner.busy=busy;self.owner.state=state
                w._set_actions();self.assertEqual(w.cancel.isEnabled(),expected)
        self.owner.busy=False;self.owner.state=ExecutorState(locked=False,core_alive=True)
        w._approved_commitment='a'*64;w._signed_ready=False;w._set_actions();w.cancel.click()
        self.assertEqual(self.calls,[('cancel',)])
    def test_real_qt_approval_rejection_cancels_without_sign_or_broadcast(self):
        from wam_regtest.wallet_session import PaymentReview
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        w=self.window
        review=PaymentReview('wamrtsp1public',123456789,10000,100000000,1,'b'*64)
        w._completed_result=('prepare',review)
        w._finished();self.app.processEvents()
        dialog=QApplication.activeModalWidget()
        self.assertIsNotNone(dialog);self.assertTrue(dialog.cancel.isDefault())
        self.assertTrue(w.cancel.isEnabled())
        dialog.cancel.click();self.app.processEvents()
        self.assertEqual(self.calls,[('cancel',)])
        self.assertFalse(w._signed_ready)
    def test_recovered_unsigned_draft_explicit_cancel_controls(self):
        from wam_regtest.wallet_executor import ExecutorState
        w=self.window;ok=ExecutorState(locked=False,core_alive=True)
        snap=lambda flag:{'recovered_unsigned_cancel_available':flag,'signer_allowed':True,
                          'payment_review':None,'payment_signed':False,'pending_confirm_txid':None,
                          'receive_code':'wamrtsp1public','confirmed_atoms':5,'available_atoms':0 if flag else 5,
                          'height':1,'tip':'c'*64,'history':(),'reservation_count':1 if flag else 0}
        # Presentation flag comes only from the backend's verified snapshot,
        # through the real production handler.
        from wam_regtest.bip39_owner_gui import Bip39TrialWindow
        Bip39TrialWindow._on_ready(w,'snapshot',snap(True));w._set_actions()
        self.assertTrue(w._recovered_unsigned_cancel)
        self.assertTrue(w.cancel.isEnabled());self.assertFalse(w.send.isEnabled())
        self.assertFalse(hasattr(w, 'fee_input'))
        w.recipient_input.setText('wamrtsp1public');w.amount_input.setText('1')
        w._prepare_send();self.assertEqual(self.calls,[])  # New payment waits.
        for name,state,busy in [('faulted',ExecutorState(locked=False,core_alive=True,faulted=True),False),
                                ('locked',ExecutorState(locked=True,core_alive=True),False),
                                ('reauth',ExecutorState(locked=False,core_alive=True,reauthentication_required=True),False),
                                ('busy',ok,True)]:
            with self.subTest(state=name):
                self.owner.state=state;self.owner.busy=busy;w._set_actions()
                self.assertFalse(w.cancel.isEnabled())
        self.owner.state=ok;self.owner.busy=False;w._set_actions()
        w._signed_ready=True;w._set_actions();self.assertFalse(w.cancel.isEnabled())
        w._signed_ready=False;w._set_actions();w.cancel.click()
        self.assertEqual(self.calls,[('cancel',)])
        Bip39TrialWindow._on_ready(w,'cancel',{'recovered_unsigned_cancelled':True,
                                              'signer_allowed':False,'broadcast_allowed':False})
        self.assertFalse(w._recovered_unsigned_cancel)
        self.assertEqual(w._pending_action,('snapshot',))  # Read only; never a write retry.
        Bip39TrialWindow._on_ready(w,'snapshot',snap(False));w._set_actions()
        self.assertFalse(w.cancel.isEnabled());self.assertTrue(w.send.isEnabled())
        # Lock/quit/open clear the cached flag; it never survives authority loss.
        for action in ('lock','open'):
            w._recovered_unsigned_cancel=True
            try:Bip39TrialWindow._on_ready(w,action,{})
            except Exception:pass
            self.assertFalse(w._recovered_unsigned_cancel)
    def test_amount_validation_dispatches_automatic_prepare_without_a_fee_field(self):
        w=self.window
        self.assertFalse(hasattr(w, 'fee_input'))
        w.recipient_input.setText('wamrtsp1public')
        for raw in ('', '0', '-1', '0.00000001', '0.00000329', 'NaN', '1e-8'):
            w.amount_input.setText(raw);w._prepare_send();self.assertEqual(self.calls,[])
        w.amount_input.setText('1.23456789');w._prepare_send()
        self.assertEqual(self.calls.pop(),('prepare_auto','wamrtsp1public',123456789))

    def test_quoted_review_and_sign_dialog_show_fee_total_and_available(self):
        from PySide6.QtWidgets import QApplication, QLabel, QWidget
        from wam_regtest.fusion_pages import approval_amount_text, fusion_review_text, owner_approval_text
        from wam_regtest.presentation.action_state import ActionInputs, available_actions
        from wam_regtest.wallet_session import PaymentReview
        import inspect
        review=PaymentReview(
            'wamrtsp1public', 25_000_000, 310, 124_989_690, 1, 'b'*64,
            rate_atoms_per_kvb=2000, rate_source='NETWORK_FLOOR_2X',
            rate_classification='UNAVAILABLE', vsize=155,
            total_debit=25_000_310, available_before=149_990_000,
            available_after=0, overpay_atoms=0, fee_quote=object())
        for text in (fusion_review_text(review), approval_amount_text(review), owner_approval_text(review)):
            self.assertIn('2× network floor', text)
            self.assertIn('0.00000310', text)
            self.assertIn('0.25000310', text)
            self.assertIn('1.49990000', text)
            self.assertIn('0.00002000', text)
            for preset in ('Fast', 'Normal', 'Slow'):
                self.assertNotIn(preset, text)
        w=self.window
        w._completed_result=('prepare_auto', review)
        w._finished();self.app.processEvents()
        dialog=QApplication.activeModalWidget()
        self.assertIsNotNone(dialog)
        shown='\n'.join(item.text() for item in dialog.findChildren(QLabel))
        recipient=dialog.findChild(QWidget, 'ReceiveCode')
        self.assertEqual(recipient.toPlainText(), review.code)
        self.assertIn(review.code, w.review_summary.text())
        self.assertIn('2× network floor', shown)
        self.assertIn('0.00000310', shown)
        self.assertIn('0.25000310', shown)
        self.assertIn('1.49990000', shown)
        dialog.cancel.click();self.app.processEvents()
        self.assertEqual(self.calls,[('cancel',)])
        self.assertNotIn('fee', inspect.getsource(available_actions))
        ready=dict(ready=True, spend_enabled=True, signed_ready=False, pending_confirm=False,
                   approved_commitment=False, recovered_unsigned_cancel=False,
                   resumable_intent=False, unlock_allowed=False, test_funded=True,
                   quit_requested=False, busy=False, executor_closed=False, faulted=False,
                   locked=False, reauthentication_required=False, core_alive=True)
        self.assertTrue(available_actions(ActionInputs(**ready))['send'])
        held=dict(ready, approved_commitment=True)
        gated=available_actions(ActionInputs(**held))
        self.assertFalse(gated['send']);self.assertTrue(gated['cancel']);self.assertFalse(gated['broadcast'])

    def test_operational_send_form_has_no_fee_field_and_prepares_automatically(self):
        from pathlib import Path
        from PySide6.QtWidgets import QLineEdit
        from wam_regtest.fusion_pages import operational_review_text
        from wam_regtest.operational_gui import OperationalWalletWindow
        from wam_regtest.wallet_session import PaymentReview
        session=type('Session', (), {
            'locked': False, 'faulted': False,
            'core_dir': Path('/tmp/wam-fee2-core'),
            'datadir': Path('/tmp/wam-fee2-data'),
            'source': Path('/tmp/wam-fee2-wsp')})()
        window=OperationalWalletWindow(session)
        self.addCleanup(window.deleteLater)
        for timer in (getattr(window, '_sync_timer', None), getattr(window, '_theme_timer', None)):
            if timer is not None:
                timer.stop()
        self.assertFalse(hasattr(window, 'fee'))
        names=' '.join(edit.accessibleName() for edit in window.findChildren(QLineEdit))
        self.assertNotIn('fee', names.lower())
        calls=[]
        window.start_operation=lambda *args: calls.append(args)
        window.recipient.setText('wamrtsp1public');window.amount.setText('1.00000000')
        window.prepare_payment()
        self.assertEqual(calls,[('prepare_auto','wamrtsp1public',100_000_000)])
        review=PaymentReview(
            'wamrtsp1public', 100_000_000, 310, 0, 1, 'c'*64,
            rate_atoms_per_kvb=2000, rate_source='NETWORK_FLOOR_2X',
            rate_classification='UNAVAILABLE', vsize=155, total_debit=100_000_310,
            available_before=100_000_310, available_after=0, overpay_atoms=0,
            fee_quote=object())
        window._operation_ready('prepare_auto', review)
        shown=window.review_text.text()
        self.assertIn('2× network floor', shown)
        self.assertIn('0.00000310', shown)
        self.assertIn('1.00000310', shown)
        self.assertEqual(shown, operational_review_text(review, signed=False))

if __name__=='__main__':unittest.main(verbosity=2)
