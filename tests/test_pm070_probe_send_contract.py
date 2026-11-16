"""Real offscreen Fusion controls with a synthetic owner; never Core qualification."""
import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from PySide6.QtWidgets import QApplication
from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
from wam_regtest.wallet_executor import ExecutorState
from wam_regtest import q06_spend_probe as probe


class ProbeSendContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.owner = SimpleNamespace(
            state=ExecutorState(locked=False, core_alive=True), busy=False, closed=False)
        self.window = Bip39FusionWindow(self.owner)
        self.window._poll.stop()
        self.window._ready = self.window._spend_enabled = True
        self.window._set_actions()
        self.destination = 'wamrtsp1public'

    def tearDown(self):
        self.window.hide()
        self.window.deleteLater()
        self.app.processEvents()

    def binding_step(self, atoms=123_456_789):
        probe._assert_send_form_contract(self.window, self.destination, atoms)

    def test_empty_disabled_valid_enabled_and_exact_atoms(self):
        self.assertFalse(self.window.send.isEnabled())
        self.binding_step()
        self.assertTrue(self.window.send.isEnabled())
        self.assertEqual(self.window._payment_form_values(), (self.destination, 123_456_789))
        self.assertIsNone(self.window._worker)
        self.assertIsNone(self.window._last_review)

    def test_rejects_send_enabled_on_empty_form(self):
        self.window.send.setEnabled(True)
        with self.assertRaisesRegex(ValueError, '^Q06_SEND_EMPTY_FORM_ENABLED$'):
            self.binding_step()

    def test_rejects_send_disabled_on_valid_form(self):
        # Mutate the observed button only after real textChanged validation.
        self.window.amount_input.textChanged.connect(
            lambda: self.window.send.setEnabled(False))
        with self.assertRaisesRegex(ValueError, '^Q06_SEND_VALID_FORM_DISABLED$'):
            self.binding_step()

    def test_failure_output_allows_only_fixed_probe_codes(self):
        cases = ((ValueError('Q06_SPEND_QT_BINDING_DENIED'), 'Q06_SPEND_QT_BINDING_DENIED'),
                 (ValueError('Q06_SEND_VALID_FORM_DISABLED'), 'Q06_SEND_VALID_FORM_DISABLED'),
                 (ValueError('Q06_GUI_WAIT_OPERATOR_APPROVAL'), 'Q06_GUI_WAIT_OPERATOR_APPROVAL'),
                 (ValueError('Q06_PRIVATE_SECRET'), 'Q06_SPEND_UNEXPECTED_FAILURE'),
                 (ValueError('/private/path raw reply'), 'Q06_SPEND_UNEXPECTED_FAILURE'),
                 (RuntimeError('Q06_SPEND_QT_BINDING_DENIED'), 'Q06_SPEND_UNEXPECTED_FAILURE'),
                 (ValueError('Q06_SPEND_QT_BINDING_DENIED', 'secret'), 'Q06_SPEND_UNEXPECTED_FAILURE'))
        for error, expected in cases:
            with self.subTest(expected=expected), patch.object(probe, 'qualify', side_effect=error):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(probe.run(None, None), 2)
                self.assertEqual(output.getvalue(),
                    'MACOS_Q06_NATIVE_BIP39_SEND_CONFIRM_REOPEN_DENIED code=' + expected + '\n')


if __name__ == '__main__':
    unittest.main()
