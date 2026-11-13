"""PM-026: V0 P1/P2 layout fixes for safety text (V0-A1, V0-A2/A3, V0-A4).

Structural guards. The rendered proof is the native source ui_gallery run
(evidence/PM-026-v0-safety-text, frozen=false) and the frozen ui_gallery run
on FC-11 (evidence/PM-026-v0-safety-text/frozen-gallery-53fa69e), because
offscreen fonts lack CJK metrics.
"""
import os
import tempfile
import unittest
from types import SimpleNamespace


class SafetyTextLayout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def setUp(self):
        from unittest.mock import patch
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.wallet_executor import ExecutorState
        env = patch.dict(os.environ, {'WAM_UI_SETTINGS_PATH':
                                      os.path.join(tempfile.mkdtemp(), 'ui.ini')})
        env.start()
        self.addCleanup(env.stop)
        self.window = Bip39FusionWindow(SimpleNamespace(state=ExecutorState(), busy=False, closed=False))
        self.window._poll.stop()
        self.addCleanup(self.window.deleteLater)

    @staticmethod
    def _grows(widget):
        from PySide6.QtWidgets import QSizePolicy
        policy = widget.sizePolicy()
        return (policy.verticalPolicy() == QSizePolicy.Policy.Minimum
                and policy.hasHeightForWidth() and widget.wordWrap())

    def test_sidebar_safety_notice_grows_with_its_wrapped_text(self):
        from PySide6.QtWidgets import QLabel
        from wam_regtest.bip39_locale import t
        notices = [w for w in self.window.findChildren(QLabel) if w.text() == t('wallet.sidebar_notice')]
        self.assertEqual(len(notices), 1)
        self.assertTrue(self._grows(notices[0]))

    def test_payment_step_labels_grow_with_their_wrapped_text(self):
        from wam_regtest.fusion_pages import PaymentSteps
        steps = self.window.findChildren(PaymentSteps)
        self.assertTrue(steps)
        for item in steps[0].labels:
            self.assertTrue(self._grows(item), item.text())

    def test_backup_checkbox_is_not_on_the_button_row(self):
        page = self.window.backup_page
        check, now, later = page._written_check, page._back_up_now, page._back_up_later
        from PySide6.QtCore import QPoint
        from PySide6.QtWidgets import QDialogButtonBox
        self.assertIs(now.parentWidget(), later.parentWidget())
        self.assertIsInstance(now.parentWidget(), QDialogButtonBox)
        self.assertIsNot(check.parentWidget(), now.parentWidget())
        page.set_phrase(('abandon',) * 11 + ('about',))
        self.window.resize(900, 630)
        self.window.stack.setCurrentWidget(page)
        self.window.show()
        for _ in range(6):
            self.app.processEvents()
        self.assertLess(check.mapTo(page, QPoint(0, check.height())).y(),
                        now.mapTo(page, QPoint(0, 0)).y())
        for button in (now, later):
            self.assertLessEqual(button.mapTo(page, QPoint(button.width(), button.height())).x(), page.width())
            self.assertLessEqual(button.mapTo(page, QPoint(0, button.height())).y(), page.height())
        self.window.hide()


def _layouts(layout):
    yield layout
    for index in range(layout.count()):
        child = layout.itemAt(index).layout()
        if child is not None:
            yield from _layouts(child)


if __name__ == '__main__':
    unittest.main()
