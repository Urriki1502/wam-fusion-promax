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

    def test_sidebar_scope_badge_is_visible_and_carries_the_full_safety_sentence(self):
        "The scope badge stays visible and the exact full safety sentence is its toolTip + accessibleDescription and the navigation's accessibleDescription (pm026, V0-A1/A3)."
        from PySide6.QtWidgets import QLabel
        from wam_regtest.bip39_locale import t
        sentence = t('wallet.sidebar_notice')
        notices = [w for w in self.window.findChildren(QLabel)
                   if w.text() == sentence]
        self.assertEqual(notices, [])
        badge = self.window.scope_badge
        self.assertFalse(badge.isHidden())
        self.assertEqual(badge.toolTip(), sentence)
        self.assertEqual(badge.accessibleDescription(), sentence)
        self.assertTrue(any(w.text() == t('desktop.regtest_badge')
                            for w in self.window.findChildren(QLabel)))
        self.assertEqual(self.window.navigation.accessibleDescription(), sentence)

    def test_payment_step_labels_grow_with_their_wrapped_text(self):
        from wam_regtest.fusion_pages import PaymentSteps
        steps = self.window.findChildren(PaymentSteps)
        self.assertTrue(steps)
        for item in steps[0].labels:
            self.assertTrue(self._grows(item), item.text())

    def test_send_review_subtitle_grows_with_wrapped_text_in_every_locale(self):
        # PM-103 r5 (native Cocoa gallery finding): the Send page's safety
        # line "서명은 입력을 예약합니다…" (FusionMuted) was vertically clipped
        # because the review panel subtitle did not grow with wrapped height.
        # It must never clip in any locale.
        from PySide6.QtCore import QRect, Qt
        from wam_regtest.presentation.strings import CATALOG
        subtitle = self.window.review_subtitle
        self.assertTrue(self._grows(subtitle))
        for lang in ('en', 'vi', 'zh-Hans', 'ko', 'id', 'ja'):
            self.window.language.setCurrentIndex(self.window.language.findData(lang))
            for _ in range(6):
                self.app.processEvents()
            self.assertEqual(subtitle.text(), CATALOG[lang]['wallet.review_subtitle'], lang)
            self.window.resize(900, 630)
            self.window.show()
            for _ in range(6):
                self.app.processEvents()
            r = subtitle.contentsRect()
            needed = subtitle.fontMetrics().boundingRect(
                QRect(0, 0, max(1, r.width()), 10000),
                int(Qt.TextFlag.TextWordWrap), subtitle.text()).height()
            self.assertGreaterEqual(r.height(), needed,
                                    (lang, r.height(), needed, subtitle.text()))
        self.window.hide()
        self.window.language.setCurrentIndex(0)

    def test_dark_light_welcome_contrast_meets_wcag_aa_text(self):
        # PM-103 r5: the dark Welcome screenshot showed pale page content
        # behind a white title and an unstyled "Nâng cao" native toggle. The
        # scroll content is now themed (FusionTransparent over the themed
        # dialog background) and the Advanced toggle uses a themed QToolButton
        # (FusionQuick). Assert the welcome title and toggle text clear WCAG
        # AA (>= 4.5:1) against their surfaces in both dark and light.
        from wam_regtest.managed_onboarding import welcome_dialog
        from wam_regtest.ui_settings import ui_settings
        from wam_regtest.fusion_ui import fusion_palette
        from PySide6.QtWidgets import QToolButton, QWidget

        def luminance(h):
            rgb = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
            return sum(k * (v / 12.92 if v <= .04045 else ((v + .055) / 1.055) ** 2.4)
                       for k, v in zip((.2126, .7152, .0722), rgb))

        def ratio(a, b):
            x, y = sorted((luminance(a), luminance(b)))
            return (y + .05) / (x + .05)

        for appearance, mode in ((1, 'light'), (2, 'dark')):
            ui_settings().setValue('fusion_appearance', appearance)
            dialog = welcome_dialog()
            self.addCleanup(dialog.deleteLater)
            c = fusion_palette(mode)
            # Welcome title sits on the themed dialog background.
            self.assertGreaterEqual(ratio(c['text'], c['bg']), 4.5, mode)
            # The Advanced toggle (FusionQuick) uses surface + text tokens.
            self.assertGreaterEqual(ratio(c['text'], c['surface']), 4.5, mode)
            self.assertEqual(dialog.objectName(), 'WAMFusionWelcome')
            content = dialog.findChild(QWidget, 'FusionTransparent')
            self.assertIsNotNone(content, mode)
            self.assertEqual(content.objectName(), 'FusionTransparent')
            toggle = dialog.findChild(QToolButton, 'FusionQuick')
            self.assertIsNotNone(toggle, mode)
            self.assertFalse(toggle.text().endswith('title'))
            self.assertTrue(toggle.text())

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
