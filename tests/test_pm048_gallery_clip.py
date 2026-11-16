"""PM-048: FE002-GALLERY-ID-CLIP regression guard.

The cocoa UI gallery reported TEXT_CLIPPED_V on scene 18-dialog-broadcast in
Indonesian (both themes, all three sizes) after FE-002 lengthened the review
text with the rate-source label. PaymentApproval pinned its height from a
pre-polish sizeHint; once the stylesheet font metrics were in effect the
dialog was a few pixels too short and the layout squeezed the wrapped review
label below its measured text. The dialog now re-fits synchronously at show
time; this test pins the review label's full visibility with the gallery's
own measurement in every locale and window size.

PM-048 round 2 (AGY PEER-163): the round-1 re-fit ran on a deferred
QTimer(0), so after a visible wide resize, hide and re-show the dialog spent
a real window at the stale height with the review label clipped, and Approve
could be clicked in that window. The fit is now synchronous inside showEvent;
the tests below assert the label is already unclipped when show() returns,
with zero event-loop timers run.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wam_regtest import bip39_locale
from wam_regtest.presentation.strings import SUPPORTED_LANGUAGES

SIZES = ((900, 630), (1100, 720), (1440, 900))
RESHOW_WIDE = (1000, 1000)
RESHOW_SIZES_ID = ((900, 630), (1100, 720), (1440, 900))
IMMEDIATE_WIDE = ((1000, 1000), (1600, 1100), (2200, 1400))


class BroadcastDialogReviewLabelFits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def _window(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.wallet_executor import ExecutorState

        executor = SimpleNamespace(state=ExecutorState(locked=False, faulted=False, core_alive=True),
                                   busy=False, closed=False)
        window = Bip39FusionWindow(executor)
        self.addCleanup(window.deleteLater)
        window._poll.stop()
        window.reduce_motion.setChecked(True)
        window.appearance_buttons[1].click()  # light theme, as in the gallery
        window.show()
        return window

    def _review_label(self, dialog, review):
        from PySide6.QtWidgets import QLabel

        from wam_regtest.fusion_pages import approval_amount_text

        expected = approval_amount_text(review)
        return next(w for w in dialog.findChildren(QLabel)
                    if w.objectName() == 'FusionMuted' and w.text() == expected)

    def _assert_review_label_fits(self, dialog, review, language, size):
        from wam_regtest.qualification.ui_gallery import _label_text_size

        label = self._review_label(dialog, review)
        rect = label.contentsRect()
        _need_w, need_h = _label_text_size(label, rect.width())
        self.assertLessEqual(need_h, rect.height() + 1,
                             f'{language} {size}: review label clipped')

    def _assert_fits_without_timers(self, dialog, review, language, context):
        """Assert the state reachable with ZERO event-loop timers: deliver only
        pending LayoutRequests (which Cocoa coalesces before the first Paint),
        then the dialog must already be at its final width with the review
        label unclipped (AGY PEER-163)."""
        from PySide6.QtCore import QCoreApplication, QEvent

        QCoreApplication.sendPostedEvents(None, QEvent.Type.LayoutRequest.value)
        self.assertEqual(640, dialog.width(),
                         f'{language} {context}: dialog not at the applied width')
        self._assert_review_label_fits(dialog, review, language, context)

    def _fresh_dialog(self, review, window):
        from PySide6.QtCore import Qt

        from wam_regtest.fusion_pages import PaymentApproval

        dialog = PaymentApproval(review, 'broadcast', window)
        dialog.setWindowModality(Qt.WindowModality.NonModal)
        return dialog

    def test_rate_source_label_fully_visible_in_six_locales_and_three_sizes(self):
        from PySide6.QtCore import Qt

        from wam_regtest.fusion_pages import PaymentApproval
        from wam_regtest.qualification.ui_gallery import _review

        window = self._window()
        for language in SUPPORTED_LANGUAGES:
            for width, height in SIZES:
                with self.subTest(language=language, size=(width, height)), \
                        patch.object(bip39_locale, '_lang', return_value=language):
                    window.resize(width, height)
                    review = _review()
                    dialog = PaymentApproval(review, 'broadcast', window)
                    dialog.setWindowModality(Qt.WindowModality.NonModal)
                    dialog.show()
                    for _ in range(3):
                        self.app.processEvents()
                    self.assertTrue(self._review_label(dialog, review).wordWrap())
                    self._assert_review_label_fits(dialog, review, language, (width, height))
                    dialog.reject()
                    dialog.deleteLater()
                    self.app.processEvents()

    def test_reshow_after_visible_wide_resize_keeps_review_label_fully_visible(self):
        """CODEX PEER-155: hide/re-show after a visible wide resize must re-fit
        at the applied 640 width using its settled layout metrics, not the
        stale wide sizeHint."""
        from PySide6.QtCore import Qt

        from wam_regtest.fusion_pages import PaymentApproval
        from wam_regtest.qualification.ui_gallery import _review

        window = self._window()
        for language in SUPPORTED_LANGUAGES:
            sizes = RESHOW_SIZES_ID if language == 'id' else (RESHOW_WIDE,)
            for wide in sizes:
                with self.subTest(language=language, wide=wide), \
                        patch.object(bip39_locale, '_lang', return_value=language):
                    review = _review()
                    dialog = PaymentApproval(review, 'broadcast', window)
                    dialog.setWindowModality(Qt.WindowModality.NonModal)
                    dialog.show()
                    for _ in range(3):
                        self.app.processEvents()
                    dialog.resize(*wide)  # visible resize to a wide size
                    for _ in range(3):
                        self.app.processEvents()
                    dialog.hide()
                    for _ in range(3):
                        self.app.processEvents()
                    dialog.show()
                    for _ in range(4):
                        self.app.processEvents()
                    self.assertEqual(640, dialog.width(),
                                     f'{language} {wide}: re-show did not re-fit width')
                    self._assert_review_label_fits(dialog, review, language, wide)
                    dialog.reject()
                    dialog.deleteLater()
                    self.app.processEvents()
    def test_indonesian_review_label_unclipped_immediately_after_show(self):
        """AGY PEER-163: at the gallery sizes the Indonesian review label must
        be unclipped when show() returns, before any event-loop timer runs."""
        from wam_regtest.qualification.ui_gallery import _review

        window = self._window()
        for size in SIZES:
            with self.subTest(language='id', size=size), \
                    patch.object(bip39_locale, '_lang', return_value='id'):
                window.resize(*size)
                for _ in range(3):
                    self.app.processEvents()
                review = _review()
                dialog = self._fresh_dialog(review, window)
                dialog.show()
                self._assert_fits_without_timers(dialog, review, 'id', size)
                dialog.reject()
                dialog.deleteLater()
                self.app.processEvents()

    def test_review_label_unclipped_immediately_after_reshow_from_wide_resize(self):
        """AGY PEER-163: after a visible wide resize, hide and re-show, the
        dialog must already be settled at the applied 640 width with the
        review label unclipped when show() returns (no timer may run)."""
        from wam_regtest.qualification.ui_gallery import _review

        window = self._window()
        with patch.object(bip39_locale, '_lang', return_value='id'):
            for wide in IMMEDIATE_WIDE:
                with self.subTest(language='id', wide=wide):
                    review = _review()
                    dialog = self._fresh_dialog(review, window)
                    dialog.show()
                    for _ in range(3):
                        self.app.processEvents()
                    dialog.resize(*wide)  # visible resize to a wide size
                    for _ in range(3):
                        self.app.processEvents()
                    dialog.hide()
                    for _ in range(3):
                        self.app.processEvents()
                    dialog.show()
                    self._assert_fits_without_timers(dialog, review, 'id', wide)
                    dialog.reject()
                    dialog.deleteLater()
                    self.app.processEvents()

    def test_review_label_unclipped_immediately_after_rapid_hide_show(self):
        """AGY PEER-163: rapid hide/show cycles with no event processing in
        between must still leave the review label unclipped when the final
        show() returns."""
        from wam_regtest.qualification.ui_gallery import _review

        window = self._window()
        with patch.object(bip39_locale, '_lang', return_value='id'):
            review = _review()
            dialog = self._fresh_dialog(review, window)
            dialog.show()
            for _ in range(3):
                self.app.processEvents()
            dialog.resize(1600, 1100)  # visible wide resize
            for _ in range(3):
                self.app.processEvents()
            for cycle in range(5):
                with self.subTest(language='id', cycle=cycle):
                    dialog.hide()
                    dialog.show()
                    self._assert_fits_without_timers(dialog, review, 'id', f'cycle {cycle}')
            dialog.reject()
            dialog.deleteLater()
            self.app.processEvents()

    def test_approve_click_immediately_after_show_cannot_be_clipped(self):
        """AGY PEER-163: Approve is clickable at the first Paint, so at the
        first possible click the review label must already be full height;
        approving a payment whose review text is clipped must be impossible."""
        from PySide6.QtTest import QTest
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QDialog

        from wam_regtest.qualification.ui_gallery import _review

        window = self._window()
        with patch.object(bip39_locale, '_lang', return_value='id'):
            review = _review()
            dialog = self._fresh_dialog(review, window)
            dialog.show()
            for _ in range(3):
                self.app.processEvents()
            dialog.resize(1600, 1100)  # visible wide resize
            for _ in range(3):
                self.app.processEvents()
            dialog.hide()
            for _ in range(3):
                self.app.processEvents()
            dialog.show()
            self._assert_fits_without_timers(dialog, review, 'id', 'first click')
            QTest.mouseClick(dialog.approve, Qt.MouseButton.LeftButton)
            self.assertEqual(QDialog.DialogCode.Accepted, dialog.result(),
                             'Approve click did not accept the dialog')
            dialog.deleteLater()
            self.app.processEvents()


if __name__ == '__main__':
    unittest.main()
