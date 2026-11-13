"""PM-048: FE002-GALLERY-ID-CLIP regression guard.

The cocoa UI gallery reported TEXT_CLIPPED_V on scene 18-dialog-broadcast in
Indonesian (both themes, all three sizes) after FE-002 lengthened the review
text with the rate-source label. PaymentApproval pinned its height from a
pre-polish sizeHint; once the stylesheet font metrics were in effect the
dialog was a few pixels too short and the layout squeezed the wrapped review
label below its measured text. The dialog now re-fits at show time; this test
pins the review label's full visibility with the gallery's own measurement in
every locale and window size.
"""
import unittest
from unittest.mock import patch

from wam_regtest import bip39_locale
from wam_regtest.presentation.strings import SUPPORTED_LANGUAGES

SIZES = ((900, 630), (1100, 720), (1440, 900))


class BroadcastDialogReviewLabelFits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def test_rate_source_label_fully_visible_in_six_locales_and_three_sizes(self):
        from types import SimpleNamespace

        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QLabel

        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.fusion_pages import PaymentApproval, approval_amount_text
        from wam_regtest.qualification.ui_gallery import _label_text_size, _review
        from wam_regtest.wallet_executor import ExecutorState

        executor = SimpleNamespace(state=ExecutorState(locked=False, faulted=False, core_alive=True),
                                   busy=False, closed=False)
        window = Bip39FusionWindow(executor)
        self.addCleanup(window.deleteLater)
        window._poll.stop()
        window.reduce_motion.setChecked(True)
        window.appearance_buttons[1].click()  # light theme, as in the gallery
        window.show()
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
                    expected = approval_amount_text(review)
                    label = next(w for w in dialog.findChildren(QLabel)
                                 if w.objectName() == 'FusionMuted' and w.text() == expected)
                    self.assertTrue(label.wordWrap())
                    rect = label.contentsRect()
                    _need_w, need_h = _label_text_size(label, rect.width())
                    self.assertLessEqual(need_h, rect.height() + 1,
                                         f'{language} {width}x{height}: review label clipped')
                    dialog.reject()
                    dialog.deleteLater()
                    self.app.processEvents()


if __name__ == '__main__':
    unittest.main()
