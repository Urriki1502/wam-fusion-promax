"""Footer and review selections must copy the exact identifier.

Wrapping may insert U+200B so a long token can break inside a QLabel.
That mark is presentation-only: mouse selection plus keyboard Copy, and the
context menu's Copy action, must put the original characters on the clipboard.
"""
import unittest
from types import SimpleNamespace

from PySide6.QtCore import QPoint, QRect, Qt, QTimer
from PySide6.QtGui import QContextMenuEvent, QKeySequence
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMenu

from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
from wam_regtest.wallet_executor import ExecutorState

TXID = "ab" * 32


class StatusCopyExact(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = Bip39FusionWindow(SimpleNamespace(
            state=ExecutorState(), busy=False, closed=False))
        self.window._poll.stop()
        self.window.resize(self.window.minimumWidth(), self.window.minimumHeight())
        self.window.show()
        self.app.processEvents()
        self.window.navigation.setCurrentRow(3)
        self.app.processEvents()
        self._prior_clipboard = self.app.clipboard().text()

    def tearDown(self):
        popup = QApplication.activePopupWidget()
        if isinstance(popup, QMenu):
            popup.close()
        for key in (Qt.Key.Key_Control, Qt.Key.Key_Meta, Qt.Key.Key_Alt, Qt.Key.Key_Shift):
            QTest.keyRelease(self.window, key)
        self.app.clipboard().setText(self._prior_clipboard)
        self.window.hide()
        self.window.deleteLater()
        self.app.processEvents()

    def _select_with_mouse(self, label):
        # A press inside an existing selection starts a drag, not a new range.
        label.setSelection(0, 0)
        end = QPoint(max(2, label.width() - 2), max(2, label.height() - 2))
        QTest.mousePress(label, Qt.MouseButton.LeftButton,
                         Qt.KeyboardModifier.NoModifier, QPoint(1, 1))
        QTest.mouseMove(label, end)
        QTest.mouseRelease(label, Qt.MouseButton.LeftButton,
                           Qt.KeyboardModifier.NoModifier, end)
        self.app.processEvents()
        self.assertTrue(label.hasSelectedText())

    def _select_token(self, label, token):
        displayed = label.text()
        plain = displayed.replace("\u200b", "")
        start = plain.index(token)
        seen = 0
        begin = end = None
        for index, character in enumerate(displayed):
            if character == "\u200b":
                continue
            if seen == start:
                begin = index
            seen += 1
            if seen == start + len(token):
                end = index + 1
                break
        self.assertIsNotNone(begin)
        label.setSelection(begin, end - begin)
        self.assertEqual(label.selectedText().replace("\u200b", ""), token)

    def _copy_with_keyboard(self, label):
        label.setFocus()
        self.app.processEvents()
        QTest.keySequence(label, QKeySequence.StandardKey.Copy)
        self.app.processEvents()
        # QTest leaves Control down after a Copy sequence the widget accepts.
        for key in (Qt.Key.Key_Control, Qt.Key.Key_Meta, Qt.Key.Key_Alt, Qt.Key.Key_Shift):
            QTest.keyRelease(label, key)
        self.app.processEvents()

    def _copy_with_context_menu(self, label):
        outcome = {}

        def step():
            try:
                menu = QApplication.activePopupWidget()
                if not isinstance(menu, QMenu):
                    outcome["tries"] = outcome.get("tries", 0) + 1
                    if outcome["tries"] > 30:
                        outcome["error"] = "context menu did not open"
                        return
                    QTimer.singleShot(0, step)
                    return
                copy = next(action for action in menu.actions()
                            if action.objectName() == "edit-copy")
                outcome["select_all"] = any(
                    action.objectName() == "select-all" and action.isEnabled()
                    for action in menu.actions())
                if not copy.isEnabled():
                    outcome["error"] = "context menu Copy is disabled"
                    menu.close()
                    return
                copy.trigger()
                menu.close()
                outcome["done"] = True
            except Exception as exc:
                outcome["error"] = repr(exc)
                menu = QApplication.activePopupWidget()
                if isinstance(menu, QMenu):
                    menu.close()

        QTimer.singleShot(0, step)
        point = QPoint(2, 2)
        QApplication.sendEvent(label, QContextMenuEvent(
            QContextMenuEvent.Reason.Mouse, point, label.mapToGlobal(point)))
        self.app.processEvents()
        self.assertTrue(outcome.get("done"), outcome.get("error", outcome))
        self.assertTrue(outcome.get("select_all"))

    def test_mouse_selection_copies_exact_txid_from_status_and_review(self):
        for label in (self.window.status, self.window.review_summary):
            self.assertIn(label.objectName(), ("FusionMuted", ""))
            label.setText(TXID)
            self.assertEqual(label.toolTip(), TXID)
            self.assertEqual(label.text().replace("\u200b", ""), TXID)
            for copy in (self._copy_with_keyboard, self._copy_with_context_menu):
                self._select_with_mouse(label)
                self.assertEqual(label.selectedText().replace("\u200b", ""), TXID)
                self.app.clipboard().setText("marker")
                copy(label)
                copied = self.app.clipboard().text()
                self.assertNotIn("\u200b", copied)
                self.assertEqual(copied, TXID)

    def test_embedded_txid_selection_copies_exact_text(self):
        message = "Broadcast submitted. Record the TXID before closing: " + TXID
        for label in (self.window.status, self.window.review_summary):
            label.setText(message)
            self.assertEqual(label.toolTip(), message)
            self.assertEqual(label.text().replace("\u200b", ""), message)
            for copy in (self._copy_with_keyboard, self._copy_with_context_menu):
                self._select_token(label, TXID)
                self.app.clipboard().setText("marker")
                copy(label)
                self.assertEqual(self.app.clipboard().text(), TXID)

    def test_minimum_width_txid_status_does_not_overflow(self):
        status = self.window.status
        status.setText(TXID)
        self.app.processEvents()
        self.assertLessEqual(self.window.width(), self.window.minimumWidth())
        self.assertTrue(status.parentWidget().rect().contains(status.geometry()))
        self.assertFalse(status.geometry().intersects(self.window.stack.geometry()))
        self.assertGreaterEqual(status.height(), status.heightForWidth(max(1, status.width())))
        contents = status.contentsRect()
        bounds = status.fontMetrics().boundingRect(
            QRect(0, 0, max(1, contents.width()), 10000),
            int(Qt.TextFlag.TextWordWrap), status.text())
        self.assertLessEqual(bounds.width(), contents.width())
        self.assertLessEqual(bounds.height(), contents.height())
