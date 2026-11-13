"""D5-A export probes. Expected failures preserve D5-E gaps, never fix them.

Offscreen Qt evidence cannot establish native accessibility or clipboard
history erasure. No wallet, Core process, retained phrase or profile is used.
"""
import sys
import unittest
from unittest.mock import Mock, patch

from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtGui import QClipboard, QKeySequence
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication, QInputDialog, QLabel, QLineEdit, QPlainTextEdit, QTextEdit, QWidget,
)

from test_q06_bip39_backup_ack import _DISPLAY_PHRASE_WORDS
from wam_regtest.bip39_backup_page import Bip39BackupPage
from wam_regtest.bip39_owner_gui import Bip39RecoveryVerifyDialog


class SecretExportContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.page = Bip39BackupPage()
        self.dialog = Bip39RecoveryVerifyDialog()
        self.page.set_phrase(_DISPLAY_PHRASE_WORDS.split())
        self.page.set_challenge({'challenge_id': 'a' * 64, 'positions': [2, 7, 12]})
        self.inputs = {
            'challenge': self.page._verify_inputs,
            'recovery': self.dialog._fields,
        }
        self.clip = self.app.clipboard()
        self.saved = self.clip.text()
        self.clip.setText('PUBLIC CLIPBOARD SENTINEL')

    def tearDown(self):
        self.clip.setText(self.saved)
        self.page.clear_phrase()
        self.dialog._clear_fields()
        for widget in (self.page, self.dialog):
            widget.hide()
            widget.deleteLater()
        self.app.processEvents()

    def _attempt_shortcuts(self, widget):
        for key in (QKeySequence.StandardKey.SelectAll, QKeySequence.StandardKey.Copy,
                    QKeySequence.StandardKey.Cut):
            QTest.keySequence(widget, QKeySequence(key))
            self.assertEqual(self.clip.text(), 'PUBLIC CLIPBOARD SENTINEL')

    def test_displayed_words_cannot_select_copy_cut_context_export_or_drag(self):
        self.page.show()
        labels = [label for label in self.page.findChildren(QLabel)
                  if label.text() in _DISPLAY_PHRASE_WORDS.split()]
        self.assertEqual(len(labels), 12)
        for label in labels:
            QTest.mouseDClick(label, Qt.MouseButton.LeftButton)
            QTest.mousePress(label, Qt.MouseButton.LeftButton, pos=QPoint(2, 2))
            QTest.mouseMove(label, QPoint(70, 2))
            QTest.mouseRelease(label, Qt.MouseButton.LeftButton, pos=QPoint(70, 2))
            self._attempt_shortcuts(label)
            self.assertFalse(label.hasSelectedText())
            self.assertEqual(label.contextMenuPolicy(), Qt.ContextMenuPolicy.NoContextMenu)
            QTest.mouseClick(label, Qt.MouseButton.RightButton)
            self.assertIsNone(self.app.activePopupWidget())
            self.assertEqual(self.clip.text(), 'PUBLIC CLIPBOARD SENTINEL')

    def test_masked_entered_words_do_not_export_by_copy_cut_or_context_menu(self):
        for kind, fields in self.inputs.items():
            for field in fields:
                with self.subTest(surface=kind):
                    field.setText('abandon')  # public BIP39 test word
                    self.assertEqual(field.echoMode(), QLineEdit.EchoMode.Password)
                    field.selectAll()
                    self._attempt_shortcuts(field)
                    field.setText('abandon')
                    field.selectAll()
                    field.copy()
                    field.cut()
                    self.assertEqual(self.clip.text(), 'PUBLIC CLIPBOARD SENTINEL')
                    menu = field.createStandardContextMenu()
                    try:
                        # Identify actions via Qt's own localized standard labels.
                        # Qt Password mode disables Copy and Cut even with selection.
                        found = []
                        for action in menu.actions():
                            text = action.text().replace('&', '').split('\t')[0].lower()
                            if text in ('copy', 'cut'):
                                found.append(text)
                                self.assertFalse(action.isEnabled())
                                action.trigger()
                        self.assertEqual(sorted(found), ['copy', 'cut'])
                        self.assertEqual(self.clip.text(), 'PUBLIC CLIPBOARD SENTINEL')
                    finally:
                        menu.deleteLater()

    def test_entered_words_have_drag_export_disabled(self):
        for kind, fields in self.inputs.items():
            for field in fields:
                with self.subTest(surface=kind):
                    field.setText('abandon')
                    field.selectAll()
                    self.assertFalse(field.dragEnabled())
                    QTest.mousePress(field, Qt.MouseButton.LeftButton, pos=QPoint(4, 4))
                    QTest.mouseMove(field, QPoint(100, 4))
                    QTest.mouseRelease(field, Qt.MouseButton.LeftButton, pos=QPoint(100, 4))
                    self.assertEqual(self.clip.text(), 'PUBLIC CLIPBOARD SENTINEL')

    def _selection_contract(self, fields):
        for field in fields:
            field.setText('abandon')
            QTest.keySequence(field, QKeySequence(QKeySequence.StandardKey.SelectAll))
            self.assertFalse(field.hasSelectedText(),
                             'D5A-03: password masking still permits Select All')

    @unittest.expectedFailure
    def test_challenge_words_cannot_be_selected(self):
        """D5A-03: default password QLineEdit permits keyboard selection."""
        self._selection_contract(self.inputs['challenge'])

    @unittest.expectedFailure
    def test_recovery_words_cannot_be_selected(self):
        """D5A-03: existing recovery password QLineEdit permits selection."""
        self._selection_contract(self.inputs['recovery'])

    def _context_selection_contract(self, fields):
        for field in fields:
            field.setText('abandon')
            menu = field.createStandardContextMenu()
            try:
                select = [a for a in menu.actions()
                          if a.text().replace('&', '').split('\t')[0].lower() == 'select all']
                self.assertEqual(len(select), 1, 'Qt standard Select All action not found')
                select[0].trigger()
                self.assertFalse(field.hasSelectedText(),
                                 'D5A-04: context Select All selects entered words')
            finally:
                menu.deleteLater()

    @unittest.expectedFailure
    def test_challenge_context_menu_cannot_select_all(self):
        """D5A-04: challenge context menu offers enabled Select All."""
        self._context_selection_contract(self.inputs['challenge'])

    @unittest.expectedFailure
    def test_recovery_context_menu_cannot_select_all(self):
        """D5A-04: recovery context menu offers enabled Select All."""
        self._context_selection_contract(self.inputs['recovery'])

    def _cut_contract(self, fields):
        for field in fields:
            field.setText('abandon')
            field.selectAll()
            QTest.keySequence(field, QKeySequence(QKeySequence.StandardKey.Cut))
            self.assertEqual(self.clip.text(), 'PUBLIC CLIPBOARD SENTINEL')
            self.assertTrue(bool(field.text()),
                            'D5A-06: keyboard Cut still deletes selected password text')

    @unittest.expectedFailure
    def test_challenge_keyboard_cut_is_blocked(self):
        """D5A-06: password Cut deletes text although it does not export it."""
        self._cut_contract(self.inputs['challenge'])

    @unittest.expectedFailure
    def test_recovery_keyboard_cut_is_blocked(self):
        """D5A-06: recovery password Cut deletes selected text."""
        self._cut_contract(self.inputs['recovery'])

    def test_primary_unchanged_after_export_attempts(self):
        if sys.platform != 'linux':
            self.skipTest('X11 PRIMARY requires Linux/X11; current host is ' + sys.platform)
        if not self.clip.supportsSelection():
            self.skipTest('Qt platform ' + self.app.platformName() + ' has no PRIMARY selection')
        mode = QClipboard.Mode.Selection
        saved = self.clip.text(mode)
        self.clip.setText('PUBLIC PRIMARY SENTINEL', mode)
        try:
            self.test_displayed_words_cannot_select_copy_cut_context_export_or_drag()
            self.assertEqual(self.clip.text(mode), 'PUBLIC PRIMARY SENTINEL')
            for field in sum(self.inputs.values(), []):
                field.setText('abandon')
                field.selectAll()
                self._attempt_shortcuts(field)
                self.assertEqual(self.clip.text(mode), 'PUBLIC PRIMARY SENTINEL')
        finally:
            self.clip.setText(saved, mode)

    def test_cleared_inputs_leave_no_words_in_metadata_or_status(self):
        for fields in self.inputs.values():
            for field, word in zip(fields, _DISPLAY_PHRASE_WORDS.split()):
                field.setText(word)
        self.page.clear_phrase()
        self.dialog._on_cancel()
        import re
        surfaces = []
        for root in (self.page, self.dialog):
            for widget in [root, *root.findChildren(QWidget)]:
                surfaces.extend((widget.toolTip(), widget.accessibleName(),
                                 widget.accessibleDescription(), widget.windowTitle(),
                                 widget.statusTip(), widget.whatsThis()))
                if isinstance(widget, QLabel):
                    surfaces.append(widget.text())
        tokens = set(re.findall('[a-z]+', ' '.join(surfaces).lower()))
        self.assertFalse(set(_DISPLAY_PHRASE_WORDS.split()) & tokens)
        self.assertTrue(all(not field.text() for fields in self.inputs.values() for field in fields))

    def _welcome_restore_probe(self):
        """Drive the real multiline prompt; stub only launch/owner boundaries."""
        from wam_regtest import bip39_owner_gui as owner
        from wam_regtest import bip39_fusion_gui as fusion
        executor = Mock(closed=True)
        window = QWidget()
        window.start = Mock()
        window.request_quit = Mock()
        observed = []
        real_prompt = QInputDialog.getMultiLineText

        def prompt(*args):
            def inspect():
                dialog = self.app.activeModalWidget()
                if isinstance(dialog, QInputDialog):
                    edit = dialog.findChild(QPlainTextEdit) or dialog.findChild(QTextEdit)
                    if edit is not None:
                        edit.setPlainText('abandon')
                        edit.selectAll()
                        selected = edit.textCursor().hasSelection()
                        edit.copy()
                        observed.append((selected, self.clip.text() != 'PUBLIC CLIPBOARD SENTINEL'))
                    dialog.reject()
            timer = QTimer()
            timer.timeout.connect(inspect)
            timer.start(10)
            watchdog = QTimer()
            watchdog.setSingleShot(True)
            watchdog.timeout.connect(lambda: self.app.activeModalWidget().reject()
                                     if self.app.activeModalWidget() else None)
            watchdog.start(2000)
            try:
                return real_prompt(*args)
            finally:
                timer.stop()
                watchdog.stop()

        try:
            with patch.object(owner, 'WalletExecutor', return_value=executor), \
                    patch.object(fusion, 'Bip39FusionWindow', return_value=window), \
                    patch.object(owner, '_onboarding_password', return_value=('public-test', True)), \
                    patch.object(owner.QInputDialog, 'getMultiLineText', side_effect=prompt):
                owner.launch_bip39_trial(None, None, None, mode='restore', authorized=True)
            return observed
        finally:
            window.hide()
            window.deleteLater()

    def test_welcome_restore_probe_reaches_real_multiline_entry(self):
        # Prevent an absent modal/editor from masquerading as the expected gap.
        self.assertEqual(self._welcome_restore_probe(), [(True, True)])

    @unittest.expectedFailure
    def test_welcome_restore_route_uses_protected_entry(self):
        """D5A-05 / spec D5-E: multiline restore allows selection and Copy."""
        self.assertEqual(self._welcome_restore_probe(), [(False, False)],
                         'D5A-05: Welcome restore permits selection and clipboard export')
