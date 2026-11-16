"""D5-A export contracts and negative/safe-editing checks on protected inputs.

Offscreen Qt evidence cannot establish native accessibility or OS clipboard
history erasure. No wallet, Core process, retained phrase or profile is used.
"""
import sys
import unittest
from unittest.mock import Mock, patch

from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtGui import QClipboard, QKeySequence
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication, QDialog, QInputDialog, QLabel, QLineEdit, QPlainTextEdit, QTextEdit, QWidget,
)

from test_q06_bip39_backup_ack import _DISPLAY_PHRASE_WORDS
from wam_regtest.bip39_backup_page import (
    Bip39BackupPage, SecretLineEdit, SecretMultilineDialog,
    SecretPlainTextEdit, protect_secret_line_edit,
)
from wam_regtest.bip39_owner_gui import Bip39RecoveryVerifyDialog


def _action_matches_standard_key(action, std_key, fallback_label):
    bindings = QKeySequence.keyBindings(std_key)
    if not action.shortcut().isEmpty() and action.shortcut() in bindings:
        return True
    text = action.text()
    if '\t' in text and QKeySequence(text.split('\t', 1)[1]) in bindings:
        return True
    object_map = {
        QKeySequence.StandardKey.Copy: 'edit-copy',
        QKeySequence.StandardKey.Cut: 'edit-cut',
        QKeySequence.StandardKey.SelectAll: 'select-all',
        QKeySequence.StandardKey.Paste: 'edit-paste',
    }
    if action.objectName() and action.objectName() == object_map.get(std_key):
        return True
    return text.replace('&', '').split('\t', 1)[0].strip().lower() == fallback_label


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
        self.assertEqual(
            self.app.keyboardModifiers(), Qt.KeyboardModifier.NoModifier,
            "Secret export test left a keyboard modifier latched")

    def _key_sequence(self, widget, sequence):
        try:
            QTest.keySequence(widget, sequence)
        finally:
            # QWidget QTest shortcuts leave Qt's cached modifiers latched even
            # after their synthetic release. Release on the live target before
            # a modal can close; keep tearDown a detector, not a state reset.
            modifiers = Qt.KeyboardModifier.NoModifier
            for index in range(sequence.count()):
                modifiers |= sequence[index].keyboardModifiers()
            for modifier, key in (
                    (Qt.KeyboardModifier.MetaModifier, Qt.Key.Key_Meta),
                    (Qt.KeyboardModifier.AltModifier, Qt.Key.Key_Alt),
                    (Qt.KeyboardModifier.ControlModifier, Qt.Key.Key_Control),
                    (Qt.KeyboardModifier.ShiftModifier, Qt.Key.Key_Shift)):
                if modifiers & modifier:
                    QTest.keyRelease(widget, key)

    def _attempt_shortcuts(self, widget):
        for key in (QKeySequence.StandardKey.SelectAll, QKeySequence.StandardKey.Copy,
                    QKeySequence.StandardKey.Cut):
            self._key_sequence(widget, QKeySequence(key))
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
                    self.assertEqual(field.text(), 'abandon')
                    menu = field.createStandardContextMenu()
                    try:
                        for action in menu.actions():
                            if (_action_matches_standard_key(action, QKeySequence.StandardKey.Copy, 'copy')
                                    or _action_matches_standard_key(action, QKeySequence.StandardKey.Cut, 'cut')):
                                self.assertFalse(action.isEnabled())
                                action.trigger()
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
                    self.assertFalse(field.acceptDrops())
                    QTest.mousePress(field, Qt.MouseButton.LeftButton, pos=QPoint(4, 4))
                    QTest.mouseMove(field, QPoint(100, 4))
                    QTest.mouseRelease(field, Qt.MouseButton.LeftButton, pos=QPoint(100, 4))
                    self.assertFalse(field.hasSelectedText())
                    self.assertEqual(self.clip.text(), 'PUBLIC CLIPBOARD SENTINEL')

    def _selection_contract(self, fields):
        for field in fields:
            field.setText('abandon')
            self._key_sequence(field, QKeySequence(QKeySequence.StandardKey.SelectAll))
            self.assertFalse(field.hasSelectedText(),
                             'D5A-03: password masking still permits Select All')
            for nav_key in (Qt.Key.Key_Left, Qt.Key.Key_Right, Qt.Key.Key_Home, Qt.Key.Key_End):
                QTest.keyClick(field, nav_key, Qt.KeyboardModifier.ShiftModifier)
                self.assertFalse(field.hasSelectedText(),
                                 'D5A-03: shift-arrow keyboard selection must be blocked')
            QTest.mouseDClick(field, Qt.MouseButton.LeftButton)
            self.assertFalse(field.hasSelectedText())

    def test_challenge_words_cannot_be_selected(self):
        """D5A-03: challenge SecretLineEdit blocks keyboard and mouse selection."""
        self._selection_contract(self.inputs['challenge'])

    def test_recovery_words_cannot_be_selected(self):
        """D5A-03: recovery SecretLineEdit blocks keyboard and mouse selection."""
        self._selection_contract(self.inputs['recovery'])

    def _context_selection_contract(self, fields):
        for field in fields:
            field.setText('abandon')
            menu = field.createStandardContextMenu()
            try:
                select = [a for a in menu.actions()
                          if _action_matches_standard_key(
                              a, QKeySequence.StandardKey.SelectAll, 'select all')]
                for action in select:
                    self.assertFalse(action.isEnabled(),
                                     'D5A-04: context menu offers enabled Select All')
                    action.trigger()
                self.assertFalse(field.hasSelectedText(),
                                 'D5A-04: context Select All selects entered words')
            finally:
                menu.deleteLater()

    def test_challenge_context_menu_cannot_select_all(self):
        """D5A-04: challenge context menu omits/disables Select All."""
        self._context_selection_contract(self.inputs['challenge'])

    def test_recovery_context_menu_cannot_select_all(self):
        """D5A-04: recovery context menu omits/disables Select All."""
        self._context_selection_contract(self.inputs['recovery'])

    def _cut_contract(self, fields):
        for field in fields:
            field.setText('abandon')
            field.selectAll()
            self._key_sequence(field, QKeySequence(QKeySequence.StandardKey.Cut))
            self.assertEqual(self.clip.text(), 'PUBLIC CLIPBOARD SENTINEL')
            self.assertEqual(field.text(), 'abandon',
                             'D5A-06: keyboard Cut must not delete or export password text')

    def test_challenge_keyboard_cut_is_blocked(self):
        """D5A-06: challenge Cut shortcut is blocked."""
        self._cut_contract(self.inputs['challenge'])

    def test_recovery_keyboard_cut_is_blocked(self):
        """D5A-06: recovery Cut shortcut is blocked."""
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
        """Drive the real protected restore modal; stub only launch/owner boundaries."""
        from wam_regtest import bip39_owner_gui as owner
        from wam_regtest import bip39_fusion_gui as fusion
        executor = Mock(closed=True)
        window = QWidget()
        window.start = Mock()
        window.request_quit = Mock()
        observed = []
        entered_texts = []

        def inspect():
            dialog = self.app.activeModalWidget()
            if isinstance(dialog, SecretMultilineDialog):
                edit = dialog.findChild(QPlainTextEdit) or dialog.findChild(QTextEdit)
                if edit is not None:
                    edit.setPlainText('abandon')
                    entered_texts.append(edit.toPlainText())
                    edit.selectAll()
                    self._key_sequence(edit, QKeySequence(QKeySequence.StandardKey.SelectAll))
                    selected = edit.textCursor().hasSelection()
                    edit.copy()
                    self._key_sequence(edit, QKeySequence(QKeySequence.StandardKey.Copy))
                    self._key_sequence(edit, QKeySequence(QKeySequence.StandardKey.Cut))
                    observed.append((selected, self.clip.text() != 'PUBLIC CLIPBOARD SENTINEL'))
                    entered_texts.append(edit.toPlainText())
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
            with patch.object(owner, 'WalletExecutor', return_value=executor), \
                    patch.object(fusion, 'Bip39FusionWindow', return_value=window), \
                    patch.object(owner, '_onboarding_password', return_value=('public-test', True)):
                owner.launch_bip39_trial(None, None, None, mode='restore', authorized=True)
            return observed, entered_texts
        finally:
            timer.stop()
            watchdog.stop()
            window.hide()
            window.deleteLater()

    def test_welcome_restore_probe_reaches_real_multiline_entry(self):
        # Prevent an absent modal/editor from masquerading as a pass.
        observed, entered_texts = self._welcome_restore_probe()
        self.assertEqual(len(observed), 1)
        self.assertEqual(entered_texts, ['abandon', 'abandon'])

    def test_welcome_restore_route_uses_protected_entry(self):
        """D5A-05: multiline restore blocks selection, Copy, and Cut."""
        observed, _ = self._welcome_restore_probe()
        self.assertEqual(observed, [(False, False)],
                         'D5A-05: Welcome restore permits selection or clipboard export')

    def test_context_menu_content_excludes_copy_cut_and_select_all_but_keeps_paste(self):
        pw_edit = SecretLineEdit()
        guarded_edit = protect_secret_line_edit(QLineEdit())
        restore_edit = SecretPlainTextEdit()
        widgets = [*self.inputs['challenge'], *self.inputs['recovery'], pw_edit, guarded_edit, restore_edit]
        try:
            for widget in widgets:
                if isinstance(widget, QPlainTextEdit):
                    widget.setPlainText('abandon')
                else:
                    widget.setText('abandon')
                menu = widget.createStandardContextMenu()
                try:
                    if isinstance(widget, QLineEdit) and type(widget) is QLineEdit:
                        from wam_regtest.bip39_backup_page import filter_secret_context_menu
                        menu = filter_secret_context_menu(menu)
                    actions = [a for a in menu.actions() if not a.isSeparator()]
                    self.assertFalse(any(
                        _action_matches_standard_key(a, QKeySequence.StandardKey.Copy, 'copy')
                        for a in actions), 'Copy action must not be offered')
                    self.assertFalse(any(
                        _action_matches_standard_key(a, QKeySequence.StandardKey.Cut, 'cut')
                        for a in actions), 'Cut action must not be offered')
                    self.assertFalse(any(
                        _action_matches_standard_key(a, QKeySequence.StandardKey.SelectAll, 'select all')
                        for a in actions), 'Select All action must not be offered')
                    self.assertTrue(any(
                        _action_matches_standard_key(a, QKeySequence.StandardKey.Paste, 'paste')
                        for a in actions), 'Paste action must remain available')
                finally:
                    menu.deleteLater()
        finally:
            for w in (pw_edit, guarded_edit, restore_edit):
                w.deleteLater()

    def test_copy_cut_drag_negatives_and_safe_editing_on_all_secret_widgets(self):
        pw_edit = SecretLineEdit()
        restore_edit = SecretPlainTextEdit()
        try:
            for widget in (self.inputs['challenge'][0], self.inputs['recovery'][0], pw_edit, restore_edit):
                widget.show()
                widget.setFocus()
                self.app.processEvents()
                # Safe typing, navigation, Backspace, Delete, and inbound Paste.
                QTest.keyClicks(widget, 'abxcd')
                QTest.keyClick(widget, Qt.Key.Key_Left)
                QTest.keyClick(widget, Qt.Key.Key_Left)
                QTest.keyClick(widget, Qt.Key.Key_Backspace)  # removes 'x' -> 'ab|cd'
                QTest.keyClick(widget, Qt.Key.Key_Left)
                QTest.keyClick(widget, Qt.Key.Key_Left)  # cursor at start -> '|abcd'
                QTest.keyClick(widget, Qt.Key.Key_Delete)  # removes 'a' -> '|bcd'
                self.clip.setText('ef')
                self._key_sequence(widget, QKeySequence(QKeySequence.StandardKey.Paste))
                text = widget.toPlainText() if isinstance(widget, QPlainTextEdit) else widget.text()
                self.assertEqual(text, 'efbcd')

                # Negative: Copy, Cut, SelectAll, Shift+Arrow, drag export all blocked.
                self.clip.setText('PUBLIC CLIPBOARD SENTINEL')
                QTest.keyClick(widget, Qt.Key.Key_Right, Qt.KeyboardModifier.ShiftModifier)
                self._key_sequence(widget, QKeySequence(QKeySequence.StandardKey.SelectAll))
                self._key_sequence(widget, QKeySequence(QKeySequence.StandardKey.Copy))
                self._key_sequence(widget, QKeySequence(QKeySequence.StandardKey.Cut))
                QTest.mousePress(widget, Qt.MouseButton.LeftButton, pos=QPoint(4, 4))
                QTest.mouseMove(widget, QPoint(80, 4))
                QTest.mouseRelease(widget, Qt.MouseButton.LeftButton, pos=QPoint(80, 4))
                self.assertEqual(self.clip.text(), 'PUBLIC CLIPBOARD SENTINEL')
                if isinstance(widget, QPlainTextEdit):
                    self.assertFalse(widget.textCursor().hasSelection())
                    self.assertEqual(widget.toPlainText(), 'efbcd')
                    self.assertFalse(widget.createMimeDataFromSelection().hasText())
                else:
                    self.assertFalse(widget.hasSelectedText())
                    self.assertEqual(widget.text(), 'efbcd')
                    self.assertFalse(widget.dragEnabled())
        finally:
            pw_edit.hide()
            pw_edit.deleteLater()
            restore_edit.hide()
            restore_edit.deleteLater()

    def test_welcome_restore_dialog_preserves_accept_and_cancel_semantics(self):
        from wam_regtest import bip39_owner_gui as owner
        from wam_regtest import bip39_fusion_gui as fusion
        for accept in (True, False):
            with self.subTest(accept=accept):
                executor = Mock(closed=True)
                window = QWidget()
                window.start = Mock()
                window.request_quit = Mock()

                def drive():
                    dialog = self.app.activeModalWidget()
                    if isinstance(dialog, SecretMultilineDialog):
                        edit = dialog.findChild(QPlainTextEdit)
                        edit.setPlainText(_DISPLAY_PHRASE_WORDS)
                        dialog.accept() if accept else dialog.reject()

                timer = QTimer()
                timer.timeout.connect(drive)
                timer.start(10)
                try:
                    with patch.object(owner, 'WalletExecutor', return_value=executor), \
                            patch.object(fusion, 'Bip39FusionWindow', return_value=window), \
                            patch.object(owner, '_onboarding_password', return_value=('public-test', True)):
                        owner.launch_bip39_trial(None, None, None, mode='restore', authorized=True)
                finally:
                    timer.stop()
                    window.hide()
                    window.deleteLater()
                if accept:
                    window.start.assert_called_once_with(b'public-test', 'restore', _DISPLAY_PHRASE_WORDS)
                    window.request_quit.assert_not_called()
                else:
                    window.start.assert_not_called()
                    window.request_quit.assert_called_once_with()

    def test_secret_text_ignores_patched_qinputdialog_gettext_and_clears_dialog(self):
        from wam_regtest.bip39_backup_page import get_secret_text
        dialogs = []

        def accept(dialog):
            dialogs.append(dialog)
            dialog.setTextValue('public-disposable-passphrase')
            return QDialog.DialogCode.Accepted

        with patch.object(QInputDialog, 'getText', return_value=('bypass', True)) as legacy, \
                patch.object(QInputDialog, 'exec', new=accept):
            self.assertEqual(get_secret_text(None, 'Title', 'Prompt'),
                             ('public-disposable-passphrase', True))
        legacy.assert_not_called()
        self.assertEqual(len(dialogs), 1)
        self.assertEqual(dialogs[0].textValue(), '')
        self.assertTrue(all(edit.text() == '' for edit in dialogs[0].findChildren(QLineEdit)))

    def test_password_prompt_uses_protected_qinputdialog_line_edit(self):
        from wam_regtest.bip39_backup_page import get_secret_text
        seen = {}

        def drive():
            dialog = self.app.activeModalWidget()
            if isinstance(dialog, QInputDialog):
                edit = dialog.findChild(QLineEdit)
                self.assertIsNotNone(edit)
                seen['echo'] = edit.echoMode()
                seen['drag'] = edit.dragEnabled()
                QTest.keyClicks(edit, 'secret-passphrase')
                self._key_sequence(edit, QKeySequence(QKeySequence.StandardKey.SelectAll))
                QTest.keyClick(edit, Qt.Key.Key_Left, Qt.KeyboardModifier.ShiftModifier)
                seen['selected'] = edit.hasSelectedText()
                self._key_sequence(edit, QKeySequence(QKeySequence.StandardKey.Copy))
                self._key_sequence(edit, QKeySequence(QKeySequence.StandardKey.Cut))
                seen['text_after_cut'] = edit.text()
                seen['clipboard_unchanged'] = self.clip.text() == 'PUBLIC CLIPBOARD SENTINEL'
                dialog.accept()

        timer = QTimer()
        timer.timeout.connect(drive)
        timer.start(10)
        try:
            value, ok = get_secret_text(None, 'Title', 'Prompt')
        finally:
            timer.stop()
        self.assertTrue(ok)
        self.assertEqual(value, 'secret-passphrase')
        self.assertEqual(seen, {
            'echo': QLineEdit.EchoMode.Password,
            'drag': False,
            'selected': False,
            'text_after_cut': 'secret-passphrase',
            'clipboard_unchanged': True,
        })
