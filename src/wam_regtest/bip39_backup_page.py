"""Production Q06 BIP39 backup onboarding UI for WAM Fusion.

Implements the 12-word grid, verification and success screens using the
existing Fusion design system. No wallet authority, no plaintext persistence.
"""
from PySide6.QtCore import QEvent, QMimeData, QObject, Qt, Signal
from PySide6.QtGui import QFontDatabase, QKeySequence
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFrame, QLabel,
    QLineEdit, QPlainTextEdit, QPushButton, QCheckBox, QStackedWidget,
    QScrollArea, QProgressBar, QSizePolicy, QDialog, QDialogButtonBox,
    QInputDialog,
)

from .bip39_locale import t
from .fusion_ui import (
    label, panel, action, fusion_palette, ResponsiveRow, TYPE, WEIGHT,
    grow_with_wrapped_text,
)


_SENSITIVE_INPUT_HINTS = (
    Qt.InputMethodHint.ImhHiddenText
    | Qt.InputMethodHint.ImhSensitiveData
    | Qt.InputMethodHint.ImhNoAutoUppercase
    | Qt.InputMethodHint.ImhNoPredictiveText
)

_BLOCKED_STANDARD_KEYS = (
    QKeySequence.StandardKey.Copy,
    QKeySequence.StandardKey.Cut,
    QKeySequence.StandardKey.SelectAll,
    QKeySequence.StandardKey.SelectNextChar,
    QKeySequence.StandardKey.SelectPreviousChar,
    QKeySequence.StandardKey.SelectNextWord,
    QKeySequence.StandardKey.SelectPreviousWord,
    QKeySequence.StandardKey.SelectNextLine,
    QKeySequence.StandardKey.SelectPreviousLine,
    QKeySequence.StandardKey.SelectStartOfLine,
    QKeySequence.StandardKey.SelectEndOfLine,
    QKeySequence.StandardKey.SelectStartOfBlock,
    QKeySequence.StandardKey.SelectEndOfBlock,
    QKeySequence.StandardKey.SelectStartOfDocument,
    QKeySequence.StandardKey.SelectEndOfDocument,
    QKeySequence.StandardKey.SelectNextPage,
    QKeySequence.StandardKey.SelectPreviousPage,
)

_NAV_KEYS = frozenset({
    Qt.Key.Key_Left,
    Qt.Key.Key_Right,
    Qt.Key.Key_Up,
    Qt.Key.Key_Down,
    Qt.Key.Key_Home,
    Qt.Key.Key_End,
    Qt.Key.Key_PageUp,
    Qt.Key.Key_PageDown,
})

_BLOCKED_MENU_OBJECT_NAMES = frozenset({'edit-cut', 'edit-copy', 'select-all'})
_BLOCKED_MENU_LABELS = frozenset({'cut', 'copy', '_'.join(('select', 'all')).replace('_', ' ')})
_BLOCKED_MENU_KEYS = (
    QKeySequence.StandardKey.Copy,
    QKeySequence.StandardKey.Cut,
    QKeySequence.StandardKey.SelectAll,
)
_BLOCKED_INPUT_METHOD_QUERIES = frozenset({
    Qt.InputMethodQuery.ImCurrentSelection,
    Qt.InputMethodQuery.ImSurroundingText,
    Qt.InputMethodQuery.ImTextBeforeCursor,
    Qt.InputMethodQuery.ImTextAfterCursor,
})



def _is_blocked_key_event(event):
    if any(event.matches(key) for key in _BLOCKED_STANDARD_KEYS):
        return True
    return bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier) and event.key() in _NAV_KEYS


def _action_is_blocked(menu_action):
    if menu_action.objectName() in _BLOCKED_MENU_OBJECT_NAMES:
        return True
    blocked_seqs = tuple(seq for key in _BLOCKED_MENU_KEYS for seq in QKeySequence.keyBindings(key))
    shortcut = menu_action.shortcut()
    if not shortcut.isEmpty() and shortcut in blocked_seqs:
        return True
    text = menu_action.text()
    if '\t' in text:
        suffix = QKeySequence(text.split('\t', 1)[1])
        if not suffix.isEmpty() and suffix in blocked_seqs:
            return True
    menu_label = text.replace('&', '').split('\t', 1)[0].strip().lower()
    return menu_label in _BLOCKED_MENU_LABELS


def filter_secret_context_menu(menu):
    """Strip Cut, Copy, Select All and redundant separators from a Qt menu."""
    if menu is None:
        return None
    for menu_action in list(menu.actions()):
        if not menu_action.isSeparator() and _action_is_blocked(menu_action):
            menu.removeAction(menu_action)
    # Remove leading, trailing, or consecutive separators left after filtering.
    prev_sep = True
    for menu_action in list(menu.actions()):
        if menu_action.isSeparator():
            if prev_sep:
                menu.removeAction(menu_action)
            prev_sep = True
        else:
            prev_sep = False
    actions = menu.actions()
    while actions and actions[-1].isSeparator():
        menu.removeAction(actions.pop())
    return menu


def _popup_filtered_menu(widget, event):
    menu = filter_secret_context_menu(widget.createStandardContextMenu())
    if menu is not None:
        menu.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        menu.popup(event.globalPos())
    event.accept()


def _clear_line_edit_selection(widget):
    if widget.hasSelectedText():
        pos = widget.cursorPosition()
        widget.deselect()
        widget.setCursorPosition(pos)


def _clear_plain_edit_selection(widget):
    cursor = widget.textCursor()
    if cursor.hasSelection():
        cursor.clearSelection()
        widget.setTextCursor(cursor)


def _place_line_edit_cursor(widget, event):
    widget.setFocus(Qt.FocusReason.MouseFocusReason)
    widget.setCursorPosition(widget.cursorPositionAt(event.position().toPoint()))
    event.accept()


def _place_plain_edit_cursor(widget, event):
    widget.setFocus(Qt.FocusReason.MouseFocusReason)
    widget.setTextCursor(widget.cursorForPosition(event.position().toPoint()))
    widget.ensureCursorVisible()
    event.accept()


class _SecretEntryFilter(QObject):
    """Event filter blocking selection/export gestures on protected inputs."""

    def __init__(self, widget, place_cursor):
        super().__init__(widget)
        self._widget = widget
        self._place_cursor = place_cursor

    def eventFilter(self, watched, event):
        if watched is not self._widget:
            return False
        kind = event.type()
        if kind in (QEvent.Type.ShortcutOverride, QEvent.Type.KeyPress):
            if _is_blocked_key_event(event):
                event.accept()
                return True
        elif kind == QEvent.Type.MouseButtonDblClick:
            event.accept()
            return True
        elif kind == QEvent.Type.MouseMove and (event.buttons() & Qt.MouseButton.LeftButton):
            event.accept()
            return True
        elif kind == QEvent.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton:
            self._place_cursor(self._widget, event)
            return True
        elif kind == QEvent.Type.ContextMenu:
            _popup_filtered_menu(self._widget, event)
            return True
        return False


def protect_secret_line_edit(line_edit):
    """Harden an existing QLineEdit (for example inside QInputDialog)."""
    line_edit.setEchoMode(QLineEdit.EchoMode.Password)
    line_edit.setDragEnabled(False)
    line_edit.setAcceptDrops(False)
    line_edit.setInputMethodHints(_SENSITIVE_INPUT_HINTS)
    line_edit.selectionChanged.connect(lambda w=line_edit: _clear_line_edit_selection(w))
    if not getattr(line_edit, '_secret_guard_installed', False):
        line_edit._secret_guard_installed = True
        line_edit.installEventFilter(_SecretEntryFilter(line_edit, _place_line_edit_cursor))
    return line_edit


class SecretLineEdit(QLineEdit):
    """Masked single-line secret entry with selection and export blocked."""

    def __init__(self, parent=None):
        super().__init__(parent)
        protect_secret_line_edit(self)

    def setDragEnabled(self, _enabled):
        super().setDragEnabled(False)

    def selectAll(self):
        return

    def setSelection(self, _start, _length):
        return

    def copy(self):
        return

    def cut(self):
        return

    def createStandardContextMenu(self):
        return filter_secret_context_menu(super().createStandardContextMenu())

    def inputMethodQuery(self, query):
        if query in _BLOCKED_INPUT_METHOD_QUERIES:
            return ''
        return super().inputMethodQuery(query)


class SecretPlainTextEdit(QPlainTextEdit):
    """Protected multiline secret entry with selection and export blocked."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(False)
        self.setInputMethodHints(_SENSITIVE_INPUT_HINTS)
        self.selectionChanged.connect(lambda: _clear_plain_edit_selection(self))
        self._secret_guard_installed = True
        self.installEventFilter(_SecretEntryFilter(self, _place_plain_edit_cursor))

    def selectAll(self):
        return

    def copy(self):
        return

    def cut(self):
        return

    def createMimeDataFromSelection(self):
        return QMimeData()

    def setTextCursor(self, cursor):
        if cursor.hasSelection():
            cursor.clearSelection()
        super().setTextCursor(cursor)

    def createStandardContextMenu(self):
        return filter_secret_context_menu(super().createStandardContextMenu())

    def inputMethodQuery(self, query):
        if query in _BLOCKED_INPUT_METHOD_QUERIES:
            return ''
        return super().inputMethodQuery(query)


class SecretMultilineDialog(QDialog):
    """Protected multiline prompt preserving QInputDialog.getMultiLineText semantics."""

    def __init__(self, title, prompt, parent=None):
        super().__init__(parent)
        self.setObjectName('FusionPanel')
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(540, 280)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)
        message = QLabel(prompt)
        message.setWordWrap(True)
        size_policy = message.sizePolicy()
        size_policy.setVerticalPolicy(QSizePolicy.Policy.Minimum)
        size_policy.setHeightForWidth(True)
        message.setSizePolicy(size_policy)
        layout.addWidget(message)
        self._editor = SecretPlainTextEdit(self)
        self._editor.setMinimumHeight(110)
        self._editor.setAccessibleName(title)
        layout.addWidget(self._editor, 1)
        buttons = QDialogButtonBox()
        cancel = buttons.addButton(t('cancel'), QDialogButtonBox.ButtonRole.RejectRole)
        approve = buttons.addButton(t('ok'), QDialogButtonBox.ButtonRole.AcceptRole)
        approve.setObjectName('FusionPrimary')
        cancel.setAutoDefault(False)
        approve.setAutoDefault(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._editor.setFocus()

    def textValue(self):
        return self._editor.toPlainText()

    def clear_secret(self):
        self._editor.clear()
        self._editor.document().clear()

    def reject(self):
        self.clear_secret()
        super().reject()

    def closeEvent(self, event):
        self.clear_secret()
        super().closeEvent(event)


def get_secret_text(parent, title, prompt):
    """Prompt for a masked secret line with protected editing."""
    dialog = QInputDialog(parent)
    dialog.setWindowTitle(title)
    dialog.setLabelText(prompt)
    dialog.setInputMode(QInputDialog.InputMode.TextInput)
    dialog.setTextEchoMode(QLineEdit.EchoMode.Password)
    for edit in dialog.findChildren(QLineEdit):
        protect_secret_line_edit(edit)
    try:
        if dialog.exec() == QDialog.DialogCode.Accepted:
            return dialog.textValue(), True
        return '', False
    finally:
        dialog.setTextValue('')
        for edit in dialog.findChildren(QLineEdit):
            edit.clear()
        dialog.deleteLater()


def get_secret_multiline_text(parent, title, prompt):
    """Prompt for multiline secret words using SecretMultilineDialog."""
    dialog = SecretMultilineDialog(title, prompt, parent)
    try:
        if dialog.exec() == QDialog.DialogCode.Accepted:
            return dialog.textValue(), True
        return '', False
    finally:
        dialog.clear_secret()
        dialog.deleteLater()


class _WordCard(QFrame):
    def __init__(self, number, word, parent=None):
        super().__init__(parent)
        self.setObjectName("FusionInset")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)
        number_label = QLabel(f"{number}")
        number_label.setObjectName("FusionMuted")
        number_label.setStyleSheet(
            "font-size:%dpx;font-weight:%d;" % (TYPE['caption'], WEIGHT['semibold']))
        word_label = QLabel(word)
        word_label.setObjectName("FusionCardValue")
        word_label.setStyleSheet(
            "font-size:%dpx;font-weight:%d;" % (TYPE['word'], WEIGHT['semibold']))
        # Recovery words are written down by hand. Never selectable/copyable:
        # X11 exports any mouse selection to PRIMARY for every client, and
        # Ctrl+C/context-menu copy would reach system clipboard history.
        word_label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        word_label.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        layout.addWidget(number_label)
        layout.addWidget(word_label)
        self.setMinimumWidth(140)


class BackupLeaveConfirm(QDialog):
    """Explicit confirmation before the only seed display is dismissed.

    Stay is the default and the Escape/close result. Presentation only: it
    never receives, shows, stores or logs recovery words.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("FusionApproval")
        self.setWindowTitle(t("leave_backup_title"))
        self.setModal(True)
        self.resize(540, 260)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        for text, role in ((t("leave_backup_title"), "PageTitle"),
                           (t("leave_backup_message"), "FusionGold")):
            wrapped = label(text, role)
            policy = wrapped.sizePolicy()
            policy.setVerticalPolicy(QSizePolicy.Policy.Minimum)
            policy.setHeightForWidth(True)
            wrapped.setSizePolicy(policy)
            layout.addWidget(wrapped)
        buttons = QDialogButtonBox()
        self.stay_button = buttons.addButton(
            t("leave_backup_stay"), QDialogButtonBox.ButtonRole.RejectRole)
        self.leave_button = buttons.addButton(
            t("leave_backup_confirm"), QDialogButtonBox.ButtonRole.AcceptRole)
        self.stay_button.setObjectName("FusionPrimary")
        self.stay_button.setDefault(True)
        self.leave_button.setObjectName("FusionDestructive")
        self.leave_button.setAutoDefault(False)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
        self.stay_button.setFocus()


class Bip39BackupPage(QWidget):
    """Full onboarding backup page: grid → verification → success."""

    verify_requested = Signal(str, list)
    challenge_requested = Signal()
    challenge_cancelled = Signal()
    deferred_requested = Signal()
    continue_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._phrase_words = []
        self._challenge_positions = []
        self._challenge_id = None
        self._verify_inputs = []
        self._verify_cards = []
        self._departure_open = False
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._stack = QStackedWidget()
        scroll = QScrollArea()
        scroll.setObjectName("FusionScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self._stack)
        scroll.viewport().setAutoFillBackground(False)
        self._stack.setAutoFillBackground(False)
        self._normal_stack_policy = self._stack.sizePolicy()
        root.addWidget(scroll, 1)

        # --- Phrase grid page ---
        self._phrase_page = QWidget()
        self._phrase_page.setObjectName("FusionInner")
        pl = QVBoxLayout(self._phrase_page)
        pl.setContentsMargins(4, 4, 12, 16)
        pl.setSpacing(18)

        pl.addWidget(label(t("backup_title"), "PageTitle"))
        pl.addWidget(label(t("backup_subtitle")))
        warning = grow_with_wrapped_text(label(t("backup_warning"), "Warning"))
        pl.addWidget(warning)

        grid_card, gcl = panel(t("phrase_grid_title"))
        self._grid = QGridLayout()
        self._grid.setSpacing(12)
        self._grid.setColumnStretch(0, 1)
        self._grid.setColumnStretch(1, 1)
        self._grid.setColumnStretch(2, 1)
        gcl.addLayout(self._grid)
        pl.addWidget(grid_card)

        controls = QHBoxLayout()
        # V0-A2: the confirmation checkbox has its own row. On one row with
        # both buttons it forced a ~717 px minimum page width, so at the
        # 900x630 minimum window the seed warning and word grid overflowed.
        written_row = QHBoxLayout()
        written_row.addStretch()
        self._written_check = QCheckBox(t("written_checkbox"))
        written_row.addWidget(self._written_check)
        pl.addLayout(written_row)
        controls.addStretch()
        self._back_up_now = action(t("back_up_now"), "check", primary=True)
        self._back_up_now.setEnabled(False)
        self._back_up_now.clicked.connect(self._on_back_up_now)
        controls.addWidget(self._back_up_now)
        self._back_up_later = action(t("back_up_later"), "backup")
        self._back_up_later.clicked.connect(self._on_back_up_later)
        controls.addWidget(self._back_up_later)
        pl.addLayout(controls)
        pl.addStretch()

        self._stack.addWidget(self._phrase_page)

        # --- Verification page (STEP 2 OF 2 backup confirmation) ---
        self._verify_page = QWidget()
        self._verify_page.setObjectName("FusionInner")
        vl = QVBoxLayout(self._verify_page)
        vl.setContentsMargins(4, 4, 12, 16)
        vl.setSpacing(18)

        vl.addWidget(label(t("backup_flow_kicker"), "FusionKicker"))
        self._step_label = label(t("backup_step_progress").format(step=2, total=2), "FusionKicker")
        vl.addWidget(self._step_label)
        self._step_progress = QProgressBar()
        self._step_progress.setRange(0, 2)
        self._step_progress.setValue(2)
        self._step_progress.setToolTip(t('backup.verify_step_tooltip'))
        self._step_progress.setTextVisible(False)
        vl.addWidget(self._step_progress)
        vl.addWidget(label(t("confirm_title"), "PageTitle"))
        vl.addWidget(label(t("confirm_subtitle")))
        vl.addWidget(label(t("backup_privacy_note"), "FusionMuted"))

        self._verify_cards = []
        for _ in range(3):
            card = QWidget()
            card.setObjectName("FusionInset")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(12, 14, 12, 14)
            card_layout.setSpacing(8)
            title = label("", "FusionCardTitle")
            edit = SecretLineEdit()
            edit.setEchoMode(QLineEdit.EchoMode.Password)
            edit.setMaxLength(16)
            edit.setPlaceholderText(t("word_label"))
            edit.returnPressed.connect(self._on_verify)
            card_layout.addWidget(title)
            card_layout.addWidget(edit)
            self._verify_cards.append((card, title, edit))
        self._verify_cards_row = ResponsiveRow(
            self._verify_cards[0][0], self._verify_cards[1][0],
            self._verify_cards[2][0], weights=[1, 1, 1])
        for index, (card, title, edit) in enumerate(self._verify_cards):
            self._verify_cards_row.addWidget(card, index, 0)
        vl.addWidget(self._verify_cards_row)

        self._verify_error = label("", "FusionGold")
        self._verify_error.hide()
        vl.addWidget(self._verify_error)

        self._verify_back = action(t("backup_back"), "backup")
        self._verify_back.clicked.connect(self._on_verify_back)
        self._verify_button = action(t("verify_backup"), "check", primary=True)
        self._verify_button.clicked.connect(self._on_verify)
        fcontrols = QHBoxLayout()
        fcontrols.addWidget(self._verify_back)
        fcontrols.addStretch()
        fcontrols.addWidget(self._verify_button)
        vl.addLayout(fcontrols)
        vl.addStretch()

        self._stack.addWidget(self._verify_page)

        # --- Success page ---
        self._success_page = QWidget()
        self._success_page.setObjectName("FusionInner")
        sl = QVBoxLayout(self._success_page)
        sl.setContentsMargins(4, 4, 12, 16)
        sl.setSpacing(18)
        sl.addStretch()
        self._success_title = label(t("success_title"), "PageTitle")
        self._success_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sl.addWidget(self._success_title)
        self._success_description = label(t("success_subtitle"))
        self._success_description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._success_description.setMinimumWidth(0)
        policy = self._success_description.sizePolicy()
        policy.setHorizontalPolicy(QSizePolicy.Policy.Expanding)
        policy.setVerticalPolicy(QSizePolicy.Policy.Minimum)
        policy.setHeightForWidth(True)
        self._success_description.setSizePolicy(policy)
        sl.addWidget(self._success_description)
        self._continue_button = action(t("continue"), "check", primary=True)
        self._continue_button.clicked.connect(self.continue_requested.emit)
        sl.addWidget(self._continue_button, alignment=Qt.AlignmentFlag.AlignCenter)
        sl.addStretch()
        self._stack.addWidget(self._success_page)
        self._stack.currentChanged.connect(self._fit_success_page)

        self._written_check.toggled.connect(self._back_up_now.setEnabled)

    def _fit_success_page(self, *_):
        # Hidden phrase/verification pages must not impose their minimum size
        # on this short centered page. Restore their original policy on return.
        policy = QSizePolicy(self._normal_stack_policy)
        if self._stack.currentWidget() is self._success_page:
            policy.setHorizontalPolicy(QSizePolicy.Policy.Ignored)
            policy.setVerticalPolicy(QSizePolicy.Policy.Ignored)
        self._stack.setSizePolicy(policy)
        self._stack.updateGeometry()

    def set_phrase(self, words):
        """Show the 12-word grid and prepare a verification challenge."""
        self._clear_grid()
        self._phrase_words = list(words)
        if len(self._phrase_words) != 12:
            raise ValueError("Q06_BACKUP_PAGE_PHRASE_LEN_DENIED")
        # 3 columns x 4 rows, numbered 1..12 left-to-right, top-to-bottom.
        for i, word in enumerate(self._phrase_words):
            card = _WordCard(i + 1, word)
            self._grid.addWidget(card, i // 3, i % 3)
        self._written_check.setChecked(False)
        self._back_up_now.setEnabled(False)
        self._clear_challenge()
        self._verify_error.hide()
        self._stack.setCurrentWidget(self._phrase_page)

    def set_deferred_mode(self):
        """Skip the grid; user must verify to resume an interrupted backup."""
        self._phrase_words = []
        self._clear_grid()
        self._clear_challenge()
        self._verify_error.hide()
        self._stack.setCurrentWidget(self._verify_page)
        self.challenge_requested.emit()

    def _clear_grid(self):
        while self._grid.count():
            item = self._grid.takeAt(0)
            card = item.widget()
            if card:
                # deleteLater() only runs on a later event-loop pass. Blank
                # the words now so no live widget keeps them in the meantime.
                for text in card.findChildren(QLabel):
                    text.clear()
                card.hide()
                card.deleteLater()

    def _clear_challenge(self):
        self._challenge_id = None
        self._challenge_positions = []
        for edit in self._verify_inputs:
            edit.clear()
        for _, _, edit in self._verify_cards:
            edit.clear()
        self._verify_inputs = []

    def set_challenge(self, challenge):
        import re
        self._clear_challenge()
        identifier = challenge.get('challenge_id')
        positions = challenge.get('positions')
        if (type(identifier) is not str or not re.fullmatch('[0-9a-f]{64}', identifier)
                or type(positions) not in (list, tuple) or len(positions) != 3
                or not all(type(p) is int and 1 <= p <= 12 for p in positions)
                or len(set(positions)) != 3):
            raise ValueError('Q06_BACKUP_PAGE_CHALLENGE_DENIED')
        self._challenge_id = identifier
        self._build_verify_inputs(positions)

    def _build_verify_inputs(self, positions):
        # Clear old inputs.
        for edit in self._verify_inputs:
            edit.clear()
        self._verify_inputs = []
        self._challenge_positions = list(positions)
        for index, position in enumerate(self._challenge_positions):
            card, title, edit = self._verify_cards[index]
            title.setText(t('recovery_word_position').format(position=position))
            edit.clear()
            self._verify_inputs.append(edit)

    def _on_back_up_now(self):
        if not self._written_check.isChecked():
            return
        self._clear_challenge()
        self.challenge_requested.emit()
        if self._challenge_id is not None:
            self._stack.setCurrentWidget(self._verify_page)

    def holds_unverified_phrase(self):
        """True while this page still holds the only display of the phrase."""
        return bool(self._phrase_words)

    def _departure_prompt(self):
        dialog = BackupLeaveConfirm(self.window())
        try:
            return dialog.exec() == QDialog.DialogCode.Accepted
        finally:
            dialog.deleteLater()

    def confirm_departure(self):
        """Ask before the unverified phrase is dismissed; Stay is the default.

        Returns True only for an explicit confirmation. A prompt that is
        already open, or one that fails, keeps the phrase on screen.
        """
        if not self._phrase_words:
            return True
        if self._departure_open:
            return False
        self._departure_open = True
        try:
            return self._departure_prompt() is True
        except Exception:
            return False
        finally:
            self._departure_open = False

    def _on_back_up_later(self):
        if not self.confirm_departure():
            return
        self.clear_phrase()
        self.deferred_requested.emit()

    def _on_verify_back(self):
        self._clear_challenge()
        self.challenge_cancelled.emit()
        if self._phrase_words:
            self._stack.setCurrentWidget(self._phrase_page)

    def _on_verify(self):
        if self._challenge_id is None:
            self.challenge_requested.emit()
            return
        answers = [edit.text().strip() for edit in self._verify_inputs]
        if not all(answers):
            self._verify_error.setText(t("verify_error"))
            self._verify_error.show()
            return
        identifier = self._challenge_id
        self._clear_challenge()
        self.verify_requested.emit(identifier, answers)

    def show_verification_error(self, key="verify_error"):
        # "verify_error" only for answers the backend compared and rejected;
        # "verify_unavailable" when the backend refused before judging words.
        self._verify_error.setText(t(key))
        self._verify_error.show()
        self._clear_challenge()

    def show_success(self):
        self.clear_phrase()
        self._verify_error.hide()
        self._stack.setCurrentWidget(self._success_page)

    def clear_phrase(self):
        self._clear_challenge()
        self._phrase_words = []
        self._clear_grid()
        self._written_check.setChecked(False)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            # Page-specific Escape. It never defers a verified backup and
            # never dismisses the phrase without the explicit confirmation.
            current = self._stack.currentWidget()
            if current is self._phrase_page:
                self._on_back_up_later()
            elif current is self._verify_page and self._phrase_words:
                self._on_verify_back()
            event.accept()
            return
        super().keyPressEvent(event)
