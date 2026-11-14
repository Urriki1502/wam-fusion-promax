"""Production Q06 BIP39 backup onboarding UI for WAM Fusion.

Implements the 12-word grid, verification and success screens using the
existing Fusion design system. No wallet authority, no plaintext persistence.
"""
from PySide6.QtCore import QEvent, QMimeData, QObject, Qt, Signal
from PySide6.QtGui import QFontDatabase, QKeySequence
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFrame, QLabel,
    QLineEdit, QPlainTextEdit, QPushButton, QCheckBox, QStackedWidget,
    QScrollArea, QSizePolicy, QDialog, QDialogButtonBox,
    QInputDialog,
)

from .bip39_locale import t
from .fusion_ui import (
    label, panel, action, fusion_palette, ResponsiveRow, TYPE, WEIGHT,
    grow_with_wrapped_text, SPACING, keep_focus_visible,
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
        layout.setContentsMargins(SPACING["md"], SPACING["sm"], SPACING["md"], SPACING["sm"])
        layout.setSpacing(4)
        number_label = QLabel(f"{number}")
        number_label.setObjectName("FusionMuted")
        number_label.setStyleSheet(
            "font-size:%dpx;font-weight:%d;" % (TYPE['caption'], WEIGHT['semibold']))
        word_label = QLabel(word)
        word_label.setObjectName("FusionCardValue")
        word_label.setWordWrap(False)
        word_label.setTextFormat(Qt.TextFormat.PlainText)
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
        self._normal_stack_policy = self._stack.sizePolicy()
        root.addWidget(self._stack, 1)
        self._busy = False

        self._phrase_page, pl, self._phrase_scroll, gcl, footer = self._task_page(
            t('backup_title'), t('backup_subtitle'), 1)
        self._phrase_preparing = label(t('backup.preparing'))
        self._phrase_preparing.setAccessibleName(t('backup.preparing'))
        gcl.addWidget(self._phrase_preparing)
        gcl.addWidget(label(t('phrase_grid_title'), 'FusionCardTitle'))
        self._grid_host = QWidget()
        self._grid_host.installEventFilter(self)
        self._grid = QGridLayout(self._grid_host)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(SPACING['md'])
        gcl.addWidget(self._grid_host)
        self._grid_host.hide()
        self._columns = None
        footer.addWidget(grow_with_wrapped_text(label(t('backup_warning'), 'Warning')))
        written_row = QHBoxLayout()
        self._written_check = QCheckBox()
        self._written_check.setAccessibleName(t('written_checkbox'))
        written_text = grow_with_wrapped_text(label(t('written_checkbox')))
        written_text.setBuddy(self._written_check)
        written_row.addWidget(self._written_check)
        written_row.addWidget(written_text, 1)
        footer.addLayout(written_row)
        self._back_up_now = action(t('back_up_now'), 'check', primary=True)
        self._back_up_now.setEnabled(False)
        self._back_up_now.clicked.connect(self._on_back_up_now)
        self._back_up_later = action(t('back_up_later'), 'backup')
        self._back_up_later.clicked.connect(self._on_back_up_later)
        self._phrase_buttons = self._buttons(footer, self._back_up_later, self._back_up_now)
        self._stack.addWidget(self._phrase_page)

        self._verify_page, vl, self._verify_scroll, vcl, vfooter = self._task_page(
            t('confirm_title'), t('confirm_subtitle'), 2)
        self._verify_preparing = label(t('backup.preparing'))
        self._verify_preparing.setAccessibleName(t('backup.preparing'))
        vcl.addWidget(self._verify_preparing)
        self._verify_cards = []
        for _ in range(3):
            card = QWidget()
            card.setObjectName('FusionInset')
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(*([SPACING['md']] * 4))
            card_layout.setSpacing(SPACING['sm'])
            title = label('', 'FusionCardTitle')
            edit = SecretLineEdit()
            edit.setMinimumHeight(36)
            edit.setMaxLength(16)
            edit.setPlaceholderText(t('word_label'))
            edit.returnPressed.connect(self._on_verify)
            title.setBuddy(edit)
            card_layout.addWidget(title)
            card_layout.addWidget(edit)
            self._verify_cards.append((card, title, edit))
        # Stack at narrow widths; the breakpoint is recalculated from all
        # localized position labels rather than assuming English fits.
        self._verify_cards_row = ResponsiveRow(
            *(card for card, _, _ in self._verify_cards), weights=[1, 1, 1])
        for index, (card, _, _) in enumerate(self._verify_cards):
            self._verify_cards_row.addWidget(card, index, 0)
        vcl.addWidget(self._verify_cards_row)
        self._verify_cards_row.hide()
        self._verify_error = grow_with_wrapped_text(label('', 'FusionGold'))
        self._verify_error.hide()
        vcl.addWidget(self._verify_error)
        vfooter.addWidget(grow_with_wrapped_text(label(t('backup_privacy_note'))))
        self._verify_back = action(t('backup_back'), 'backup')
        self._verify_back.clicked.connect(self._on_verify_back)
        self._verify_button = action(t('verify_backup'), 'check', primary=True)
        self._verify_button.clicked.connect(self._on_verify)
        self._verify_button.setEnabled(False)
        self._verify_buttons = self._buttons(vfooter, self._verify_back, self._verify_button)
        self._stack.addWidget(self._verify_page)
        self.setTabOrder(self._written_check, self._back_up_later)
        self.setTabOrder(self._back_up_later, self._back_up_now)
        chain = [edit for _, _, edit in self._verify_cards] + [self._verify_back, self._verify_button]
        for first, second in zip(chain, chain[1:]):
            self.setTabOrder(first, second)
        for control in [self._written_check, self._back_up_later, self._back_up_now, *chain]:
            control.installEventFilter(self)

        # --- Success page ---
        # Preserve scene 14's original scrolling/centered success surface;
        # scenes 12/13 have their own scroll areas and persistent bands.
        self._success_page = QScrollArea()
        self._success_page.setObjectName('FusionScroll')
        self._success_page.setFrameShape(QFrame.Shape.NoFrame)
        self._success_page.setWidgetResizable(True)
        success_content = QWidget()
        success_content.setObjectName('FusionInner')
        self._success_page.setWidget(success_content)
        success_content.setAutoFillBackground(False)
        self._success_page.viewport().setAutoFillBackground(False)
        sl = QVBoxLayout(success_content)
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

        self._written_check.toggled.connect(
            lambda checked: self._back_up_now.setEnabled(checked and bool(self._phrase_words) and not self._busy))

    def _task_page(self, title, subtitle, step):
        page = QWidget()
        page.setObjectName('FusionInner')
        page.installEventFilter(self)
        page.setAccessibleName(title)
        page.setAccessibleDescription(t('backup_step_progress').format(step=step, total=2)
                                      + ('. ' + t('backup.verify_step_tooltip') if step == 2 else ''))
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        content = QWidget()
        content.setMaximumWidth(760)
        content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        outer.addWidget(content, 1)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(*([SPACING['lg']] * 4))
        layout.setSpacing(SPACING['md'])
        layout.addWidget(grow_with_wrapped_text(label(title, 'PageTitle')))
        layout.addWidget(grow_with_wrapped_text(label(t('welcome.regtest_preview_no_real_funds'))))
        scroll = QScrollArea()
        scroll.setObjectName('FusionScroll')
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidgetResizable(True)
        scroll.viewport().setAutoFillBackground(False)
        scroll.viewport().installEventFilter(self)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        keep_focus_visible(scroll, t('backup.scroll_accessible'))
        body = QWidget()
        body.setAutoFillBackground(False)
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        card, card_layout = panel()
        card_layout.setContentsMargins(*([SPACING['md']] * 4))
        card_layout.addWidget(grow_with_wrapped_text(label(subtitle)))
        body_layout.addWidget(card)
        body_layout.addStretch()
        scroll.setWidget(body)
        # QScrollArea.setWidget enables auto-fill on its child; restore the
        # transparent D1 surface after installing it (including dark mode).
        body.setAutoFillBackground(False)
        scroll.viewport().setAutoFillBackground(False)
        layout.addWidget(scroll, 1)
        band = QWidget()
        footer = QVBoxLayout(band)
        footer.setContentsMargins(0, 0, 0, 0)
        footer.setSpacing(SPACING['sm'])
        layout.addWidget(band)
        return page, layout, scroll, card_layout, footer

    def _buttons(self, layout, secondary, primary):
        buttons = QDialogButtonBox()
        buttons.addButton(secondary, QDialogButtonBox.ButtonRole.RejectRole)
        buttons.addButton(primary, QDialogButtonBox.ButtonRole.AcceptRole)
        for button in (secondary, primary):
            button.setAccessibleName(button.text())
            button.setAutoDefault(False)
            button.setMinimumHeight(36)
        primary.setDefault(True)
        layout.addWidget(buttons)
        return buttons

    def eventFilter(self, watched, event):
        if event.type() == QEvent.Type.KeyPress and event.key() in (Qt.Key.Key_Tab, Qt.Key.Key_Backtab):
            # Keep the documented task order under Qt styles that otherwise
            # redirect entry into a button box to its default button.
            controls = ([self._written_check, self._back_up_later, self._back_up_now]
                        if self._stack.currentWidget() is self._phrase_page else
                        [edit for _, _, edit in self._verify_cards] + [self._verify_back, self._verify_button])
            controls = [control for control in controls if control.isVisible() and control.isEnabled()]
            if watched in controls:
                backwards = event.key() == Qt.Key.Key_Backtab or bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier)
                index = controls.index(watched) + (-1 if backwards else 1)
                if 0 <= index < len(controls):
                    controls[index].setFocus(Qt.FocusReason.BacktabFocusReason if backwards else Qt.FocusReason.TabFocusReason)
                    event.accept()
                    return True
        if event.type() == QEvent.Type.Resize:
            if watched in (getattr(self, '_phrase_page', None), getattr(self, '_verify_page', None)):
                width = self.window().width()
                inset = SPACING['xxl'] if width >= 1440 else SPACING['xl'] if width >= 1100 else SPACING['lg']
                watched.layout().itemAt(0).widget().layout().setContentsMargins(*([inset] * 4))
            scroll = getattr(self, '_phrase_scroll', None)
            if watched is getattr(self, '_grid_host', None) or (scroll is not None and watched is scroll.viewport()):
                self._reflow_words()
        return super().eventFilter(watched, event)

    def _reflow_words(self):
        cards = [self._grid.itemAt(i).widget() for i in range(self._grid.count())]
        needed = max((card.minimumSizeHint().width() for card in cards), default=140)
        available = self._phrase_scroll.viewport().width() - 2 * SPACING['md']
        columns = 3 if available >= 3 * needed + 2 * SPACING['md'] else 2
        if columns == self._columns:
            return
        self._columns = columns
        # Reinsert the existing items, not their widgets. addWidget() removes
        # and deletes the old C++ QWidgetItem behind itemAt()'s borrowed Python
        # wrapper. PySide can retain that stale wrapper and later resolve a
        # new QObject (for example the staggered overview opacity effect) at
        # the reused address to a non-QObject, crashing its metaobject lookup.
        items = [self._grid.takeAt(0) for _ in cards]
        for i, item in enumerate(items):
            self._grid.addItem(item, i // columns, i % columns)
        for column in range(3):
            self._grid.setColumnStretch(column, 1 if column < columns else 0)

    def _set_busy(self, key):
        self._busy = True
        self._verify_button.setText(t(key))
        self._verify_button.setAccessibleName(t(key))
        self._verify_button.setEnabled(False)
        self._back_up_now.setEnabled(False)
        self._verify_back.setEnabled(False)
        self._verify_cards_row.setEnabled(False)
        self._verify_preparing.setText(t(key))
        self._verify_preparing.setAccessibleName(t(key))
        self._verify_preparing.show()

    def _finish_busy(self):
        self._busy = False
        self._verify_button.setText(t('verify_backup'))
        self._verify_button.setAccessibleName(t('verify_backup'))
        self._verify_button.setEnabled(True)
        self._verify_back.setEnabled(True)
        self._verify_cards_row.setEnabled(True)
        self._back_up_now.setEnabled(bool(self._phrase_words) and self._written_check.isChecked())
        self._verify_preparing.hide()

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
        self._columns = None
        self._grid_host.show()
        self._phrase_preparing.hide()
        self._reflow_words()
        self._finish_busy()
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
        self._verify_back.hide()
        self._set_busy('backup.preparing')
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
        self._finish_busy()
        self._verify_cards_row.show()
        self._verify_back.setVisible(bool(self._phrase_words))
        self._verify_inputs[0].setFocus()

    def _build_verify_inputs(self, positions):
        # Clear old inputs.
        for edit in self._verify_inputs:
            edit.clear()
        self._verify_inputs = []
        self._challenge_positions = list(positions)
        for index, position in enumerate(self._challenge_positions):
            card, title, edit = self._verify_cards[index]
            title.setText(t('recovery_word_position').format(position=position))
            edit.setAccessibleName(title.text())
            edit.setAccessibleDescription(self._verify_error.text() if not self._verify_error.isHidden() else '')
            edit.clear()
            self._verify_inputs.append(edit)
        label_width = max(title.fontMetrics().horizontalAdvance(title.text()) for _, title, _ in self._verify_cards)
        self._verify_cards_row._break = max(620, 3 * (label_width + 2 * SPACING['md']) + 2 * SPACING['lg'])

    def _on_back_up_now(self):
        if self._busy or not self._phrase_words or not self._written_check.isChecked():
            return
        self._clear_challenge()
        self._stack.setCurrentWidget(self._verify_page)
        self._verify_cards_row.hide()
        self._set_busy('backup.preparing')
        self.challenge_requested.emit()

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
        if self._busy:
            return
        self._clear_challenge()
        self.challenge_cancelled.emit()
        if self._phrase_words:
            self._stack.setCurrentWidget(self._phrase_page)

    def _on_verify(self):
        if self._busy:
            return
        if self._challenge_id is None:
            self._set_busy('backup.preparing')
            self.challenge_requested.emit()
            return
        answers = [edit.text().strip() for edit in self._verify_inputs]
        if not all(answers):
            self._verify_error.setText(t("verify_error"))
            self._verify_error.show()
            return
        identifier = self._challenge_id
        self._clear_challenge()
        self._set_busy('backup.checking')
        self.verify_requested.emit(identifier, answers)

    def show_verification_error(self, key="verify_error"):
        # "verify_error" only for answers the backend compared and rejected;
        # "verify_unavailable" when the backend refused before judging words.
        self._finish_busy()
        self._verify_cards_row.hide()
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
        self._grid_host.hide()
        self._phrase_preparing.show()
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
