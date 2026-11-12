"""Production Q06 BIP39 backup onboarding UI for WAM Fusion.

Implements the 12-word grid, verification and success screens using the
existing Fusion design system. No wallet authority, no plaintext persistence.
"""
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFrame, QLabel,
    QLineEdit, QPushButton, QCheckBox, QStackedWidget, QScrollArea, QProgressBar, QSizePolicy,
    QDialog, QDialogButtonBox,
)

from .bip39_locale import t
from .fusion_ui import label, panel, action, fusion_palette, ResponsiveRow


class _WordCard(QFrame):
    def __init__(self, number, word, parent=None):
        super().__init__(parent)
        self.setObjectName("FusionInset")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)
        number_label = QLabel(f"{number}")
        number_label.setObjectName("FusionMuted")
        number_label.setStyleSheet("font-size:11px;font-weight:600;")
        word_label = QLabel(word)
        word_label.setObjectName("FusionCardValue")
        word_label.setStyleSheet("font-size:17px;font-weight:600;")
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
        warning = label(t("backup_warning"), "Warning")
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
        controls.addStretch()
        self._written_check = QCheckBox(t("written_checkbox"))
        controls.addWidget(self._written_check)
        controls.addSpacing(16)
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
            edit = QLineEdit()
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
