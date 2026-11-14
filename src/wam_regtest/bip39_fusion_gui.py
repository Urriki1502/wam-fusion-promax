"""Q06 presentation inside the EXISTING Fusion visual system.

No new wallet manager or signing authority: this is a Qt skin for the
unchanged Bip39TrialWindow/WalletExecutor and its fail-closed native custody.
The reusable Q05 Fusion Overview/Receive/History/PaymentSteps are real widgets,
not a painted mockup or a separate demo account.
"""
import os
import re
from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import QFontDatabase, QIcon, QKeySequence, QPixmap
from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QFrame, QLabel, QLineEdit,
    QListWidget, QMenu, QMessageBox, QDialog, QToolButton,
    QCheckBox, QComboBox, QApplication, QSizePolicy,
)

from .bip39_owner_gui import Bip39TrialWindow
from .presentation.action_state import SharedInputs, apply_shared_profile, available_actions, fusion_actions
from .domain.payment_state import reserved_rows_needing_attention

from .bip39_locale import effective_choice, t
from .desktop import resolve_theme
from .gui_errors import operation_error
from .fusion_ui import (
    FusionOverview, fusion_stylesheet, fusion_palette, page, panel,
    label, ResponsiveRow, vector_icon, nav_icon_for, FUSION_NAV_PAGES, fusion_nav_pages,
    StateSwitch, action, ThemeSlider, grow_with_wrapped_text,
    SHELL, present_brand_title, install_keyboard_focus_mark,
)
from .fusion_motion import fade_widget, PressFeedback, TransitionHost, STAGGER_MS, STANDARD_MS, motion_reduced
from .fusion_status import classify
from .fusion_pages import ReceivePage, HistoryPage, PaymentSteps, PaymentApproval, WalletConsent, NetworkPage, describe_broadcast_result, fusion_review_text
from .bip39_backup_page import Bip39BackupPage
from .wallet_read import WalletReadSnapshot
from .amounts import parse_amount
from .branding import brand_image
from .infrastructure import core_compat
from .ui_settings import ui_settings


def displayed_reserved_inputs(result):
    """Reserved-input count for the overview (W-TX-03b).

    With verified per-state counts, a confirmed payment's leftover 'broadcast'
    rows are not shown as coins that "stay unavailable". Without them (older
    result shapes) the previous raw count is shown unchanged.
    """
    counts = result.get("reservation_state_counts")
    if counts is None:
        return result.get("reservation_count")
    return reserved_rows_needing_attention(counts)



class _WrappingStatusLabel(QLabel):
    """Status text that wraps long tokens and copies the exact characters.

    QLabel word wrap does not break an unbroken identifier, and QLabel has no
    wrap-anywhere option. A read-only editor would stop matching QLabel#FusionMuted.
    U+200B is only a line-break opportunity. Copy publishes the selection
    without it; the tooltip keeps the exact message.
    """

    def __init__(self, text=""):
        super().__init__(text)
        # Drag selection and the Copy menu exist only with this flag. These
        # two labels are constructed directly, not via label(..., selectable=True).
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

    def setText(self, text):
        self.setToolTip(text)
        super().setText(re.sub(r"\S{33,}", lambda match: "\u200b".join(
            match[0][i:i + 24] for i in range(0, len(match[0]), 24)), text))

    def _copy_selection(self, *_args):
        if not self.hasSelectedText():
            return
        QApplication.clipboard().setText(self.selectedText().replace("\u200b", ""))

    def _select_all(self, *_args):
        self.setSelection(0, len(self.text()))

    def keyPressEvent(self, event):
        if event.matches(QKeySequence.StandardKey.Copy):
            self._copy_selection()
            event.accept()
            return
        super().keyPressEvent(event)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        copy = menu.addAction(t("common.copy"))
        copy.setShortcut(QKeySequence(QKeySequence.StandardKey.Copy))
        copy.setEnabled(self.hasSelectedText())
        copy.triggered.connect(self._copy_selection)
        select_all = menu.addAction(t("common.select_all"))
        select_all.setShortcut(QKeySequence(QKeySequence.StandardKey.SelectAll))
        select_all.setEnabled(bool(self.text()))
        select_all.triggered.connect(self._select_all)
        menu.popup(event.globalPos())
        event.accept()


class _AdvancedControlsToggle(QToolButton):
    def minimumSizeHint(self):
        # Keep the native styled text + padding, including font/DPI changes.
        return self.sizeHint()

    def _sync_minimum(self):
        self.setMinimumSize(self.sizeHint())
        self.updateGeometry()

    def setText(self, text):
        super().setText(text)
        self._sync_minimum()

    def showEvent(self, event):
        super().showEvent(event)
        self._sync_minimum()

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() in (event.Type.FontChange, event.Type.StyleChange):
            self._sync_minimum()


class Bip39FusionWindow(Bip39TrialWindow):
    """The normal BIP39 UI uses the same Fusion navigation, theme and pages.

    The legacy Q06 controls remain bound to the SAME executor. The old
    developer-only layout is parked, its already connected controls are moved
    into the correct Fusion pages. No second Qt worker or owner is started.
    """

    def __init__(self, executor, *, shared_profile=None):
        self.shared_profile = shared_profile
        self._shared_connected = False
        super().__init__(executor)
        legacy = QWidget(self)
        legacy.setLayout(self.layout())
        self._legacy_layout_holder = legacy
        legacy.hide()
        self.setObjectName("WalletRoot")
        self.setWindowTitle(t('wallet.window_title') + (" (V1-NET)" if shared_profile else ""))
        self.setWindowIcon(QIcon(str(brand_image())))
        self.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont))
        self.resize(1260, 810)
        self.setMinimumSize(900, 630)
        shell = QHBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        # Native macOS-style workspace, not a second wallet manager.
        sidebar = QFrame()
        sidebar.setObjectName("FusionSidebar")
        sidebar.setFixedWidth(SHELL['sidebar_width'])
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(
            SHELL['sidebar_pad_x'], SHELL['sidebar_pad_top'],
            SHELL['sidebar_pad_x'], SHELL['sidebar_pad_bottom'])
        side.setSpacing(SHELL['sidebar_gap'])
        brand = QVBoxLayout()
        brand.setSpacing(SHELL['brand_gap'])
        logo = QLabel()
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark = QPixmap(str(brand_image())).scaled(
            SHELL['logo'], SHELL['logo'], Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation)
        logo.setPixmap(mark)
        logo.setFixedHeight(SHELL['logo_box'])
        brand.addWidget(logo)
        self._brand_title = label(t('wallet.brand'), "BrandTitle")
        brand.addWidget(self._brand_title)
        side.addLayout(brand)
        side.addWidget(label(t('wallet.shared_badge') if shared_profile else "REGTEST", "FusionBadge"),
                       0, Qt.AlignmentFlag.AlignHCenter)
        self.navigation = QListWidget()
        self.navigation.setIconSize(QSize(SHELL['nav_icon'], SHELL['nav_icon']))
        self.navigation.setSpacing(SHELL['nav_gap'])
        self.navigation.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.navigation.setAccessibleName(t('wallet.navigation_accessible'))
        self.navigation.addItems(tuple(title for title, _icon in fusion_nav_pages()))
        side.addWidget(self.navigation, 1)
        notice = grow_with_wrapped_text(label(t('wallet.sidebar_notice'), 'FusionMuted'))
        notice.setMinimumWidth(0)
        side.addWidget(notice)
        shell.addWidget(sidebar)

        main = QWidget()
        main.setObjectName("FusionTransparent")
        content = QVBoxLayout(main)
        content.setContentsMargins(
            SHELL['content_left'], SHELL['content_top'],
            SHELL['content_right'], SHELL['content_bottom'])
        content.setSpacing(SHELL['content_gap'])

        topbar = QFrame()
        topbar.setObjectName("FusionTopbar")
        top = QHBoxLayout(topbar)
        top.setContentsMargins(0, 0, 0, SHELL['topbar_bottom'])
        top.setSpacing(SHELL['topbar_gap'])
        self.page_title = label(t('fusion.overview'), "PageTitle")
        self.page_title.hide()
        top.addWidget(self.page_title)
        top.addStretch()
        self.connection_pill = label(t('wallet.snapshot_unverified'), "FusionBadge")
        top.addWidget(self.connection_pill)
        self.sync.setText(t('fusion.refresh'))
        self.sync.setObjectName("FusionSecondary")
        self.sync.setToolTip(t('wallet.refresh_tooltip'))
        self.sync.setAccessibleName(t('wallet.refresh_accessible'))
        top.addWidget(self.sync)
        divider = QFrame()
        divider.setObjectName("FusionDivider")
        divider.setFrameShape(QFrame.Shape.NoFrame)
        divider.setFixedWidth(SHELL['divider'])
        divider.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.MinimumExpanding)
        top.addWidget(divider)
        top.addWidget(label(t('wallet.theme'), "FusionMuted"))
        self.header_theme = ThemeSlider(compact=True)
        self.header_theme.setAccessibleName(t('wallet.theme_accessible'))
        top.addWidget(self.header_theme)
        content.addWidget(topbar)

        self.stack = TransitionHost()
        content.addWidget(self.stack, 1)
        original_status = self.status
        self.status = _WrappingStatusLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setText(original_status.text())
        original_status.deleteLater()
        self.status.setObjectName("FusionMuted")
        self.status.setWordWrap(True)
        self.status.setMinimumWidth(0)
        status_policy = self.status.sizePolicy()
        status_policy.setHorizontalPolicy(QSizePolicy.Policy.Ignored)
        status_policy.setVerticalPolicy(QSizePolicy.Policy.Minimum)
        status_policy.setHeightForWidth(True)
        self.status.setSizePolicy(status_policy)
        content.addWidget(self.status)
        shell.addWidget(main, 1)
        self.overview = FusionOverview()
        self.stack.addWidget(self.overview)
        self.receive_page = ReceivePage()
        self.stack.addWidget(self.receive_page)
        self.history_page = HistoryPage()
        self.stack.addWidget(self.history_page)

        send_page, send_layout = page(
            t('fusion.send'),
            t('wallet.send_subtitle'),
            t('wallet.send_kicker'),
        )
        self.payment_steps = PaymentSteps()
        send_layout.addWidget(self.payment_steps)
        form, fl = panel(t('wallet.prepare_title'), t('wallet.prepare_subtitle'))
        self.recipient_input = QLineEdit()
        self.recipient_input.setMaxLength(256)
        self.recipient_input.setPlaceholderText(t('wallet.recipient_hint'))
        self.amount_input = QLineEdit()
        self.amount_input.setMaxLength(32)
        self.amount_input.setPlaceholderText("0.00000000")
        fl.addWidget(label(t('wallet.recipient_caption'), "FusionKicker"))
        fl.addWidget(self.recipient_input)
        fl.addWidget(label(t('wallet.amount_caption'), "FusionKicker"))
        fl.addWidget(self.amount_input)
        fl.addWidget(label(t('wallet.fee_is_network')))
        self.send.setText(t('wallet.review_payment'))
        self.send.setObjectName("FusionPrimary")
        self.send.setProperty("fusion_icon", "send")
        fl.addWidget(self.send)
        review, rl = panel(
            t('wallet.review_title'),
            t('wallet.review_subtitle'),
        )
        self.review_summary = _WrappingStatusLabel()
        self.review_summary.setWordWrap(True)
        self.review_summary.setText(t('wallet.no_prepared_payment'))
        self.review_summary.setMinimumWidth(0)
        rl.addWidget(self.review_summary)
        self.activate.setText(t('wallet.enable_sending'))
        self.activate.setObjectName("FusionSecondary")
        self.activate.setProperty("fusion_icon", "security")
        self.broadcast.setText(t('pages.approve_broadcast'))
        self.broadcast.setObjectName("FusionSecondary")
        self.broadcast.setProperty("fusion_icon", "send")
        self.cancel.setText(t('owner.cancel_draft'))
        self.cancel.setObjectName("FusionSecondary")
        rl.addWidget(self.activate)
        rl.addWidget(self.broadcast)
        rl.addWidget(self.cancel)
        self.send_result = label(t('wallet.no_broadcast_result'))
        self.send_result.setMinimumWidth(0)
        rl.addWidget(self.send_result)
        rl.addWidget(label(t('wallet.no_automatic_retry'), "FusionGold"))
        send_layout.addWidget(ResponsiveRow(form, review, weights=[3, 2]))
        send_layout.addStretch()
        self.stack.addWidget(send_page)

        security_page, security_layout = page(
            t('fusion.security'),
            t('wallet.security_subtitle'),
            t('wallet.security_kicker'),
        )
        wallet_card, wl = panel(t('wallet.protection_title'), t('wallet.protection_subtitle'))
        self.security_state = label(t('wallet.awaiting_wallet'), "FusionCardValue")
        wl.addWidget(self.security_state)
        self.lock.setText(t('wallet.lock'))
        self.lock.setObjectName("FusionSecondary")
        self.lock.setProperty("fusion_icon", "lock")
        self.lock.hide()
        self.unlock.setText(t('owner.unlock'))
        self.unlock.setObjectName("FusionSecondary")
        self.unlock.hide()
        self.custody_switch = StateSwitch(t('fusion.locked'))
        self.custody_switch.setAccessibleName(t('fusion.wallet_lock_unlock_switch'))
        self.custody_switch.setToolTip(t('wallet.unlock_tooltip'))
        self.custody_switch.clicked.connect(self._switch_custody)
        wl.addWidget(self.custody_switch)
        # The base developer layout parks lock/unlock/quit in a utility bar;
        # the normal Fusion workspace owns the Security-page placement instead.
        self._legacy_layout_holder.layout().removeWidget(self.unlock)
        self.quit.setText(t('owner.quit'))
        self.quit.setObjectName("FusionDestructive")
        wl.addWidget(self.quit)
        wl.addWidget(label(
            t('wallet.seed_support_warning')
        ))
        recovery_card, rl = panel(
            t('wallet.recovery_title'),
            t('wallet.recovery_subtitle'),
        )
        rl.addWidget(self.recovery)
        rl.addWidget(label(
            t('wallet.reservations_retained'),
            "FusionGold",
        ))
        backup_card, bl = panel(t('wallet.backup_status'), t('wallet.backup_requirement'))
        bl.addWidget(label(t('wallet.recovery_support_warning')))
        self.backup_review = action(t('wallet.review_backup'), 'backup')
        self.backup_review.setAccessibleName(t('wallet.review_backup'))
        self.backup_review.clicked.connect(self._quick_backup)
        bl.addWidget(self.backup_review)
        security_layout.addWidget(ResponsiveRow(wallet_card, recovery_card))
        security_layout.addWidget(backup_card)
        security_layout.addStretch()
        self.stack.addWidget(security_page)

        self.network_page = NetworkPage()
        self.stack.addWidget(self.network_page)

        settings_page, settings_layout = page(
            t('fusion.settings'),
            t('wallet.settings_subtitle'),
            t('wallet.settings_kicker'),
        )
        appearance, appearance_layout = panel(
            t('wallet.appearance'),
            t('wallet.appearance_body'))
        self.settings_theme = ThemeSlider(compact=False)
        appearance_layout.addWidget(self.settings_theme, 0, Qt.AlignmentFlag.AlignLeft)
        self.appearance_group = self.header_theme.group
        self.appearance_buttons = self.header_theme.buttons
        self.reduce_motion = QCheckBox(t('wallet.reduce_motion'))
        stored = ui_settings()
        self.reduce_motion.setChecked(
            os.environ.get("QT_REDUCE_MOTION") == "1"
            or stored.value("fusion_reduce_motion", False, type=bool))
        self.reduce_motion.toggled.connect(self._set_reduce_motion)
        appearance_layout.addWidget(self.reduce_motion)
        settings_layout.addWidget(appearance)

        language_card, language_layout = panel(
            t("settings.language"),
            t("settings.language_next_window"))
        self.language = QComboBox()
        self.language.setObjectName("FusionLanguage")
        self.language.setAccessibleName(t("settings.language"))
        for caption, code in (
                (t("settings.language_system"), "system"),
                ("English", "en"),
                ("简体中文", "zh-Hans"),
                ("Tiếng Việt", "vi"),
                ("한국어", "ko"),
                ("Bahasa Indonesia", "id"),
                ("日本語", "ja")):
            self.language.addItem(caption, code)
        language_choice = effective_choice()
        self.language.blockSignals(True)
        language_index = self.language.findData(language_choice)
        self.language.setCurrentIndex(language_index if language_index >= 0 else 0)
        self.language.blockSignals(False)
        self.language.currentIndexChanged.connect(self._language_chosen)
        language_layout.addWidget(self.language)
        settings_layout.addWidget(language_card)

        about, about_layout = panel(
            t('wallet.about_title'),
            t('wallet.about_body'))
        about_layout.addWidget(label(core_compat.DISPLAY_NAME + t('wallet.protocol_summary')))
        about_layout.addWidget(label(
            t('wallet.preview_notice')))
        settings_layout.addWidget(about)
        self.network_state = self.network_page.connection_value
        if shared_profile is not None:
            self.reconcile_button = action(t('wallet.reconcile_retained'), 'security')
            self.reconcile_button.clicked.connect(self._reconcile_shared)
            self.network_page.controls_host.addWidget(self.reconcile_button)
            self._last_reconciliation = None
            for title, command in ((t('wallet.verify_peer_chain'), ('network_status',)),
                                   (t('wallet.disconnect_p2p'), ('network_active', False)),
                                   (t('wallet.reconnect_p2p'), ('network_active', True))):
                button = action(title, 'sync')
                button.clicked.connect(lambda _checked=False, command=command: self._command(*command))
                self.network_page.controls_host.addWidget(button)

        advanced_card, advanced_layout = panel(
            t('wallet.advanced_title'),
            t('wallet.advanced_body'))
        self.advanced_toggle = _AdvancedControlsToggle()
        self.advanced_toggle.setObjectName("FusionAdvanced")
        self.advanced_toggle.setCheckable(True)
        self.advanced_toggle.setText(t('wallet.show_developer'))
        self.advanced_toggle.setAccessibleName(t('wallet.expand_developer'))
        self.advanced_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        # Native macOS minimumSizeHint omits part of the stylesheet padding.
        # Minimum vertical policy keeps the complete styled sizeHint at any DPI.
        self.advanced_toggle.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Minimum)
        advanced_layout.addWidget(self.advanced_toggle)
        self.advanced_container = QWidget()
        self.advanced_container.setObjectName("FusionTransparent")
        advanced_body = QVBoxLayout(self.advanced_container)
        advanced_body.setContentsMargins(0, 6, 0, 0)
        advanced_body.setSpacing(13)
        advanced_body.addWidget(label(
            t('wallet.test_chain_warning'),
            "FusionGold"))
        advanced_body.addWidget(self.fund)
        advanced_body.addWidget(self.confirm)
        advanced_body.addWidget(self.inspect)
        advanced_body.addWidget(self.intents)
        advanced_body.addWidget(self.resume)
        advanced_body.addWidget(label(t('wallet.session_kicker'), "FusionKicker"))
        advanced_body.addWidget(self.account)
        advanced_body.addWidget(self.balance)
        advanced_body.addWidget(self.tip)
        for text in (self.account, self.balance, self.tip):
            text.setWordWrap(True)
            text.setMinimumWidth(0)
            policy = text.sizePolicy()
            policy.setHorizontalPolicy(QSizePolicy.Policy.Ignored)
            policy.setVerticalPolicy(QSizePolicy.Policy.Minimum)
            policy.setHeightForWidth(True)
            text.setSizePolicy(policy)
        advanced_body.addWidget(label(t('wallet.last_broadcast_kicker'), "FusionKicker"))
        advanced_body.addWidget(self.last_txid)
        advanced_layout.addWidget(self.advanced_container)
        self.advanced_container.hide()
        self.advanced_toggle.toggled.connect(self._toggle_advanced)
        settings_layout.addWidget(advanced_card)
        settings_layout.addStretch()
        self.stack.addWidget(settings_page)

        self.backup_page = Bip39BackupPage()
        self.backup_page.verify_requested.connect(self._on_backup_verify)
        self.backup_page.challenge_requested.connect(self._on_backup_challenge)
        self.backup_page.challenge_cancelled.connect(self._on_backup_challenge_cancel)
        self.backup_page.deferred_requested.connect(self._on_backup_deferred)
        self.backup_page.continue_requested.connect(self._on_backup_continue)
        self.stack.addWidget(self.backup_page)

        self.backup_deferred_page, deferred_layout = page(t('backup_title'), '', '')
        deferred_card, deferred_body = panel()
        deferred_card.setMaximumWidth(560)
        self.backup_locked_description = grow_with_wrapped_text(label(t('locked_subtitle')))
        deferred_body.addWidget(self.backup_locked_description)
        self.backup_reopen = action(t('backup.reopen'), 'security', primary=True)
        self.backup_reopen.setAccessibleName(t('backup.reopen'))
        self.backup_reopen.setMinimumHeight(36)
        # Existing password/profile/native-custody flow; no optimistic unlock.
        self.backup_reopen.clicked.connect(self._unlock_prompt)
        deferred_body.addWidget(self.backup_reopen)
        deferred_layout.addWidget(deferred_card)
        deferred_layout.addStretch()
        self.stack.addWidget(self.backup_deferred_page)

        self._transition = None
        self._advanced_transition = None
        self._press_feedback = PressFeedback(self)
        self._theme_sync = False
        self.header_theme.currentChanged.connect(self._theme_chosen)
        self.settings_theme.currentChanged.connect(self._theme_chosen)
        saved = ui_settings().value("fusion_appearance", 0, type=int)
        if saved in (0, 1, 2):
            self.header_theme.setCurrentIndex(saved, animate=False)
            self.settings_theme.setCurrentIndex(saved, animate=False)
        self._set_reduce_motion(self.reduce_motion.isChecked())
        self._overview_intro = False
        self.navigation.currentRowChanged.connect(self._navigate)
        self.navigation.setCurrentRow(0)
        self.overview.go_receive.clicked.connect(
            lambda: self.navigation.setCurrentRow(1))
        self.overview.go_send.clicked.connect(
            lambda: self.navigation.setCurrentRow(3))
        self.overview.open_history.clicked.connect(
            lambda: self.navigation.setCurrentRow(2))
        self.overview.open_security.clicked.connect(
            lambda: self.navigation.setCurrentRow(4))
        self.overview.manual_sync.clicked.connect(
            lambda: self._command("snapshot"))
        self.overview.transaction_selected.connect(self._select_transaction)
        self.history_page.page_requested.connect(self._request_history_page)
        self.overview.custody_switch.clicked.connect(self._switch_custody)
        self._payment_decision = None
        self.recipient_input.textChanged.connect(self._set_actions)
        self.amount_input.textChanged.connect(self._set_actions)
        self._last_verified = None
        self._last_review = None
        self._last_network = None
        self._broadcast_complete = False
        self._apply_fusion_theme()
        self._press_feedback.attach(self)
        self.overview.render_snapshot(
            None, locked=True, network=self._network_view(None),
            faulted=self.executor.state.faulted,
            core_alive=self.executor.state.core_alive)
        if hasattr(QApplication.styleHints(), "colorSchemeChanged"):
            QApplication.styleHints().colorSchemeChanged.connect(
                self._native_theme_changed)
        install_keyboard_focus_mark(self)
        self._set_actions()

    def _language_chosen(self, index):
        value = self.language.itemData(index)
        if type(value) is not str:
            return
        settings = ui_settings()
        settings.setValue("ui_language", value)
        settings.sync()

    def _set_reduce_motion(self, checked):
        self.setProperty("fusion_reduce_motion", bool(checked))
        ui_settings().setValue("fusion_reduce_motion", bool(checked))
        self.style().unpolish(self)
        self.style().polish(self)

    def _theme_chosen(self, index):
        if index not in (0, 1, 2) or self._theme_sync:
            return
        self._theme_sync = True
        try:
            for slider in (self.header_theme, self.settings_theme):
                if slider.currentIndex() != index:
                    slider.setCurrentIndex(index, animate=slider is not self.sender())
            ui_settings().setValue("fusion_appearance", index)
            self._apply_fusion_theme()
        finally:
            self._theme_sync = False

    def _native_theme_changed(self, *_):
        if self.header_theme.currentIndex() == 0:
            self._apply_fusion_theme()

    def _apply_fusion_theme(self, *_):
        from datetime import datetime
        selection = self.header_theme.currentIndex()
        if selection == 0:
            # Match macOS System Appearance, not an assumed day/night hour.
            scheme = QApplication.styleHints().colorScheme()
            mode = ("dark" if scheme == Qt.ColorScheme.Dark else
                    "light" if scheme == Qt.ColorScheme.Light else
                    resolve_theme("auto", datetime.now().astimezone()))
        else:
            mode = "light" if selection == 1 else "dark"
        colors = fusion_palette(mode)
        # Reapplying an unchanged sheet resigns the Cocoa key window once
        # Tab is allowed to reach every control. Icons below still follow
        # the selected page.
        if getattr(self, '_styled_mode', None) != mode:
            self.setStyleSheet(fusion_stylesheet(mode))
            self._styled_mode = mode
        present_brand_title(
            self._brand_title, t('wallet.brand'),
            SHELL['sidebar_width'] - 2 * SHELL['sidebar_pad_x'],
            colors['brand'])
        self.overview.set_theme(mode)
        self.history_page.set_theme(mode)
        selected = self.navigation.currentRow()
        for index in range(self.navigation.count()):
            item = self.navigation.item(index)
            tone = colors["onaccent"] if index == selected else colors["muted"]
            item.setIcon(nav_icon_for(item.text(), tone, max(1, self.devicePixelRatioF())))
        for button in self.findChildren(__import__(
                "PySide6.QtWidgets", fromlist=["QPushButton"]).QPushButton):
            icon = button.property("fusion_icon")
            if icon:
                tone = colors["onaccent"] if button.objectName() == "FusionPrimary" else colors["accent"]
                button.setIcon(vector_icon(icon, tone, max(1, self.devicePixelRatioF())))
        from PySide6.QtWidgets import QToolButton, QLabel
        dpr = max(1, self.devicePixelRatioF())
        for button in self.findChildren(QToolButton):
            icon = button.property("fusion_icon")
            if icon:
                on_thumb = (button.objectName() == "FusionSegment" and button.isChecked())
                button.setIcon(vector_icon(
                    icon, colors["onaccent"] if on_thumb else colors["accent"], dpr))
        for icon_label in self.findChildren(QLabel):
            name = icon_label.property("fusion_icon_label")
            if name:
                icon_label.setPixmap(vector_icon(name, colors["accent"], max(1, self.devicePixelRatioF())).pixmap(24, 24))
        self.sync.setIcon(vector_icon("sync", colors["accent"], max(1, self.devicePixelRatioF())))
        self.custody_switch.setProperty("fusion_mode", mode)
        self.overview.custody_switch.setProperty("fusion_mode", mode)
        self.custody_switch.update()
        self.overview.custody_switch.update()

    def _navigate(self, index):
        if not 0 <= index < len(FUSION_NAV_PAGES):
            return
        if self._backup_flow_active:
            if not self._backup_verified and self.backup_page.holds_unverified_phrase():
                if self.backup_page.confirm_departure():
                    self.backup_page.clear_phrase()
                    self._defer_active_backup()
            if self._backup_flow_active and self.navigation.currentRow() != 0:
                self.navigation.blockSignals(True)
                self.navigation.setCurrentRow(0)
                self.navigation.blockSignals(False)
            return
        self.page_title.setText(self.navigation.item(index).text())
        reduced = self.reduce_motion.isChecked() or motion_reduced(self)
        self.stack.set_current(index, reduced=reduced)
        self._apply_fusion_theme()
        if index == 0:
            self._play_overview_intro()

    def _toggle_advanced(self, expanded):
        self.advanced_toggle.setText(
            t('wallet.hide_developer') if expanded
            else t('wallet.show_developer'))
        self.advanced_container.setVisible(expanded)
        if not expanded:
            return
        self._advanced_transition = fade_widget(
            self.advanced_container, start=0.5, end=1.0, duration=180, parent=self)

    def _quick_backup(self):
        dialog = WalletConsent(
            t('wallet.backup_title'),
            t('wallet.backup_explanation'),
            self, accept_text=t('wallet.verify_words'))
        try:
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.recovery.click()
        finally:
            dialog.deleteLater()

    def _play_overview_intro(self):
        if getattr(self, '_overview_intro', False) or motion_reduced(self) or self.reduce_motion.isChecked():
            return
        self._overview_intro = True
        groups = (
            self.overview.hero,
            self.overview.status_board,
            self.overview.activity_panel,
        )
        for delay, widget in enumerate(groups):
            # Context object = this window: Qt drops the pending fade if the
            # window is destroyed first (for example right after Quit), instead
            # of calling into deleted widgets.
            QTimer.singleShot(
                STAGGER_MS * delay, self,
                lambda widget=widget: fade_widget(
                    widget, start=0.35, end=1.0, duration=STANDARD_MS, parent=self))

    def _request_history_page(self, offset):
        # Only a read of this same authenticated profile. Never select a
        # different owner or grant spending authority from cached GUI rows.
        if (not self._ready or self._quit_requested or self.executor.state.locked
                or self.executor.state.faulted):
            return False
        return self._command('snapshot', offset)

    def _select_transaction(self, txid):
        self.navigation.setCurrentRow(2)
        self.history_page.select_txid(txid)

    def _network_view(self, snap):
        shared = self.shared_profile is not None
        view = {
            'shared': shared,
            'mode': t('pages.shared_regtest') if shared else t('pages.isolated_regtest'),
        }
        net = getattr(self, '_last_network', None)
        if isinstance(net, dict):
            if type(net.get('peer_count')) is int:
                view['peer_count'] = net['peer_count']
            if 'connected' in net:
                view['connected'] = net['connected']
        lines = [view['mode']]
        if 'peer_count' in view:
            lines.append(str(view['peer_count']) + t('wallet.peer_suffix'))
        elif not shared:
            lines.append(t('pages.zero_peer_isolated_profile'))
        if snap is not None:
            lines.append(t('wallet.height_prefix') + str(snap.height))
        view['summary'] = '\n'.join(lines)
        return view

    def _render_network(self, snap=None):
        net = getattr(self, '_last_network', None) or {}
        snap = self._last_verified if snap is None and hasattr(self, '_last_verified') else snap
        self.network_page.render(
            shared=self.shared_profile is not None,
            connected=net.get('connected') if isinstance(net, dict) else None,
            peer_count=net.get('peer_count') if isinstance(net, dict) else None,
            height=(snap.height if snap is not None else
                    (net.get('height') if isinstance(net, dict) else None)),
            tip=(snap.tip if snap is not None else
                 (net.get('tip') if isinstance(net, dict) else None)),
            coordinator=None if self.shared_profile is None else self.shared_profile.coordinator,
            core_alive=self.executor.state.core_alive,
        )

    def _set_actions(self):
        inputs = self._action_inputs()
        profile = getattr(self, 'shared_profile', None)
        shared = (None if profile is None else
                  SharedInputs(coordinator=bool(profile.coordinator),
                               connected=bool(self._shared_connected)))
        actions = apply_shared_profile(available_actions(inputs), shared)
        if hasattr(self, 'recipient_input'):
            try:
                self._payment_form_values()
            except (ValueError, ArithmeticError):
                actions['send'] = False
        self._apply_actions(actions)
        if (not self._payment_scope_valid()
                or (getattr(self, '_payment_decision', None) is not None
                    and self._payment_decision_commitment != self._approved_commitment)
                or (self._worker is not None
                    and self._worker_action in ('lock', 'quit', 'open', 'unlock', 'reconcile_reorg'))):
            self._invalidate_payment_decision()
        if hasattr(self, "overview"):
            extra = fusion_actions(inputs, actions, shared)
            idle = not inputs.busy
            if hasattr(self,'reconcile_button'):
                self.reconcile_button.setEnabled(extra['reconcile'])
            if hasattr(self, 'custody_switch'):
                unlocked = extra['custody_unlocked']
                for switch in (self.custody_switch, self.overview.custody_switch):
                    switch.setToolTip(t('wallet.lock_tooltip') if unlocked else
                                      t('wallet.unlock_password_tooltip'))
                    switch.blockSignals(True)
                    switch.setChecked(unlocked)
                    switch.setText(t('fusion.unlocked') if unlocked else t('fusion.locked'))
                    switch.setEnabled(extra['custody_switch'])
                    switch.blockSignals(False)
                self.overview.security_card.apply(*classify(
                    'security',
                    snap=self._last_verified,
                    locked=not unlocked,
                    operational=unlocked,
                    faulted=self.executor.state.faulted,
                    core_alive=self.executor.state.core_alive,
                    busy=not idle,
                    network=self._network_view(self._last_verified),
                ), animate=False)
            self.overview.go_send.setEnabled(extra['go_send'])
            self.overview.open_security.setEnabled(extra['open_security'])
            if hasattr(self, "security_state"):
                self.security_state.setText(
                    t('wallet.security_faulted')
                    if self.executor.state.faulted else
                    t('wallet.security_locked')
                    if self.executor.state.locked else
                    t('wallet.security_reauth')
                    if self.executor.state.reauthentication_required else
                    t('wallet.security_core_unverified')
                    if self.executor.state.core_alive is not True else
                    t('wallet.security_disconnected')
                    if self.shared_profile is not None and self._spend_enabled and not self._shared_connected else
                    t('wallet.security_verified') if self._spend_enabled else
                    t('wallet.security_checkpoint') if self._ready else
                    t('wallet.security_locked')
                )
            if hasattr(self, "payment_steps"):
                self.payment_steps.set_stage(
                    4 if getattr(self, '_broadcast_complete', False) else
                    3 if self._signed_ready else
                    2 if self._approved_commitment is not None else 0
                )
            self._render_network()

    def _present_backup_ack(self, result):
        self.navigation.setEnabled(False)
        self.page_title.setText(t('wallet.backup_heading'))
        self.page_title.show()
        self.connection_pill.setText(t("regtest_preview"))
        if result.get("backup_status") == "required" and result.get("mnemonic_once"):
            self.backup_page.set_phrase(result["mnemonic_once"].split())
        else:
            self.backup_page.set_deferred_mode()
        self.stack.setCurrentWidget(self.backup_page)

    def _switch_custody(self, checked):
        # Reflect only authenticated backend state, never the optimistic click.
        self._set_actions()
        if checked:
            self._unlock_prompt()
        else:
            self._command('lock')

    def _passphrase(self, message):
        dialog = WalletConsent(t('wallet.unlock_title'), message, self, password=True)
        try:
            if dialog.exec() == QDialog.DialogCode.Accepted and dialog.password_input.text():
                return dialog.password_input.text().encode('utf-8')
            return None
        finally:
            dialog.password_input.clear()
            dialog.deleteLater()

    def _confirm_activation(self):
        if not self._ready or self._spend_enabled or self.executor.busy:
            return
        dialog = WalletConsent(t('wallet.enable_title'),
            t('wallet.enable_consent'), self)
        try:
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self._command('activate')
        finally:
            dialog.deleteLater()

    def _reconcile_shared(self):
        if self.shared_profile is None or self.executor.busy or self._worker is not None or self._delivering_result:
            return
        dialog=WalletConsent(t('wallet.reconcile_title'),
            t('wallet.reconcile_consent'),
            self,password=True,accept_text=t('wallet.reconcile'))
        try:
            if dialog.exec()==QDialog.DialogCode.Accepted:
                self._command('reconcile_reorg',dialog.password_input.text().encode('utf-8'))
        finally:
            dialog.password_input.clear();dialog.deleteLater()

    def _confirm_one_block(self):
        txid = self._pending_confirm_txid
        if not self._spend_enabled or txid is None:
            return
        dialog = WalletConsent(t('wallet.confirm_title'),
            t('wallet.confirm_consent'), self)
        try:
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self._command('confirm', txid)
        finally:
            dialog.deleteLater()

    def _confirm_funding(self):
        if not self._ready or self._spend_enabled or self._test_funded:
            return
        dialog = WalletConsent(t('wallet.fund_title'),
            t('wallet.fund_consent'), self)
        try:
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self._command('mine')
        finally:
            dialog.deleteLater()

    def _on_backup_challenge(self):
        try:
            challenge = self.executor.request('backup_challenge', timeout=30)
            self.backup_page.set_challenge(challenge)
        except Exception as error:
            self.backup_page.show_verification_error('verify_unavailable')
            self._last_error_code = operation_error('backup_challenge', error)
            self.status.setText(t('wallet.backup_verify_unavailable'))

    def _on_backup_challenge_cancel(self):
        try:
            self.executor.request('backup_challenge_cancel', timeout=30)
        except Exception as error:
            self._last_error_code = operation_error('backup_challenge_cancel', error)
            self.status.setText(t('wallet.backup_verify_unavailable'))

    def _on_backup_verify(self, identifier, answers):
        try:
            ok = self.executor.request("backup_verify", identifier, answers, timeout=30)
        except Exception as error:
            self._last_error_code = operation_error('backup_verify', error)
            self.status.setText(t('wallet.backup_verify_unavailable'))
            # The backend refused before judging the words: never report this
            # as a wrong-word result (V19: correct words shown as "do not match").
            self.backup_page.show_verification_error('verify_unavailable')
            self._on_backup_challenge()
            return
        if ok:
            self._backup_verified = True
            self.backup_page.show_success()
        else:
            self.backup_page.show_verification_error()
            self._on_backup_challenge()

    def _defer_active_backup(self):
        if not self._backup_flow_active:
            return
        self._backup_flow_active = False
        if self._backup_verified:
            # Verified acknowledgement is final; never send a deferral for it.
            self._backup_flow_completed(True)
            return
        # Clear any visible recovery words BEFORE dispatching backup_defer.
        self.backup_page.clear_phrase()
        defer_error = None
        try:
            self.executor.request("backup_defer", timeout=30)
        except Exception as error:
            self._last_error_code = operation_error('backup_defer', error)
            defer_error = t('wallet.backup_defer_unavailable')
        self._backup_flow_completed(False)
        # Never present an uncertain deferral as successfully locked.
        if defer_error is None and self.executor.state.locked and not self._quit_requested:
            self.stack.setCurrentWidget(self.backup_deferred_page)
        if defer_error is not None and not self._quit_requested:
            self.status.setText(defer_error)

    def _on_backup_deferred(self):
        self._defer_active_backup()

    def _on_backup_continue(self):
        self._backup_flow_completed(True)

    def request_quit(self):
        # Window close and quit while the only seed display is still on
        # screen need the same explicit confirmation as Back up later.
        if (self._backup_flow_active and not self._quit_requested
                and not self._backup_verified
                and self.backup_page.holds_unverified_phrase()):
            if not self.backup_page.confirm_departure():
                return
            self.backup_page.clear_phrase()
        super().request_quit()

    def _backup_flow_completed(self, success):
        # Every exit route drops the recovery words from the widgets.
        self.backup_page.clear_phrase()
        self.navigation.setEnabled(True)
        self.stack.setCurrentIndex(0)
        self.navigation.setCurrentRow(0)
        self.page_title.setText(t('fusion.overview'))
        self.page_title.hide()
        if success:
            self.connection_pill.setText(classify(
                'snapshot', snap=None, locked=True,
                core_alive=self.executor.state.core_alive)[1])
        super()._backup_flow_completed(success)

    def _payment_scope_valid(self):
        state = self.executor.state
        return (self._ready and self._spend_enabled and not self._quit_requested
                and not self.executor.closed and not state.locked and not state.faulted
                and not state.reauthentication_required and state.core_alive is True
                and (self.shared_profile is None or self._shared_connected))

    def _invalidate_payment_decision(self):
        dialog = getattr(self, '_payment_decision', None)
        if dialog is not None:
            # Revoke the callback BEFORE reject() synchronously emits finished.
            self._payment_decision = None
            dialog.setEnabled(False)
            dialog.reject()

    def _payment_form_values(self):
        atoms = parse_amount(self.amount_input.text())
        code = self.recipient_input.text().strip()
        if not code.startswith("wamrtsp1") or len(code) > 256:
            raise ValueError("Q06_FUSION_RECIPIENT_DENIED")
        return code, atoms

    def _open_payment_decision(self, dialog, decide):
        """Present PaymentApproval without a nested QDialog.exec() loop.

        Cocoa can fail to leave exec() when the dialog is accepted while
        exec() is still inside show(). The Accept button is unchanged and
        nothing is signed or broadcast until that button finishes the dialog.
        """
        self._invalidate_payment_decision()
        self._payment_decision = dialog
        commitment = self._approved_commitment
        self._payment_decision_commitment = commitment
        def finished(code):
            current = self._payment_decision is dialog
            if current:
                self._payment_decision = None
            dialog.deleteLater()
            if (current and self._payment_scope_valid()
                    and commitment == self._approved_commitment):
                decide(code)
        dialog.finished.connect(finished)
        if not self._payment_scope_valid():
            self._invalidate_payment_decision()
            return
        dialog.open()
        # Invalidation can arrive inside showEvent; open() must not revive it.
        if not dialog.isEnabled():
            dialog.reject()

    def _prepare_send(self):
        if (not self._spend_enabled or self._approved_commitment is not None
                or self._recovered_unsigned_cancel
                or self.executor.state.faulted or self.executor.busy):
            return
        try:
            code, atoms = self._payment_form_values()
        except (ValueError, ArithmeticError):
            self.status.setText(t('wallet.invalid_payment'))
            return
        self._command("prepare_auto", code, atoms)

    def _confirm_broadcast(self):
        if (not self._signed_ready or self._approved_commitment is None
                or self._last_review is None or self.executor.state.faulted
                or self.executor.busy or self._quit_requested):
            return
        review = self._last_review
        if review.commitment != self._approved_commitment:
            return
        dialog = PaymentApproval(review, "broadcast", self)
        commitment = review.commitment
        def decide(code):
            if (code == QDialog.DialogCode.Accepted
                    and commitment == self._approved_commitment):
                self._command("broadcast", commitment)
        self._open_payment_decision(dialog, decide)

    def _render_verified(self, result):
        snap = result.get("fusion_snapshot")
        if (type(snap) is not WalletReadSnapshot
                or snap.chain != "regtest"
                or snap.synthetic_rpc or snap.mainnet_allowed
                or snap.receive_code != result.get("receive_code")
                or snap.confirmed_atoms != result.get("confirmed_atoms")
                or snap.signer_allowed is not result.get("signer_allowed")
                or snap.broadcast_allowed is not result.get("broadcast_allowed")
                or self.executor.state.faulted):
            self._clear_visuals()
            self.status.setText("Q06_FUSION_VERIFIED_SNAPSHOT_DENIED")
            return
        try:
            self.overview.render_snapshot(
                snap, operational=True, network=self._network_view(snap),
                available_atoms=result.get("available_atoms"),
                reservation_count=displayed_reserved_inputs(result),
                core_alive=self.executor.state.core_alive,
                busy=False)
            self.connection_pill.setText(classify(
                'snapshot', snap=snap, operational=True,
                faulted=self.executor.state.faulted,
                core_alive=self.executor.state.core_alive,
                network=self._network_view(snap))[1])
            self.receive_page.render_snapshot(snap)
            self.history_page.render_snapshot(snap)
            self._render_network(snap)
        except (ValueError, TypeError):
            self._clear_visuals()
            self.status.setText("Q06_FUSION_PRESENTATION_DENIED")
            return
        self._last_verified = snap
        # go_send availability has ONE writer: _set_actions via
        # presentation.action_state.fusion_actions (every caller of this
        # method reaches _set_actions before _on_ready returns).

    def _clear_visuals(self):
        # A missing/denied presentation snapshot clears display data, not the
        # live payment review. Session/scope changes revoke decisions separately.
        self._last_verified = None
        self._last_network = None
        self._shared_connected = False
        # Advanced/compatibility fields share the same lifetime as the pages.
        # Do not use lock delivery here: it also changes payment authority.
        self.receive.clear()
        self.history.clear()
        self.account.setText(t('owner.account_locked'))
        self.balance.setText(t('owner.balance_unverified'))
        self.tip.setText(t('owner.chain_unverified'))
        # Value-bearing labels have selectable and accessibility buffers even
        # when hidden. Invalidate their metadata with the displayed values.
        for field in (self.receive, self.history, self.account, self.balance, self.tip,
                      self.overview.balance_value, self.overview.balance_unit,
                      self.overview.fund_details, self.overview.utxo_details,
                      self.overview.evidence_text, self.overview.environment_core,
                      self.receive_page.receive_code, self.receive_page.received,
                      self.history_page.detail_id, self.history_page.detail_values,
                      self.history_page.scope):
            field.setToolTip('')
            field.setAccessibleName('')
            field.setAccessibleDescription('')
        self.connection_pill.setText(classify(
            'snapshot', snap=None, locked=True,
            faulted=self.executor.state.faulted,
            core_alive=self.executor.state.core_alive)[1])
        self.overview.render_snapshot(
            None, locked=True, faulted=self.executor.state.faulted,
            network=self._network_view(None),
            core_alive=self.executor.state.core_alive)
        self.receive_page.render_snapshot(None)
        self.history_page.render_snapshot(None)
        self._render_network(None)
        if hasattr(self, 'review_summary'):
            self.review_summary.setText(t('wallet.no_prepared_payment'))

    def _on_ready(self, action, result):
        if action in ('lock', 'quit', 'open', 'unlock', 'reconcile_reorg'):
            self._invalidate_payment_decision()
        if action in ('open', 'unlock'):
            # Revoke old values before the base handler can expose the new
            # authenticated account or enter backup acknowledgement.
            if action == 'open':
                self._last_error_code = None
            self._clear_visuals()
        if action=='reconcile_reorg':
            self._last_reconciliation=result['reconciliation']
            self._spend_enabled=self._signed_ready=False
            self._approved_commitment=self._pending_confirm_txid=None
            self._last_review=None
            self._clear_visuals()
            super()._on_ready('open',result)
            self.status.setText(t('wallet.reconciled'))
            self._set_actions()
            return
        if isinstance(result,dict) and 'shared_network' in result:
            self._shared_connected = result['shared_network']['connected']
            self._last_network = result['shared_network']
        if action in ('network_status','network_active'):
            self._shared_connected = result['connected']
            self._last_network = result
            self.network_state.setText((t('wallet.connected') if result['connected'] else t('wallet.disconnected'))
                +t('wallet.network_details').format(peer_count=result['peer_count'], height=result['height'], tip=result['tip']))
            self.status.setText(t('wallet.shared_verified')
                                if result['connected'] else t('wallet.peer_disconnected'))
            self._set_actions()
            return
        if action in ("prepare", "prepare_auto"):
            # Existing Q05 Fusion exact-transaction approval, not the old
            # developer QMessageBox. Signing still requires explicit consent
            # and retains its native-anchored irreversible reservation.
            self._approved_commitment = result.commitment
            self._last_review = result
            self._signed_ready = False
            self._broadcast_complete = False
            self.review_summary.setText(fusion_review_text(result))
            self.payment_steps.set_stage(1)
            dialog = PaymentApproval(result, "sign", self)
            commitment = result.commitment
            def decide(code):
                accepted = code == QDialog.DialogCode.Accepted
                self.status.setText(
                    t('wallet.sign_approved')
                    if accepted else
                    t('wallet.sign_declined')
                )
                if accepted and commitment == self._approved_commitment:
                    pending = ("sign", commitment)
                elif not accepted:
                    pending = ("cancel",)
                else:
                    pending = None
                # Acceptance during show() is still inside prepare delivery.
                # Leave the one explicit command for _finished. A later click
                # is outside delivery and must start that same command itself.
                if self._delivering_result:
                    self._pending_action = pending
                elif (pending is not None and self._worker is None
                      and not self._quit_requested):
                    self._command(*pending)
                self._set_actions()
            # The prepare worker has already finished. Opening the dialog
            # returns to the main loop so an approval that arrives during
            # show() cannot wedge QDialog.exec() and hide the wait deadline.
            self._open_payment_decision(dialog, decide)
            return
        super()._on_ready(action, result)
        if action in ("cancel", "broadcast", "lock", "quit"):
            self._last_review = None
        if action == "broadcast":
            txid = self.last_txid.text().strip()
            if txid and 'uncertain' not in txid.lower():
                self.send_result.setText(describe_broadcast_result(txid))
                self._broadcast_complete = True
            else:
                self.send_result.setText(describe_broadcast_result(None))
                self._broadcast_complete = False
        if (action == "confirm" and isinstance(result, dict)
                and result.get("status") == "Q06_REGTEST_EXACT_SEND_CONFIRMED"
                and type(result.get("txid")) is str and self._pending_confirm_txid is None):
            # confirm_pending returns this only after the exact TXID is in
            # verified history; the base handler already matched the TXID.
            self.send_result.setText(describe_broadcast_result(
                result["txid"], {"status": "Q06_CONFIRMED_IN_VERIFIED_HISTORY"}))
        if action == "inspect_confirmed":
            facts = result if isinstance(result, dict) else None
            txid = facts.get("txid") if facts is not None else None
            self.send_result.setText(describe_broadcast_result(txid, facts))
            if facts is not None and facts.get("status") == "Q06_CONFIRMED_IN_VERIFIED_HISTORY":
                self._broadcast_complete = True
                self.payment_steps.set_stage(4)
            elif facts is not None and facts.get("in_mempool") is True:
                self._broadcast_complete = True
                self.payment_steps.set_stage(4)
        if action == "sign":
            self.payment_steps.set_stage(3)
        if action in ("snapshot", "activate"):
            self._render_verified(result)
            txid = self._pending_confirm_txid
            # Only inspect the exact pending broadcast. last_txid after
            # confirmation must not start a second inspect that can deny
            # the following lock/unlock wait.
            if (action == "snapshot" and self._broadcast_complete
                    and type(txid) is str and len(txid) == 64):
                self._pending_action = ("inspect_confirmed", txid)
            elif (type(txid) is str and len(txid) == 64 and not self._broadcast_complete
                    and self._last_review is None):
                # Reopened wallet: the session re-identified its unconfirmed
                # broadcast. Show it on Send too; display only, no auto-inspect.
                self.send_result.setText(describe_broadcast_result(txid))
        elif action == "open":
            # Same owner, bounded read-only chain sync only after the explicit
            # backup acknowledgement; a refused create above stops with lock.
            if (not self._backup_flow_active and not self._backup_unacked
                    and not result.get('checkpoint_present')):
                self._pending_action = ("snapshot",)
        elif action == "mine":
            self._pending_action = ("snapshot",)
        elif action in ("lock", "quit"):
            self._broadcast_complete = False
            self._clear_visuals()
        elif action == 'unlock':
            if result.get('fusion_snapshot') is not None:
                self._render_verified(result)
        self._set_actions()

    def _on_denied(self, code):
        super()._on_denied(code)
        if code == 'SHARED_CONFIRMED_PEER_REQUIRED':
            self._shared_connected=False
            self.status.setText(t('wallet.peer_reconnect_warning'))
            self._set_actions()
        if (self.executor.state.faulted or self.executor.state.core_alive is not True
                or code in ('WALLET_CORE_AUTHENTICATION_DENIED',
                            'WALLET_CORE_IDENTITY_DENIED', 'WALLET_CORE_UNAVAILABLE',
                            'WALLET_CORE_UNVERIFIED')):
            # Revoke only the cached GUI scope. The backend's commitment,
            # signed evidence and irreversible reservations are untouched.
            self._spend_enabled = False
            self._clear_visuals()
            if (self._approved_commitment is not None or self._signed_ready
                    or self._pending_confirm_txid is not None
                    or self._recovered_unsigned_cancel):
                self.review_summary.setText(
                    t('wallet.payment_retained'))
            self.connection_pill.setText(classify(
                'snapshot', snap=None, locked=True, faulted=self.executor.state.faulted,
                core_alive=self.executor.state.core_alive)[1])
        elif self._last_verified is not None:
            self.overview.live_badge.setText(t('wallet.refresh_required'))
        self._set_actions()
