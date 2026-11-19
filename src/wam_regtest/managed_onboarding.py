"""V1 Welcome is BIP39 create, open, and restore only.

Q05 files are not opened and are not migrated. No new wallet owner, seed
conversion, backup import, Core/GUI signing authority or automatic recovery.
The welcome screen only chooses an explicit route. Every actual profile is
authenticated by its existing native owner.
"""
from .bip39_locale import t as ui_text
from pathlib import Path
import re
import secrets


def selected_profile(directory, create):
    if (type(create) is not bool or not directory.is_absolute()
            or directory.is_symlink() or not directory.is_dir()):
        raise ValueError("MANAGED_PROFILE_SELECTION_DENIED")
    if create:
        root = directory / ("wam-fusion-core-" + secrets.token_hex(8))
        if root.exists() or root.is_symlink():
            raise ValueError("MANAGED_PROFILE_SELECTION_DENIED")
        return root
    if not re.fullmatch(r"wam-fusion-core-[0-9a-f]{16}", directory.name):
        raise ValueError("MANAGED_PROFILE_SELECTION_DENIED")
    # Opening an old folder must never silently create/repair/replace it.
    if not (directory / "supervisor.profile").is_file():
        raise ValueError("MANAGED_PROFILE_SELECTION_DENIED")
    return directory


# (uses BIP39, seed open mode, selects NEW disposable Core profile)
_ROUTES = {
    "create": (True, "create", True),
    "open": (True, "reopen", False),
    "restore": (True, "restore", True),
}
_RETIRED_WELCOME = frozenset(("legacy_open", "legacy_create"))


def wallet_route(choice):
    """Pure routing contract; never migrate Q05 keys/anchors into Q06."""
    if choice in _RETIRED_WELCOME:
        raise ValueError("LEGACY_Q05_RETIRED")
    if type(choice) is not str or choice not in _ROUTES:
        raise ValueError("WAM_FUSION_WELCOME_CHOICE_DENIED")
    return _ROUTES[choice]


def welcome_dialog():
    """One native Qt welcome screen; no Core, seed or credential is opened."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QApplication, QDialog, QFrame, QVBoxLayout, QCheckBox,
        QScrollArea, QWidget,
    )
    from .fusion_ui import action, label, panel, fusion_palette, fusion_stylesheet, vector_icon

    dialog = QDialog()
    dialog.setObjectName("WAMFusionWelcome")
    dialog.setWindowTitle(ui_text('welcome.wam_fusion_privacy_wallet'))
    dialog.setMinimumSize(540, 550)
    # Not modal: see run_welcome(). It is the only window while it is shown.
    dialog.setWindowModality(Qt.WindowModality.NonModal)
    dialog.selection = None
    dialog.buttons = {}
    hint = QApplication.styleHints()
    mode = "dark" if hint.colorScheme() == Qt.ColorScheme.Dark else "light"
    dialog.setStyleSheet(fusion_stylesheet(mode))
    palette = fusion_palette(mode)

    outer = QVBoxLayout(dialog)
    outer.setContentsMargins(0, 0, 0, 0)
    scroll = QScrollArea(dialog)
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    content = QWidget()
    scroll.setWidget(content)
    outer.addWidget(scroll)
    root = QVBoxLayout(content)
    root.setContentsMargins(28, 28, 28, 24)
    root.setSpacing(18)
    root.addWidget(label(ui_text('welcome.wam_fusion'), "FusionKicker"))
    root.addWidget(label(ui_text('welcome.welcome_to_your_wallet'), "PageTitle"))
    root.addWidget(label(
        ui_text('welcome.begin')
    ))
    root.addWidget(label(ui_text('welcome.regtest_preview_no_real_funds'), "FusionBadge"))
    dialog.shared_mode = QCheckBox(ui_text('welcome.shared_regtest_manual_core_p2p'))
    dialog.shared_mode.setToolTip(ui_text('welcome.shared_tooltip'))
    root.addWidget(dialog.shared_mode)

    choices, layout = panel(
        ui_text('welcome.your_wallet'),
        ui_text('welcome.experience'),
    )
    for key, title, detail, icon_name, primary in (
        ("create", ui_text('welcome.create_a_new_wallet'),
         ui_text('welcome.create_detail'), "overview", True),
        ("open", ui_text('welcome.open_existing_wallet'),
         ui_text('welcome.open_detail'), "unlock", False),
        ("restore", ui_text('welcome.restore_from_12_words'),
         ui_text('welcome.restore_detail'), "backup", False),
    ):
        button = action(title, icon_name, primary)
        button.setAccessibleName(title)
        button.setMinimumHeight(48)
        button.setIcon(vector_icon(
            icon_name, palette["onaccent"] if primary else palette["accent"]))
        dialog.buttons[key] = button
        layout.addWidget(button)
        layout.addWidget(label(detail, "FusionMuted"))
    root.addWidget(choices)
    QWidget.setTabOrder(dialog.buttons["create"], dialog.buttons["open"])
    QWidget.setTabOrder(dialog.buttons["open"], dialog.buttons["restore"])
    root.addStretch()

    def select(key):
        dialog.selection = key
        dialog.accept()

    for key, button in dialog.buttons.items():
        button.clicked.connect(
            lambda _checked=False, selected=key: select(selected))
    return dialog


def assert_unified_welcome_qt():
    """Live Qt source/packaged smoke. Never creates keys or starts a Core."""
    from PySide6.QtWidgets import QDialog, QWidget
    for choice in ("create", "open", "restore"):
        dialog = welcome_dialog()
        if (dialog.selection is not None
                or tuple(dialog.buttons) != ("create", "open", "restore")
                or dialog.findChild(QWidget, "FusionAdvanced") is not None):
            raise ValueError("WAM_FUSION_WELCOME_LAYOUT_DENIED")
        dialog.buttons[choice].click()
        if (dialog.result() != QDialog.DialogCode.Accepted
                or dialog.selection != choice or not wallet_route(choice)[0]):
            raise ValueError("WAM_FUSION_WELCOME_BIP39_ROUTE_DENIED")
        dialog.deleteLater()

    # Also executed by genuine native/frozen Q06 probes before any owner exists.
    from .onboarding_probe import qualify_password_dialogs
    qualify_password_dialogs()


def run_welcome(dialog):
    """Show Welcome and wait for its result without an application-modal session.

    QDialog.exec() is always application-modal for this parentless dialog. On
    macOS, AppKit then disables the application menu's Quit item, so Command+Q
    did nothing on Welcome. Nothing else is open yet, so modality protected
    nothing. Quit now closes the dialog as rejected, like Escape or closing
    the window.
    """
    from PySide6.QtCore import QEventLoop
    loop = QEventLoop()
    dialog.finished.connect(loop.quit)
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
    loop.exec()
    return dialog.result()


def launch(core, source):
    from .desktop import qt_application
    from PySide6.QtWidgets import QFileDialog, QDialog, QMessageBox
    qt_application()
    while True:
        dialog = welcome_dialog()
        try:
            if run_welcome(dialog) != QDialog.DialogCode.Accepted:
                return 0
            choice = dialog.selection
            shared = dialog.shared_mode.isChecked()
        finally:
            dialog.deleteLater()
        q06, mode, create = wallet_route(choice)
        shared_profile = None
        if shared:
            if not q06:
                QMessageBox.warning(None, ui_text('welcome.shared_regtest'), ui_text('welcome.shared_needs_bip39'))
                continue
            from .shared_regtest_gui import configure
            shared_profile = configure()
            if shared_profile is None:
                continue
        selected = QFileDialog.getExistingDirectory(
            None,
            (ui_text('welcome.choose_new_folder')
             if create else
             ui_text('welcome.choose_existing_folder')),
        )
        if not selected:
            continue
        try:
            root = selected_profile(Path(selected).absolute(), create)
        except ValueError:
            QMessageBox.warning(
                None, ui_text('welcome.wallet_folder_not_accepted'),
                ui_text('welcome.folder_rejected'),
            )
            continue
        if not q06:
            raise ValueError("LEGACY_Q05_RETIRED")
        from .bip39_owner_gui import launch_bip39_trial
        return launch_bip39_trial(
            root, core, source, mode=mode, authorized=True, shared_profile=shared_profile)
