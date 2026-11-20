"""V1 Welcome is BIP39 create, open, and restore only.

Q05 files are not opened and are not migrated. No new wallet owner, seed
conversion, backup import, Core/GUI signing authority or automatic recovery.
The welcome screen only chooses an explicit route. Every actual profile is
authenticated by its existing native owner.
"""
from .bip39_locale import t as ui_text
import os
from pathlib import Path
import re
import secrets
import stat


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


class LegacyQ05InspectionError(ValueError):
    """Typed fail-closed error when Q05 layout preflight cannot be verified."""


_Q05_ROOT_EXACT = ("supervisor.wallet",)
_Q05_ROOT_PREFIXES = ("supervisor.recovery.",)
_Q05_CHAIN_EXACT = (
    "wallet-vault",
    "wallet-runtime.sqlite",
    "wallet-runtime.sqlite-journal",
    "wallet-runtime.sqlite-wal",
    "wallet-runtime.sqlite-shm",
    "wallet-runtime.sqlite.scan.lock",
)
_Q05_CHAIN_PREFIXES = ("wallet-recovery-",)


def _entry_exists_nofollow(path):
    """Conservative lstat check: any entry (dir, file, symlink, dangling link) is present.

    Returns False ONLY on FileNotFoundError (ENOENT). Any other OSError
    (permission, I/O, ENOTDIR, ELOOP) fails closed with LegacyQ05InspectionError.
    """
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise LegacyQ05InspectionError("LEGACY_Q05_PREFLIGHT_UNVERIFIED") from None
    return True


def _scan_dir_for_markers(directory, exact_names, prefixes):
    """Inspect a real directory without following symlinks for Q05 markers."""
    for name in exact_names:
        if _entry_exists_nofollow(directory / name):
            return True
    fd = None
    try:
        if hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"):
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(directory, flags)
            with os.scandir(fd) as entries:
                for entry in entries:
                    if entry.name in exact_names or entry.name.startswith(prefixes):
                        return True
        else:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name in exact_names or entry.name.startswith(prefixes):
                        return True
    except OSError:
        raise LegacyQ05InspectionError("LEGACY_Q05_PREFLIGHT_UNVERIFIED") from None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    return False


def inspect_legacy_q05_layout(directory):
    """Read-only conservative no-follow preflight for Q05 supervisor markers.

    Returns 'legacy' if any Q05 marker exists in any form (dir, file, symlink,
    or dangling symlink), 'absent' if the directory is missing or verified free
    of Q05 markers, and raises LegacyQ05InspectionError on any inspection error
    or symlinked/non-directory root or chain path.
    """
    if not isinstance(directory, (str, os.PathLike)):
        raise LegacyQ05InspectionError("LEGACY_Q05_PREFLIGHT_UNVERIFIED")
    directory = Path(directory)
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return "absent"
    except OSError:
        raise LegacyQ05InspectionError("LEGACY_Q05_PREFLIGHT_UNVERIFIED") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise LegacyQ05InspectionError("LEGACY_Q05_PREFLIGHT_UNVERIFIED")
    if _scan_dir_for_markers(directory, _Q05_ROOT_EXACT, _Q05_ROOT_PREFIXES):
        return "legacy"
    chain = directory / "chain"
    try:
        chain_info = chain.lstat()
    except FileNotFoundError:
        return "absent"
    except OSError:
        raise LegacyQ05InspectionError("LEGACY_Q05_PREFLIGHT_UNVERIFIED") from None
    if stat.S_ISLNK(chain_info.st_mode) or not stat.S_ISDIR(chain_info.st_mode):
        raise LegacyQ05InspectionError("LEGACY_Q05_PREFLIGHT_UNVERIFIED")
    if _scan_dir_for_markers(chain, _Q05_CHAIN_EXACT, _Q05_CHAIN_PREFIXES):
        return "legacy"
    return "absent"


def legacy_q05_layout(directory):
    """Return True iff Q05 markers exist; raise LegacyQ05InspectionError on errors."""
    return inspect_legacy_q05_layout(directory) == "legacy"


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
    from PySide6.QtGui import QPixmap
    from .branding import brand_image
    from PySide6.QtWidgets import (
        QApplication, QDialog, QFrame, QVBoxLayout,
        QScrollArea, QWidget, QToolButton,
    )
    from .fusion_i18n import I18nCheckBox, bind, retranslate_tree
    from .fusion_ui import action, label, panel, fusion_palette, fusion_stylesheet, vector_icon

    dialog = QDialog()
    dialog.setObjectName("WAMFusionWelcome")
    dialog.setWindowTitle(ui_text('welcome.wam_fusion_privacy_wallet'))
    bind(dialog, window_title='welcome.wam_fusion_privacy_wallet')
    dialog.setMinimumSize(540, 550)
    # Not modal: see run_welcome(). It is the only window while it is shown.
    dialog.setWindowModality(Qt.WindowModality.NonModal)
    dialog.selection = None
    dialog.buttons = {}
    hint = QApplication.styleHints()
    from .ui_settings import ui_settings
    choice = ui_settings().value('fusion_appearance', 2, type=int)
    mode = ('dark' if choice == 2 else 'light' if choice == 1 else
            'dark' if hint.colorScheme() == Qt.ColorScheme.Dark else 'light')
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
    logo = label('')
    logo.setPixmap(QPixmap(str(brand_image())).scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
    root.addWidget(logo, alignment=Qt.AlignmentFlag.AlignHCenter)
    root.addWidget(label(ui_text('wallet.brand'), 'BrandTitle'))
    root.addWidget(label(ui_text('welcome.welcome_to_your_wallet'), "PageTitle"))
    root.addWidget(label(ui_text('welcome.regtest_preview_no_real_funds'), "FusionBadge"))
    dialog.shared_mode = I18nCheckBox(ui_text('welcome.shared_regtest_manual_core_p2p'))
    dialog.shared_mode.setAccessibleName(ui_text('welcome.shared_regtest_manual_core_p2p'))
    dialog.shared_mode.setToolTip(ui_text('welcome.shared_tooltip'))
    advanced_network = QToolButton()
    bind(advanced_network, text=ui_text('wallet.advanced_title'), accessible_name=ui_text('wallet.advanced_title'))
    advanced_network.setCheckable(True)
    dialog.shared_mode.hide()
    advanced_network.toggled.connect(dialog.shared_mode.setVisible)
    root.addWidget(advanced_network)
    root.addWidget(dialog.shared_mode)

    choices, layout = panel(
        ui_text('welcome.your_wallet'),
        '',
    )
    for key, title, detail, icon_name, primary in (
        ("create", ui_text('welcome.create_a_new_wallet'),
         '', "overview", True),
        ("open", ui_text('welcome.open_existing_wallet'),
         '', "unlock", False),
        ("restore", ui_text('welcome.restore_from_12_words'),
         '', "backup", False),
    ):
        button = action(title, icon_name, primary)
        button.setAccessibleName(title)
        button.setMinimumHeight(48)
        button.setIcon(vector_icon(
            icon_name, palette["onaccent"] if primary else palette["accent"]))
        dialog.buttons[key] = button
        layout.addWidget(button)
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

    def retranslate():
        retranslate_tree(dialog)

    dialog.retranslate = retranslate
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
        chosen = Path(selected).absolute()
        try:
            if mode in ("reopen", "restore") and legacy_q05_layout(chosen):
                QMessageBox.warning(
                    None, ui_text("welcome.wallet_folder_not_accepted"),
                    ui_text("welcome.legacy_q05_preserved"))
                continue
            root = selected_profile(chosen, create)
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
