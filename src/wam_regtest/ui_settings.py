"""The one place that opens the wallet's UI preference store (W-TEST-01).

UI preferences only: appearance, reduced motion, language and the last
remembered profile *folder path*. Never keys, seeds, passwords or wallet
state, and never part of a wallet profile.

The real app uses the native per-user store QSettings("WAM Privacy Wallet",
"REGTEST") exactly as before, so existing preferences are kept.

When WAM_UI_SETTINGS_PATH names a file, that INI file is used instead. The
test runner (tests/sitecustomize.py) and the frozen qualification pipeline
(scripts/build_macos_bundle.sh) set it, so tests and qualification runs can
never overwrite the owner's real preferences. The variable grants no
authority: it only relocates these UI preferences.
"""
import os

ORGANIZATION = "WAM Privacy Wallet"
APPLICATION = "REGTEST"
ENV_PATH = "WAM_UI_SETTINGS_PATH"


def ui_settings():
    """QSettings for UI preferences (native store, or the isolated INI file)."""
    from PySide6.QtCore import QSettings
    path = os.environ.get(ENV_PATH)
    if path:
        return QSettings(path, QSettings.Format.IniFormat)
    return QSettings(ORGANIZATION, APPLICATION)
