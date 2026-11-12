"""The one place that opens the wallet's UI preference store (W-TEST-01).

UI preferences only: appearance, reduced motion, language and the last
remembered profile *folder path*. Never keys, seeds, passwords or wallet
state, and never part of a wallet profile.

Isolated by default, by construction:
  * Only the shipped production entry points (production_entry,
    windows_production_entry, linux_production_entry) call
    use_native_store() just before launching the wallet. They then use the
    native per-user store QSettings("WAM Privacy Wallet", "REGTEST") exactly as
    before, so the owner's existing preferences are kept. In that mode the
    environment is ignored.
  * Every other process (tests, source runs, the qualification app, probes)
    uses an isolated INI file: WAM_UI_SETTINGS_PATH when set (the frozen
    qualification pipeline sets it), otherwise a private file in a fresh
    temporary directory for this process. Such a process can therefore never
    write the owner's real preferences, however it was invoked.
"""
import os
import tempfile

ORGANIZATION = "WAM Privacy Wallet"
APPLICATION = "REGTEST"
ENV_PATH = "WAM_UI_SETTINGS_PATH"

_native = False
_private_path = None


def use_native_store():
    """Called only by the production entry points, right before launch."""
    global _native
    _native = True


def native_store_enabled():
    return _native


def isolated_path():
    """The INI file used by every non-production process."""
    global _private_path
    path = os.environ.get(ENV_PATH)
    if path:
        return path
    if _private_path is None:
        _private_path = os.path.join(tempfile.mkdtemp(prefix="wam-ui-settings-"), "ui-settings.ini")
    return _private_path


def ui_settings():
    """QSettings for UI preferences: native store in production, isolated INI otherwise."""
    from PySide6.QtCore import QSettings
    if _native:
        return QSettings(ORGANIZATION, APPLICATION)
    return QSettings(isolated_path(), QSettings.Format.IniFormat)
