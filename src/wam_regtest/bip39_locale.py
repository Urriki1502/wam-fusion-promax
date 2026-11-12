"""UI language adapter over the presentation catalog.

System default follows the Qt locale: vi and ja prefixes select those
catalogs. Simplified Chinese is selected only for zh, zh-Hans, zh-CN, zh-SG,
and zh_Hans* names; Traditional and other Chinese locales use English. An
explicit ui_language value in
QSettings("WAM Privacy Wallet", "REGTEST") wins. This does not select the
BIP39 wordlist language.
"""
from PySide6.QtCore import QLocale, QSettings

from .presentation.strings import CATALOG, resolve_language, text

# Compatibility views of the original Q06 table, not a second copy catalog.
_LEGACY_KEYS = ('app_name',
 'regtest_preview',
 'backup_title',
 'backup_subtitle',
 'backup_warning',
 'phrase_grid_title',
 'word_label',
 'back_up_now',
 'back_up_later',
 'written_checkbox',
 'verify_title',
 'verify_subtitle',
 'verify_prompt',
 'verify',
 'verify_error',
 'verify_unavailable',
 'success_title',
 'success_subtitle',
 'continue',
 'locked_title',
 'locked_subtitle',
 'close_to_lock',
 'ok',
 'cancel',
 'recovery_verify_kicker',
 'recovery_verify_title',
 'recovery_verify_subtitle',
 'recovery_readonly_notice',
 'recovery_paste_words',
 'recovery_clear_words',
 'recovery_verify_phrase',
 'recovery_cancel',
 'recovery_word_position',
 'recovery_word_count',
 'recovery_invalid',
 'backup_flow_kicker',
 'confirm_title',
 'confirm_subtitle',
 'verify_backup',
 'backup_back',
 'backup_step_progress',
 'backup_privacy_note',
 'leave_backup_title',
 'leave_backup_message',
 'leave_backup_stay',
 'leave_backup_confirm')
_STRINGS = {lang: {key: entries[key] for key in _LEGACY_KEYS if key in entries}
            for lang, entries in CATALOG.items()}


def stored_language(settings=None):
    """Persisted UI language. A missing value means the system locale."""
    if settings is None:
        settings = QSettings("WAM Privacy Wallet", "REGTEST")
    value = settings.value("ui_language", "system")
    return value if type(value) is str and value else "system"


def _lang():
    return resolve_language(stored_language(), QLocale.system().name())


def t(key):
    """Return the localized string for `key`, falling back to English."""
    return text(key, _lang())
