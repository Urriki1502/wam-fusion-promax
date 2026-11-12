"""UI language adapter over the presentation catalog.

An explicit ui_language value in the UI preference store wins, including
'system'. When the key is missing, the native production store follows the
Qt locale and every other process uses English. The primary language
subtag vi, ja, or ko selects that catalog. The primary subtag id, or the
legacy Indonesian subtag in, selects Indonesian. Simplified Chinese is
selected only for zh, zh-Hans, zh-CN, zh-SG, and zh_Hans* names; Traditional
and other Chinese locales use English.
This does not select the BIP39 wordlist language.
"""
from PySide6.QtCore import QLocale

from .ui_settings import native_store_enabled, ui_settings

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
    """Persisted UI language token. A missing or empty value is 'system'."""
    if settings is None:
        settings = ui_settings()
    value = settings.value("ui_language", "system")
    return value if type(value) is str and value else "system"


def _lang():
    """Catalog language for this process.

    A missing ui_language follows the system locale only when the native
    production store is enabled. Isolated processes use English until a
    value is stored. A stored value, including 'system', is resolved as before.
    """
    settings = ui_settings()
    if not native_store_enabled() and not settings.contains("ui_language"):
        return "en"
    return resolve_language(stored_language(settings), QLocale.system().name())


def t(key):
    """Return the localized string for `key`, falling back to English."""
    return text(key, _lang())
