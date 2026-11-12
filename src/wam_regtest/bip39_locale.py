"""Minimal Vietnamese/English localization for the Q06 BIP39 backup UI.

Uses PySide6's system locale when available; falls back to English. This is a
compatibility adapter over the pure presentation catalog.
"""
from PySide6.QtCore import QLocale

from .presentation.strings import CATALOG, text

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


def _lang():
    name = QLocale.system().name().lower()
    return "vi" if name.startswith("vi") else "en"


def t(key):
    """Return the localized string for `key`, falling back to English."""
    return text(key, _lang())
