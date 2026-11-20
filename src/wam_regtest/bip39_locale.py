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

from .presentation.strings import CATALOG, SUPPORTED_LANGUAGES, resolve_language, text

# Tokens the Fusion language picker can select.
_PICKER_CHOICES = ('system',) + SUPPORTED_LANGUAGES

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


def effective_choice(settings=None):
    """Picker token for the language actually in effect.

    A missing ui_language is English in an isolated process and 'system' in
    the native store. _lang resolves this token, so the picker and the UI
    share that one rule. A stored picker token is returned as stored. Any
    other stored value falls back to 'system'.
    """
    if settings is None:
        settings = ui_settings()
    if not native_store_enabled() and not settings.contains("ui_language"):
        return "en"
    value = stored_language(settings)
    if value not in _PICKER_CHOICES:
        return "system"
    return value


def _lang():
    """Catalog language for this process.

    A missing ui_language follows the system locale only when the native
    production store is enabled. Isolated processes use English until a
    value is stored. A stored value, including 'system', is resolved as before.
    """
    return resolve_language(effective_choice(), QLocale.system().name())


class Phrase(str):
    """Localized presentation value retaining its keys and format parameters.

    Formatting and composition keep a recipe, never a wallet/executor action.
    Explicit str() and f-strings discard it; use format/concatenation or
    join_phrases for text that must survive a live language change.
    """

    def __new__(cls, value, key=None, render=None):
        obj = str.__new__(cls, value)
        obj.key = key
        obj._render = render
        return obj

    def translated(self):
        return self._render() if self._render is not None else text(self.key, _lang())

    def format(self, *args, **kwargs):
        def render():
            return self.translated().format(
                *(_translated(value) for value in args),
                **{key: _translated(value) for key, value in kwargs.items()})
        return Phrase(str.format(self, *args, **kwargs), render=render)

    def __add__(self, other):
        if not isinstance(other, str):
            return NotImplemented
        return Phrase(str.__add__(self, other),
                      render=lambda: self.translated() + _translated(other))

    def __radd__(self, other):
        if not isinstance(other, str):
            return NotImplemented
        return Phrase(str.__add__(other, self),
                      render=lambda: _translated(other) + self.translated())


def _translated(value):
    return value.translated() if isinstance(value, Phrase) else value


def join_phrases(separator, values):
    """Join public presentation values without flattening localized children."""
    values = tuple(values)
    return Phrase(separator.join(values), render=lambda: separator.join(
        _translated(value) for value in values))


def t(key):
    """Return the localized string for `key`, falling back to English."""
    return Phrase(text(key, _lang()), key)
