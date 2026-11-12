"""UI copy lookup. Language tables are data modules; this module does not import Qt.

``None`` or an unknown language selects English. A missing key is returned
unchanged. Callers format named placeholders. Seed words, addresses, TXIDs,
hashes, amounts and public error codes are not translated here.
"""
from wam_regtest.presentation.locales.en import EN
from wam_regtest.presentation.locales.ja import JA
from wam_regtest.presentation.locales.vi import VI
from wam_regtest.presentation.locales.zh_hans import ZH_HANS

SUPPORTED_LANGUAGES = ('en', 'vi', 'ja', 'zh-Hans')
SYSTEM_LANGUAGE = 'system'

CATALOG = {
    'en': EN,
    'vi': VI,
    'ja': JA,
    'zh-Hans': ZH_HANS,
}


_SIMPLIFIED_CHINESE = frozenset({'zh', 'zh_hans', 'zh_cn', 'zh_sg'})


def resolve_language(choice, system_name=''):
    """Explicit choice, then a supported system locale, then English.

    Simplified Chinese is selected for ``zh``, ``zh-Hans``, ``zh-CN``,
    ``zh-SG``, and any ``zh_Hans*`` name. Traditional and other Chinese
    locales fall back to English.
    """
    if choice in SUPPORTED_LANGUAGES:
        return choice
    name = (system_name or '').lower().replace('-', '_')
    if name.startswith('vi'):
        return 'vi'
    if name.startswith('ja'):
        return 'ja'
    if name in _SIMPLIFIED_CHINESE or name.startswith('zh_hans'):
        return 'zh-Hans'
    return 'en'


def text(key, lang=None):
    """Look up UI copy without translating identifiers or formatting values."""
    return CATALOG.get(lang, {}).get(key, CATALOG['en'].get(key, key))
