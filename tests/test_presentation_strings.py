"""PM-014 catalog contracts; literals transcribed from 88eaa41, never imported as expectations."""
import ast
import json
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from wam_regtest.presentation.strings import CATALOG, text

# PM-015 replaced truncated sentence slugs. Fixture bytes stay the PM-014
# English sentences; named placeholders canonicalise back to value_N.
KEY_RENAMES = json.loads((Path(__file__).resolve().parent / 'pm015_key_renames.json').read_text())['renames']
STABLE_PLACEHOLDERS = {'position', 'entered', 'step', 'total'}
SETTINGS_KEYS = {'settings.language', 'settings.language_system', 'settings.language_next_window'}


def canonical_placeholders(value):
    index = 0

    def repl(match):
        nonlocal index
        name = match.group(1)
        if name in STABLE_PLACEHOLDERS or re.fullmatch(r'value_\d+', name):
            return match.group(0)
        index += 1
        return '{value_%d}' % index

    return re.sub(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', repl, value)


def pm014_key(key):
    return KEY_RENAMES.get(key, key)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / 'tests/pm014_english_literals.json').read_text())
MODULES = ('bip39_locale', 'gui_errors', 'managed_onboarding', 'fusion_ui', 'fusion_pages')


def english_source_fingerprint(source, catalog):
    """Compare executable AST after resolving copy and normalizing f-strings.

    Expected hashes were captured from git show 88eaa41:<module>, before edits.
    This also detects accidental changes to routing, amounts and identifiers.
    """
    import hashlib

    class Normalize(ast.NodeTransformer):
        def visit_ImportFrom(self, node):
            if node.module == 'bip39_locale' and any(a.asname == 'ui_text' for a in node.names):
                return None
            if node.module == 'presentation.strings' and [a.name for a in node.names] == ['CATALOG']:
                return None
            return node

        def visit_Subscript(self, node):
            if (isinstance(node.value, ast.Subscript)
                    and isinstance(node.value.value, ast.Name)
                    and node.value.value.id == 'CATALOG'
                    and isinstance(node.value.slice, ast.Constant)
                    and node.value.slice.value == 'en'):
                return ast.Constant(catalog[node.slice.value])
            return self.generic_visit(node)

        def visit_FunctionDef(self, node):
            # Late lookup is covered by test_pm014_lazy_locale. Compare the
            # original English executable shape without replacing its hashes.
            if node.name == 'fusion_nav_pages':
                return None
            if (node.name == 'page' and len(node.args.defaults) == 1
                    and isinstance(node.args.defaults[0], ast.Constant)
                    and node.args.defaults[0].value is None):
                guard = node.body[0]
                assert ast.dump(guard.test) == ast.dump(ast.parse('kicker is None', mode='eval').body)
                assert ast.dump(guard.body[0]) == ast.dump(ast.parse(
                    "kicker = ui_text('fusion.wam_fusion_regtest')").body[0])
                node.args.defaults = [guard.body[0].value]
                node.body = node.body[1:]
            return self.generic_visit(node)

        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id == 'fusion_nav_pages':
                return ast.Name(id='FUSION_NAV_PAGES', ctx=ast.Load())
            if isinstance(node.func, ast.Name) and node.func.id == 'ui_text':
                return ast.Constant(canonical_placeholders(catalog[node.args[0].value]))
            node = self.generic_visit(node)
            if (isinstance(node.func, ast.Attribute) and node.func.attr == 'format'
                    and isinstance(node.func.value, ast.Constant)
                    and isinstance(node.func.value.value, str)
                    and '{value_' in node.func.value.value):
                number = 0
                for keyword in node.keywords:
                    if keyword.arg in STABLE_PLACEHOLDERS or re.fullmatch(r'value_\d+', keyword.arg or ''):
                        continue
                    number += 1
                    keyword.arg = 'value_%d' % number
            return node

        def visit_JoinedStr(self, node):
            template, values = '', []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    template += value.value.replace('{', '{{').replace('}', '}}')
                else:
                    name = 'value_' + str(len(values) + 1)
                    spec = '' if value.conversion == -1 else '!' + chr(value.conversion)
                    if value.format_spec:
                        spec += ':' + ''.join(v.value for v in value.format_spec.values)
                    template += '{' + name + spec + '}'
                    values.append(ast.keyword(arg=name, value=self.visit(value.value)))
            return ast.Call(func=ast.Attribute(value=ast.Constant(template), attr='format', ctx=ast.Load()),
                            args=[], keywords=values)

    canonical = ast.dump(Normalize().visit(ast.parse(source)), include_attributes=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _proven_source(module):
    """Module text the PM-014 English-source proof applies to (PM-026).

    The proof certifies that a module's English output equals the pre-catalog
    baseline. It is anchored to the git blob on which it held, verified by
    SHA-256, so a later edit of the live module neither freezes nor voids it.
    The live file is used while it still matches. Without git history the
    proof is skipped, never passed.
    """
    import hashlib
    import subprocess
    record = FIXTURE['source_proven'][module]
    current = (ROOT / 'src/wam_regtest' / (module + '.py')).read_bytes()
    if hashlib.sha256(current).hexdigest() == record['proven_source_sha256']:
        return current.decode()
    try:
        proven = subprocess.run(['git', '-C', str(ROOT), 'cat-file', '-p', record['proven_blob']],
                                capture_output=True, check=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        raise unittest.SkipTest('PM-014 proof blob %s not available' % record['proven_blob'][:12])
    if hashlib.sha256(proven).hexdigest() != record['proven_source_sha256']:
        raise AssertionError('PM-014 proof blob content changed: ' + module)
    return proven.decode()


class CatalogTests(unittest.TestCase):
    def test_english_executable_source_matches_baseline(self):
        self.assertEqual(set(FIXTURE['source_proven']), set(FIXTURE['source_fingerprints']))
        for module, expected in FIXTURE['source_fingerprints'].items():
            with self.subTest(module=module):
                source = _proven_source(module)
                self.assertEqual(english_source_fingerprint(source, CATALOG['en']), expected, module)

    def test_english_bytes_and_existing_vietnamese(self):
        for lang, entries in FIXTURE['legacy'].items():
            for key, literal in entries.items():
                self.assertEqual(canonical_placeholders(CATALOG[lang][pm014_key(key)]).encode(), literal.encode(), key)
        for entries in FIXTURE['moved'].values():
            for key, literal in entries.items():
                self.assertEqual(canonical_placeholders(text(pm014_key(key), 'en')).encode(), literal.encode(), key)
        for code, literal in FIXTURE['errors'].items():
            self.assertEqual(text('errors.' + code, 'en').encode(), literal.encode())
        expected = {pm014_key(key) for key in FIXTURE['legacy']['en']}
        expected.update('errors.' + code for code in FIXTURE['errors'])
        for entries in FIXTURE['moved'].values():
            expected.update(pm014_key(key) for key in entries)
        # PM-017 additions have their own source-transcribed English fixture.
        pm017_keys = set(json.loads((ROOT / 'tests/pm017_english_literals.json').read_text())['new_keys'])
        status_keys = set(json.loads((ROOT / 'tests/pm017_status_english_literals.json').read_text())['new_keys'])
        pm018_keys = set(json.loads((ROOT / 'tests/pm018_english_literals.json').read_text())['new_keys'])
        pm021 = json.loads((ROOT / 'tests/pm021_english_literals.json').read_text())
        for key, literal in pm021['english'].items():
            self.assertEqual(text(key, 'en').encode(), literal.encode(), key)
        fe002 = json.loads((ROOT / 'tests/fe002_english_literals.json').read_text())
        for key, literal in fe002['english'].items():
            self.assertEqual(text(key, 'en').encode(), literal.encode(), key)
        pm041 = json.loads((ROOT / 'tests/pm041_english_literals.json').read_text())
        for key, literal in pm041['english'].items():
            self.assertEqual(text(key, 'en').encode(), literal.encode(), key)
        fe003 = json.loads((ROOT / 'tests/fe003_english_literals.json').read_text())
        for key, literal in fe003['english'].items():
            self.assertEqual(text(key, 'en').encode(), literal.encode(), key)
        self.assertEqual(set(CATALOG['en']) - SETTINGS_KEYS,
                         expected | pm017_keys | status_keys | pm018_keys
                         | set(pm021['english']) | set(fe002['english']) | set(pm041['english'])
                         | set(fe003['english']))

    def test_public_error_mapping_and_codes_unchanged(self):
        from wam_regtest.gui_errors import _MESSAGES, error_text, public_code
        fe003 = json.loads((ROOT / 'tests/fe003_english_literals.json').read_text())
        additions = {key.removeprefix('errors.'): value
                     for key, value in fe003['english'].items() if key.startswith('errors.')}
        self.assertEqual(_MESSAGES, FIXTURE['errors'] | additions)
        for code, literal in FIXTURE['errors'].items():
            self.assertEqual(public_code(code), code)
            self.assertEqual(error_text(code), literal)
        self.assertEqual(public_code('untrusted'), 'WALLET_OPERATION_DENIED_STATE_RETAINED')

    def test_fallbacks_and_compatibility_language_resolution(self):
        from wam_regtest import bip39_locale
        for key, english in CATALOG['en'].items():
            self.assertEqual(text(key, 'de'), english)
            self.assertEqual(text(key), english)
            for language in ('vi', 'ja', 'zh-Hans', 'ko', 'id'):
                self.assertEqual(text(key, language), CATALOG[language][key])
        self.assertEqual(text('missing.key', 'vi'), 'missing.key')
        for language in ('en', 'zh-Hans', 'vi', 'ko', 'id', 'ja'):
            with patch.object(bip39_locale, '_lang', return_value=language):
                for key in CATALOG['en']:
                    self.assertEqual(bip39_locale.t(key), text(key, language))

    def test_system_locale_resolution_follows_prefix(self):
        import tempfile
        from types import SimpleNamespace
        from PySide6.QtCore import QSettings
        from wam_regtest import bip39_locale
        # PM-020: an isolated process resolves the system locale only when
        # 'system' is stored. A missing key is English, so this subtag matrix
        # stores that choice explicitly.
        with tempfile.TemporaryDirectory() as tmp:
            settings = QSettings(str(Path(tmp) / 'ui.ini'), QSettings.Format.IniFormat)
            settings.setValue('ui_language', 'system')
            for name, language in (('vi_VN', 'vi'), ('VI_vn', 'vi'), ('en_US', 'en'),
                                   ('ja_JP', 'ja'), ('zh_CN', 'zh-Hans'), ('zh_Hans_CN', 'zh-Hans'),
                                   ('zh_SG', 'zh-Hans'), ('zh', 'zh-Hans'), ('zh_TW', 'en'),
                                   ('zh_HK', 'en'), ('zh_MO', 'en'), ('zh_Hant', 'en'),
                                   ('ko_KR', 'ko'), ('ko', 'ko'), ('id_ID', 'id'), ('in_ID', 'id'),
                                   ('in', 'id'), ('vi', 'vi'),
                                   ('kok_IN', 'en'), ('inh_RU', 'en'), ('jam_JM', 'en'),
                                   ('C', 'en'), ('fr_FR', 'en')):
                with patch.object(bip39_locale, 'ui_settings', return_value=settings), \
                        patch.object(bip39_locale.QLocale, 'system',
                                     return_value=SimpleNamespace(name=lambda n=name: n)):
                    self.assertEqual(bip39_locale._lang(), language)
                    self.assertEqual(bip39_locale.t('backup_title'), text('backup_title', language))

    def test_used_key_coverage(self):
        used = set()
        for name in MODULES:
            tree = ast.parse((ROOT / 'src/wam_regtest' / (name + '.py')).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'ui_text':
                    if name == 'gui_errors':
                        self.assertIsInstance(node.args[0], ast.BinOp)
                        continue
                    self.assertIsInstance(node.args[0], ast.Constant)
                    key = node.args[0].value
                    self.assertIn(key, CATALOG['en'])
                    used.add(key)
        inverse = {new: old for old, new in KEY_RENAMES.items()}
        used_pm014 = {inverse.get(key, key) for key in used}
        for entries in FIXTURE['moved'].values():
            self.assertLessEqual(set(entries), used_pm014)

    def test_catalog_contains_copy_only(self):
        for language, entries in CATALOG.items():
            self.assertLessEqual(set(entries), set(CATALOG['en']), language)
            for key, value in entries.items():
                self.assertIsInstance(value, str)
                self.assertNotRegex(value, r'(?i)\b[0-9a-f]{64}\b', key)
                # Full payloads only: instructional '(wamrtsp1…)' is preserved English copy.
                self.assertNotRegex(value, r'(?i)\b(?:wamrtsp|bc1)[a-z0-9]{12,}', key)
        # A phrase/list of BIP39 words must not become UI copy.
        from mnemonic import Mnemonic
        words = set(Mnemonic('english').wordlist)
        for entries in CATALOG.values():
            for value in entries.values():
                tokens = value.split()
                self.assertFalse(len(tokens) >= 12 and all(t in words for t in tokens), value)

    def test_pure_presentation_import_boundary(self):
        directory = ROOT / 'src/wam_regtest/presentation'
        locale_modules = {
            'wam_regtest.presentation.locales.en',
            'wam_regtest.presentation.locales.vi',
            'wam_regtest.presentation.locales.ja',
            'wam_regtest.presentation.locales.zh_hans',
            'wam_regtest.presentation.locales.ko',
            'wam_regtest.presentation.locales.id',
        }
        for path in directory.rglob('*.py'):
            rel = path.relative_to(directory).as_posix()
            imports = [node for node in ast.walk(ast.parse(path.read_text()))
                       if isinstance(node, (ast.Import, ast.ImportFrom))]
            if rel.startswith('locales/'):
                self.assertEqual(imports, [], rel)
                continue
            if rel == 'strings.py':
                for node in imports:
                    self.assertIsInstance(node, ast.ImportFrom, rel)
                    self.assertEqual(node.level, 0, rel)
                    self.assertIn(node.module, locale_modules, rel)
                continue
            for node in imports:
                if isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    self.assertFalse(module.startswith('PySide6'))
                    if node.level or module.startswith('wam_regtest'):
                        self.assertTrue(module == 'foundation' or module.startswith(('foundation.', 'wam_regtest.foundation')), (path, module))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(alias.name.startswith('PySide6'))
                        if alias.name.startswith('wam_regtest'):
                            self.assertTrue(alias.name.startswith('wam_regtest.foundation.'), (path, alias.name))
