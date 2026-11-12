"""PM-014 catalog contracts; literals transcribed from 88eaa41, never imported as expectations."""
import ast
import json
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from wam_regtest.presentation.strings import CATALOG, text

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
                return ast.Constant(catalog[node.args[0].value])
            return self.generic_visit(node)

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


class CatalogTests(unittest.TestCase):
    def test_english_executable_source_matches_baseline(self):
        for module, expected in FIXTURE['source_fingerprints'].items():
            source = (ROOT / 'src/wam_regtest' / (module + '.py')).read_text()
            self.assertEqual(english_source_fingerprint(source, CATALOG['en']), expected, module)

    def test_english_bytes_and_existing_vietnamese(self):
        for lang, entries in FIXTURE['legacy'].items():
            for key, literal in entries.items():
                self.assertEqual(CATALOG[lang][key].encode(), literal.encode(), key)
        for entries in FIXTURE['moved'].values():
            for key, literal in entries.items():
                self.assertEqual(text(key, 'en').encode(), literal.encode(), key)
        for code, literal in FIXTURE['errors'].items():
            self.assertEqual(text('errors.' + code, 'en').encode(), literal.encode())
        expected = set(FIXTURE['legacy']['en']) | {'errors.' + c for c in FIXTURE['errors']}
        for entries in FIXTURE['moved'].values():
            expected.update(entries)
        self.assertEqual(set(CATALOG['en']), expected)

    def test_public_error_mapping_and_codes_unchanged(self):
        from wam_regtest.gui_errors import _MESSAGES, error_text, public_code
        self.assertEqual(_MESSAGES, FIXTURE['errors'])
        for code, literal in FIXTURE['errors'].items():
            self.assertEqual(public_code(code), code)
            self.assertEqual(error_text(code), literal)
        self.assertEqual(public_code('untrusted'), 'WALLET_OPERATION_DENIED_STATE_RETAINED')

    def test_fallbacks_and_compatibility_language_resolution(self):
        from wam_regtest import bip39_locale
        for key, english in CATALOG['en'].items():
            self.assertEqual(text(key, 'ja'), english)
            self.assertEqual(text(key), english)
            self.assertEqual(text(key, 'vi'), CATALOG['vi'].get(key, english))
        self.assertEqual(text('missing.key', 'vi'), 'missing.key')
        for language in ('en', 'vi'):
            with patch.object(bip39_locale, '_lang', return_value=language):
                for key in CATALOG['en']:
                    self.assertEqual(bip39_locale.t(key), text(key, language))

    def test_system_locale_resolution_is_unchanged(self):
        from types import SimpleNamespace
        from wam_regtest import bip39_locale
        for name, language in (('vi_VN', 'vi'), ('VI_vn', 'vi'), ('en_US', 'en'),
                               ('ja_JP', 'en'), ('zh_CN', 'en')):
            with patch.object(bip39_locale.QLocale, 'system',
                              return_value=SimpleNamespace(name=lambda: name)):
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
        for entries in FIXTURE['moved'].values():
            self.assertLessEqual(set(entries), used)

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
        for path in directory.glob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
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
