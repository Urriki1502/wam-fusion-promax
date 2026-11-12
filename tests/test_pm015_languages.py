"""PM-015 language catalogs, persisted choice, and rebuilt Fusion windows."""
import ast
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from wam_regtest.presentation.strings import CATALOG, resolve_language, text

ROOT = Path(__file__).resolve().parents[1]
PROTECTED = re.compile(
    r'WSP-1|SHA-256|BIP352|BIP39|REGTEST|V1-NET|TXID|Q05|Q06|wamrtsp1…|'
    r'\bWAM\b|\bCore\b|\bP2P\b|\bRPC\b|\bUTXO\b|\bQR\b|\bIP\b|\d+(?:\.\d+)?'
)
WORDS = (
    'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon',
    'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'about',
)
TXID = 'ab' * 32


def _placeholders(value):
    return re.findall(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', value)


class LanguageCatalogTests(unittest.TestCase):
    def test_every_language_has_exactly_the_english_keys(self):
        english = set(CATALOG['en'])
        self.assertEqual(set(CATALOG), {'en', 'zh-Hans', 'vi', 'ko', 'id', 'ja'})
        for language, entries in CATALOG.items():
            self.assertEqual(set(entries), english, language)
            self.assertEqual(len(entries), len(english), language)

    def test_placeholders_match_english_for_every_key(self):
        for key, english in CATALOG['en'].items():
            expected = _placeholders(english)
            for language, entries in CATALOG.items():
                self.assertEqual(_placeholders(entries[key]), expected, (language, key))

    def test_protected_tokens_match_english(self):
        for key, english in CATALOG['en'].items():
            expected = PROTECTED.findall(english)
            for language, entries in CATALOG.items():
                self.assertEqual(PROTECTED.findall(entries[key]), expected, (language, key))
                self.assertNotRegex(entries[key], r'(?i)\b[0-9a-f]{64}\b', (language, key))
                self.assertNotRegex(entries[key], r'(?i)\b(?:wamrtsp|bc1)[a-z0-9]{12,}', (language, key))

    def test_locale_modules_import_nothing(self):
        directory = ROOT / 'src/wam_regtest/presentation/locales'
        modules = sorted(path.name for path in directory.glob('*.py'))
        self.assertEqual(modules, ['__init__.py', 'en.py', 'id.py', 'ja.py', 'ko.py', 'vi.py', 'zh_hans.py'])
        for name in modules:
            tree = ast.parse((directory / name).read_text())
            self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(tree)), name)

    def test_resolution_precedence(self):
        self.assertEqual(resolve_language('ja', 'vi_VN'), 'ja')
        self.assertEqual(resolve_language('en', 'ja_JP'), 'en')
        self.assertEqual(resolve_language('zh-Hans', 'en_US'), 'zh-Hans')
        self.assertEqual(resolve_language('vi', 'zh_CN'), 'vi')
        self.assertEqual(resolve_language('ko', 'id_ID'), 'ko')
        self.assertEqual(resolve_language('id', 'ko_KR'), 'id')
        self.assertEqual(resolve_language('en', 'ko_KR'), 'en')
        self.assertEqual(resolve_language('system', 'ja_JP'), 'ja')
        self.assertEqual(resolve_language('system', 'ko_KR'), 'ko')
        self.assertEqual(resolve_language('system', 'ko'), 'ko')
        for name in ('id', 'id_ID', 'id-ID', 'ID_id', 'in', 'in_ID', 'in-ID', 'IN_id'):
            self.assertEqual(resolve_language('system', name), 'id', name)
        self.assertEqual(resolve_language('nope', 'ko_KR'), 'ko')
        self.assertEqual(resolve_language('nope', 'in_ID'), 'id')
        for name in ('zh', 'zh_Hans', 'zh-Hans', 'zh_CN', 'zh-CN', 'zh_SG',
                     'zh-SG', 'zh_Hans_CN', 'zh-Hans-SG'):
            self.assertEqual(resolve_language('system', name), 'zh-Hans', name)
        for name in ('zh_Hant', 'zh-Hant', 'zh_TW', 'zh-TW', 'zh_HK', 'zh-HK',
                     'zh_MO', 'zh-MO', 'zh_Hant_TW', 'zh-Hant-HK'):
            self.assertEqual(resolve_language('system', name), 'en', name)
        self.assertEqual(resolve_language('system', 'vi_VN'), 'vi')
        for name, language in (
                ('kok_IN', 'en'), ('inh_RU', 'en'), ('jam_JM', 'en'),
                ('ko', 'ko'), ('in', 'id'), ('id_ID', 'id'), ('vi', 'vi')):
            self.assertEqual(resolve_language('system', name), language, name)
        self.assertEqual(resolve_language('system', 'fr_FR'), 'en')
        self.assertEqual(resolve_language('system', 'C'), 'en')
        self.assertEqual(resolve_language(None, ''), 'en')
        self.assertEqual(resolve_language('nope', 'ja_JP'), 'ja')
        self.assertEqual(text('fusion.overview', 'ja'), '概要')
        self.assertEqual(text('fusion.overview', 'ko'), '개요')
        self.assertEqual(text('fusion.overview', 'id'), 'Ringkasan')
        self.assertEqual(text('fusion.overview', 'de'), 'Overview')

    def test_korean_block_confirm_stays_distinct_from_payment_approval(self):
        block = CATALOG['ko']['owner.confirm_block']
        title = CATALOG['ko']['owner.confirm_title']
        self.assertEqual(block, '1 REGTEST 블록을 확인')
        self.assertIn('확인', block)
        self.assertNotIn('승인', block)
        self.assertIn('확인', title)
        self.assertNotIn('승인', title)
        self.assertEqual(CATALOG['ko']['pages.approve'], '승인')
        self.assertNotIn('확인', CATALOG['ko']['pages.approve'])
        self.assertIn('승인', CATALOG['ko']['pages.approve_signature'])
        self.assertIn(block, CATALOG['ko']['owner.awaiting_confirmation'])

    def test_security_review_manifest_exists_in_every_language(self):
        manifest = json.loads((ROOT / 'tests/l10n_security_review_keys.json').read_text())
        self.assertEqual(manifest['review_status'], 'pending native review')
        self.assertEqual(
            manifest['pending_native_review'],
            ['vi', 'ja', 'zh-Hans', 'ko', 'id'])
        self.assertIn('not a review receipt', manifest['note'].lower())
        items = manifest['keys']
        keys = [item['key'] for item in items]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertGreaterEqual(len(keys), 100)
        for item in items:
            self.assertTrue(item['reason'].strip())
            for language in ('en', 'zh-Hans', 'vi', 'ko', 'id', 'ja'):
                self.assertIn(item['key'], CATALOG[language])

    def test_automatic_wording_is_not_by_oneself(self):
        for key, english in CATALOG['en'].items():
            lowered = english.lower()
            if 'automatic' not in lowered and 'auto-' not in lowered:
                continue
            self.assertIn('tự động', CATALOG['vi'][key].lower(), key)
            self.assertIn('自動', CATALOG['ja'][key], key)
            self.assertIn('自动', CATALOG['zh-Hans'][key], key)
            self.assertIn('자동', CATALOG['ko'][key], key)
            self.assertIn('otomatis', CATALOG['id'][key].lower(), key)

    def test_persisted_choice_round_trip_uses_an_isolated_file(self):
        from PySide6.QtCore import QSettings
        from wam_regtest.bip39_locale import stored_language
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'regtest.ini')
            settings = QSettings(path, QSettings.Format.IniFormat)
            settings.setValue('ui_language', 'zh-Hans')
            settings.sync()
            again = QSettings(path, QSettings.Format.IniFormat)
            self.assertEqual(stored_language(again), 'zh-Hans')
            self.assertEqual(resolve_language(stored_language(again), 'en_US'), 'zh-Hans')
            settings.setValue('ui_language', 'system')
            settings.sync()
            reread = QSettings(path, QSettings.Format.IniFormat)
            self.assertEqual(resolve_language(stored_language(reread), 'ja_JP'), 'ja')
            empty = QSettings(str(Path(tmp) / 'empty.ini'), QSettings.Format.IniFormat)
            self.assertEqual(stored_language(empty), 'system')


class FusionLanguageWindowTests(unittest.TestCase):
    def setUp(self):
        from PySide6.QtCore import QSettings as RealQSettings
        from wam_regtest import bip39_fusion_gui, bip39_locale
        from wam_regtest.desktop import qt_application
        self.qt_application = qt_application
        self.gui = bip39_fusion_gui
        self.locale = bip39_locale
        self.real_settings = RealQSettings
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / 'regtest.ini')
        real = RealQSettings

        def factory(*args, **kwargs):
            if args[:2] == ('WAM Privacy Wallet', 'REGTEST'):
                return real(self.path, real.Format.IniFormat)
            return real(*args, **kwargs)

        self.factory = factory
        self.qt_application()

    def _window(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.wallet_executor import ExecutorState
        window = Bip39FusionWindow(SimpleNamespace(state=ExecutorState(), busy=False, closed=False))
        window._poll.stop()
        self.addCleanup(window.deleteLater)
        return window

    def test_rebuilt_window_uses_each_language_without_translating_words_or_txid(self):
        from PySide6.QtWidgets import QLabel
        from wam_regtest.wallet_read import HistoryRow, WalletReadSnapshot
        snapshot = WalletReadSnapshot(
            chain='regtest', height=4, tip='cd' * 32, receive_code='',
            confirmed_atoms=100_000_000, confirmed_utxos=1,
            history=(HistoryRow(TXID, 3, 2, 100_000_000, 0),),
            core_sha256='ef' * 32, history_complete=True, receive_count=1)
        # PM-016: every UI preference goes through ui_settings(); point it at this test's INI.
        with patch.dict(os.environ, {'WAM_UI_SETTINGS_PATH': self.path}):
            first = self.real_settings(self.path, self.real_settings.Format.IniFormat)
            first.setValue('ui_language', 'en')
            first.sync()
            window = self._window()
            self.assertEqual(window.navigation.item(0).text(), 'Overview')
            window.language.setCurrentIndex(window.language.findData('ja'))
            self.assertEqual(window.navigation.item(0).text(), 'Overview')
            for language in ('vi', 'ja', 'zh-Hans', 'ko', 'id'):
                with self.subTest(language=language):
                    window.language.setCurrentIndex(window.language.findData(language))
                    rebuilt = self._window()
                    self.assertEqual(rebuilt.navigation.item(0).text(), text('fusion.overview', language))
                    self.assertNotEqual(rebuilt.navigation.item(0).text(), 'Overview')
                    self.assertEqual(rebuilt.language.currentData(), language)
                    rebuilt.backup_page.set_phrase(WORDS)
                    shown = []
                    for index in range(rebuilt.backup_page._grid.count()):
                        card = rebuilt.backup_page._grid.itemAt(index).widget()
                        shown.append(card.findChild(QLabel, 'FusionCardValue').text())
                    self.assertEqual(shown, list(WORDS))
                    rebuilt.history_page.render_snapshot(snapshot)
                    rebuilt.history_page.table.selectRow(0)
                    self.assertEqual(rebuilt.history_page.detail_id.text(), TXID)
                    self.assertIn('1.00000000', rebuilt.history_page.detail_values.text())
                    self.assertNotIn(TXID, rebuilt.history_page.detail_values.text())
                    self.assertEqual(rebuilt.history_page.table.item(0, 1).toolTip(), TXID)
                    window = rebuilt
