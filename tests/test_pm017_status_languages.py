"""Status copy transcribed from f189129; no Core/frozen/custody qualification."""
import ast
import copy
import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wam_regtest.presentation.strings import CATALOG, text
from wam_regtest.fusion_status import classify

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / 'tests/pm017_status_english_literals.json').read_text())


def shape(node):
    return ast.dump(node, include_attributes=False)


def facts():
    for snap, locked, operational, faulted, alive, busy, network in itertools.product(
            (None, SimpleNamespace(height=1234567)), (False, True), (False, True),
            (False, True), (None, False, True), (False, True),
            ({}, {'shared': True}, {'peer_count': True}, {'peer_count': '7'},
             {'peer_count': 1234567}, {'peer_count': 0, 'connected': False},
             {'peer_count': 1234567, 'connected': True},
             {'peer_count': 1234567, 'connected': 1})):
        yield dict(snap=snap, locked=locked, operational=operational, faulted=faulted,
                   core_alive=alive, busy=busy, network=network)


class StatusCatalogTests(unittest.TestCase):
    def test_source_shape_and_every_english_result_match_original(self):
        reverse = {shape(ast.parse(r['replacement'], mode='eval').body):
                   ast.parse('(' + r['original'] + ')', mode='eval').body
                   for r in FIXTURE['moved']}

        class Restore(ast.NodeTransformer):
            def visit_ImportFrom(self, node):
                if node.level == 1 and node.module == 'bip39_locale':
                    return None
                return node

            def visit(self, node):
                if shape(node) in reverse:
                    return copy.deepcopy(reverse[shape(node)])
                return super().visit(node)

        restored = ast.fix_missing_locations(Restore().visit(ast.parse(
            (ROOT / 'src/wam_regtest/fusion_status.py').read_text())))
        self.assertEqual(hashlib.sha256(shape(restored).encode()).hexdigest(), FIXTURE['fingerprint'])
        original = {}
        exec(compile(restored, '<f189129-status-fixture>', 'exec'), original)
        with patch('wam_regtest.bip39_locale._lang', return_value='en'):
            for values in facts():
                for kind in ('core', 'chain', 'security', 'network', 'snapshot'):
                    expected = original['classify'](kind, **values)
                    actual = classify(kind, **values)
                    self.assertEqual(tuple(v.encode() for v in actual),
                                     tuple(v.encode() for v in expected), (kind, values))
            with self.assertRaisesRegex(ValueError, '^FUSION_STATUS_KIND_DENIED$'):
                classify('invalid')

    def test_fixture_bytes_parity_placeholders_and_no_dynamic_identifiers(self):
        for record in FIXTURE['moved']:
            self.assertEqual(text(record['key'], 'en').encode(), record['english'].encode())
        for language, entries in CATALOG.items():
            self.assertEqual(set(entries), set(CATALOG['en']), language)
        # Global placeholder/token/secret checks also exercise these keys via
        # test_pm015_languages and test_presentation_strings.
        for key in FIXTURE['new_keys']:
            for language in CATALOG:
                self.assertNotEqual(text(key, language), key)
                if language != 'en':
                    self.assertNotEqual(text(key, language), text(key, 'en'))

    def test_import_is_qt_free_in_fresh_process(self):
        result = subprocess.run(
            [sys.executable, '-c', 'import sys; import wam_regtest.fusion_status; '
             'assert not any(n == "PySide6" or n.startswith("PySide6.") for n in sys.modules)'],
            env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')},
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        tree = ast.parse((ROOT / 'src/wam_regtest/fusion_status.py').read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertFalse((node.module or '').startswith('PySide6'))
            if isinstance(node, ast.Import):
                self.assertFalse(any(a.name.startswith('PySide6') for a in node.names))

    def test_every_branch_resolves_at_call_time_and_preserves_state(self):
        # Import classify before changing locale. Capture all unique resolver
        # paths with the cross product; each key must actually be rendered.
        seen = set()
        from wam_regtest import bip39_locale
        for language in CATALOG:
            def localized(key):
                seen.add(key)
                return text(key, language)
            with patch.object(bip39_locale, 't', side_effect=localized):
                for values in facts():
                    for kind in ('core', 'chain', 'security', 'network', 'snapshot'):
                        state, title, detail = classify(kind, **values)
                        self.assertIn(state, ('unknown', 'pending', 'verified', 'warning', 'error'))
                        self.assertTrue(title)
                        self.assertTrue(detail)
                self.assertEqual(classify('chain', snap=SimpleNamespace(height=1234567))[1],
                                 text('status.height', language).format(height='1234567'))
                self.assertEqual(classify('network', network={'peer_count': 1234567, 'connected': True})[2],
                                 text('status.peers_verified', language).format(peer_count='1234567'))
                self.assertEqual(classify('security', faulted=True),
                                 ('error', text('status.faulted', language),
                                  text('status.reservations_preserved', language)))
        self.assertEqual(seen, set(FIXTURE['new_keys']))

    def test_fault_warning_forbids_all_retry_not_only_automatic_retry(self):
        for language, prohibition in {
            'en': 'Do not retry uncertain payments.',
            'vi': 'Không thử lại các khoản thanh toán chưa rõ kết quả.',
            'ja': '結果が不確実な支払いを再試行しないでください。',
            'zh-Hans': '请勿重试结果不确定的付款。',
        }.items():
            warning = text('status.reservations_preserved', language)
            self.assertIn(prohibition, warning)
            for automatic in ('auto', 'tự động', '自動', '自动'):
                self.assertNotIn(automatic, warning)


class StatusWidgetTests(unittest.TestCase):
    def test_main_overview_cards_and_connection_pill_use_late_locale(self):
        from PySide6.QtCore import QSettings, QThread
        from wam_regtest.desktop import qt_application
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.wallet_executor import ExecutorState
        from wam_regtest.wallet_read import WalletReadSnapshot

        app = qt_application()
        snapshot = WalletReadSnapshot(chain='regtest', height=1234567, tip='ab' * 32,
                                      receive_code='public-test-code', confirmed_atoms=0,
                                      confirmed_utxos=0, history=(), core_sha256='cd' * 32)
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ, {'WAM_UI_SETTINGS_PATH': str(Path(directory) / 'ui.ini')}):
            for language in CATALOG:
                settings = QSettings(os.environ['WAM_UI_SETTINGS_PATH'], QSettings.Format.IniFormat)
                settings.setValue('ui_language', language)
                settings.setValue('fusion_reduce_motion', True)
                settings.sync()
                owner = SimpleNamespace(state=ExecutorState(core_alive=True), busy=False, closed=False)
                # Observe the actual rendering thread, not just a static call site.
                calls = []
                def translated(key):
                    calls.append(QThread.currentThread() == app.thread())
                    return text(key, language)
                with patch('wam_regtest.bip39_locale.t', side_effect=translated):
                    window = Bip39FusionWindow(owner)
                    window._poll.stop()
                    try:
                        window.overview.render_snapshot(snapshot, core_alive=True, operational=True,
                                                        network={'peer_count': 1234567, 'connected': True})
                        for kind in ('core', 'chain', 'security', 'network'):
                            card = getattr(window.overview, kind + '_card')
                            expected = classify(kind, snap=snapshot, core_alive=True, operational=True,
                                                network={'peer_count': 1234567, 'connected': True})
                            self.assertEqual(card.value.text(), expected[1])
                            self.assertEqual(card.detail.text(), expected[2])
                        window._on_denied('WALLET_CORE_UNAVAILABLE')
                        self.assertEqual(window.connection_pill.text(), text('status.core_running', language))
                        self.assertTrue(calls)
                        self.assertTrue(all(calls))
                    finally:
                        window.hide()
                        window.deleteLater()
                        app.processEvents()
