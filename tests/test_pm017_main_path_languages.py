"""PM-017 main-path copy; expectations transcribed from f189129, before catalog edits.

Real Qt widgets with an inert executor: these checks grant no Core/frozen or
custody acceptance. Every preference write targets a temporary INI file.
"""
import ast
import copy
import hashlib
import json
import os
import re
import string
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from wam_regtest.presentation.strings import CATALOG, text

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / 'tests/pm017_english_literals.json').read_text())
PM043 = json.loads((ROOT / 'tests/pm043_copy_ledger.json').read_text())
PM045 = json.loads((ROOT / 'tests/pm045_copy_ledger.json').read_text())


def shape(node):
    return ast.dump(node, include_attributes=False)


def _proven_source(module, data):
    """The module text the PM-017 structural proof applies to.

    The proof is "the PM-017 revision equals f189129 with only the recorded
    string moves". It is anchored to that exact revision (FIXTURE['proven_at'],
    pinned by SHA-256), so later legitimate edits of the module do not void it
    and are not frozen by it. The current file is used while it is unchanged;
    otherwise the pinned revision is read from git. Without git history the
    proof cannot be re-run here and the test is skipped, never passed.
    """
    path = ROOT / 'src/wam_regtest' / (module + '.py')
    current = path.read_bytes()
    if hashlib.sha256(current).hexdigest() == data['proven_source_sha256']:
        return current.decode()
    try:
        proven = subprocess.run(
            ['git', '-C', str(ROOT), 'show',
             FIXTURE['proven_at'] + ':src/wam_regtest/' + module + '.py'],
            capture_output=True, check=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        raise unittest.SkipTest('PM-017 proof revision %s not available without git history'
                                % FIXTURE['proven_at'][:12])
    if hashlib.sha256(proven).hexdigest() != data['proven_source_sha256']:
        raise AssertionError('PM-017 proof revision content changed: ' + module)
    return proven.decode()


class MainPathCatalogTests(unittest.TestCase):
    def test_every_moved_english_literal_is_byte_identical(self):
        for module, data in FIXTURE['modules'].items():
            for record in data['moved']:
                key = record['key']
                with self.subTest(module=module, key=key):
                    # D5-B changes only these catalog values; retain the original AST proof.
                    expected = PM045['english'].get(key, PM043['english'].get(key, record['english']))
                    self.assertEqual(text(key, 'en').encode(), expected.encode())
                    original = ast.parse('(' + record['original'] + ')', mode='eval')
                    replacement = ast.parse(record['replacement'], mode='eval')
                    # Compare actual formatting, including grouped integers, padding,
                    # literal backslash-n, line breaks and trailing spaces.
                    arguments = (replacement.body.keywords if isinstance(replacement.body, ast.Call)
                                 and isinstance(replacement.body.func, ast.Attribute) else [])
                    samples = {}
                    for keyword in arguments:
                        numeric = keyword.arg in {
                            'position', 'height', 'atoms', 'fee', 'change_atoms',
                            'input_count', 'history_count', 'confirmed_atoms',
                            'available_atoms', 'count', 'peer_count'}
                        # Fusion review values are already formatted decimal strings.
                        if module == 'bip39_fusion_gui' and key == 'wallet.review_details':
                            numeric = False
                        samples[shape(keyword.value)] = ast.Constant(1234567 if numeric else 'ab' * 32)

                    class Substitute(ast.NodeTransformer):
                        def visit(self, node):
                            if shape(node) in samples:
                                return copy.deepcopy(samples[shape(node)])
                            return super().visit(node)

                    def render(tree):
                        tree = ast.fix_missing_locations(Substitute().visit(tree))
                        return eval(compile(tree, '<source-copy-fixture>', 'eval'),
                                    {'__builtins__': {}, 't': lambda k: PM045['previous']['en'].get(k, PM043['previous']['en'].get(k, text(k, 'en')))})
                    self.assertEqual(render(original).encode(), render(replacement).encode())

    def test_source_structure_matches_before_move(self):
        for module, data in FIXTURE['modules'].items():
            reverse = {}
            for record in data['moved']:
                replacement = ast.parse(record['replacement'], mode='eval').body
                original = ast.parse('(' + record['original'] + ')', mode='eval').body
                fingerprint = shape(replacement)
                if fingerprint in reverse:
                    self.assertEqual(shape(reverse[fingerprint]), shape(original))
                reverse[fingerprint] = original

            class Restore(ast.NodeTransformer):
                def visit(self, node):
                    if shape(node) in reverse:
                        return copy.deepcopy(reverse[shape(node)])
                    return super().visit(node)

            with self.subTest(module=module):  # a skipped proof skips only this module
                restored = Restore().visit(ast.parse(_proven_source(module, data)))
                self.assertEqual(hashlib.sha256(shape(restored).encode()).hexdigest(),
                                 data['fingerprint'], module)

    def test_all_used_keys_exist_and_resolve_only_inside_functions(self):
        seen = set()
        for module in FIXTURE['modules']:
            tree = ast.parse((ROOT / 'src/wam_regtest' / (module + '.py')).read_text())
            parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == 't'):
                    continue
                if isinstance(node.args[0], ast.Constant):
                    key = node.args[0].value
                    seen.add(key)
                    for lang, entries in CATALOG.items():
                        self.assertIn(key, entries, (module, lang))
                else:
                    # Backup page's public verification-error selector is bounded
                    # by its existing call sites and default parameter.
                    self.assertEqual(module, 'bip39_backup_page')
                    self.assertEqual(ast.unparse(node.args[0]), 'key')
                parent = parents.get(node)
                while parent is not None and not isinstance(parent, (ast.FunctionDef, ast.Lambda)):
                    parent = parents.get(parent)
                self.assertIsNotNone(parent, module)
        self.assertLessEqual(set(FIXTURE['new_keys']), seen)

    def test_no_untranslated_prose_remains(self):
        # Complete allowlist for prose-shaped non-copy constants in these modules.
        allowed = {'Tiếng Việt', 'Bahasa Indonesia', ' (V1-NET)'}
        for module in FIXTURE['modules']:
            tree = ast.parse((ROOT / 'src/wam_regtest' / (module + '.py')).read_text())
            parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                value = node.value
                if not re.search(r'[A-Za-z]', value) or ' ' not in value:
                    continue
                if isinstance(parents.get(node), ast.Expr):  # docstrings
                    continue
                if value in allowed or 'font-' in value or 'palette(' in value:
                    continue
                self.fail(f'{module}:{node.lineno}: uncataloged copy {value!r}')

    def test_named_placeholders_and_identifier_shapes(self):
        formatter = string.Formatter()
        for key in FIXTURE['new_keys']:
            english = CATALOG['en'][key]
            expected = [(name, spec, conv) for _, name, spec, conv in formatter.parse(english)
                        if name is not None]
            for language, entries in CATALOG.items():
                value = entries[key]
                fields = [(name, spec, conv) for _, name, spec, conv in formatter.parse(value)
                          if name is not None]
                self.assertEqual(fields, expected, (language, key))
                self.assertTrue(all(name.isidentifier() for name, _, _ in fields))
                self.assertNotRegex(value, r'(?i)\b[0-9a-f]{64}\b')
                self.assertNotRegex(value, r'(?i)\b(?:wamrtsp|bc1)[a-z0-9]{12,}')
                for token in ('REGTEST', 'BIP39', 'BIP352', 'WSP', 'PSBT', 'SHA256', 'TXID'):
                    self.assertEqual(english.count(token), value.count(token), (language, key, token))
        from mnemonic import Mnemonic
        words = set(Mnemonic('english').wordlist)
        for entries in CATALOG.values():
            for key in FIXTURE['new_keys']:
                tokens = entries[key].split()
                self.assertFalse(len(tokens) >= 12 and all(token in words for token in tokens), key)


class MainPathWindowTests(unittest.TestCase):
    def test_rebuilt_windows_translate_controls_statuses_and_keep_identifiers(self):
        from PySide6.QtCore import QSettings
        from PySide6.QtWidgets import QLabel
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.bip39_owner_gui import Bip39RecoveryVerifyDialog
        from wam_regtest.desktop import qt_application
        from wam_regtest.wallet_executor import ExecutorState
        from wam_regtest.wallet_read import HistoryRow, WalletReadSnapshot

        app = qt_application()
        from wam_sp.core import pub
        from wam_sp.keystore import ScanAccount
        txid, tip, account = 'ab' * 32, 'cd' * 32, 'ef' * 32
        receive = ScanAccount(0, 1, pub(2), birthday=1).payment_code()
        words = ['abandon'] * 11 + ['about']
        snapshot = WalletReadSnapshot(
            chain='regtest', height=4, tip=tip, receive_code=receive,
            confirmed_atoms=100_000_000, confirmed_utxos=1,
            history=(HistoryRow(txid, 3, 2, 100_000_000, 0),),
            core_sha256='12' * 32, history_complete=True, receive_count=1,
            signer_allowed=True, broadcast_allowed=True)
        result = dict(receive_code=receive, confirmed_atoms=100_000_000,
                      available_atoms=99_000_000, height=4, tip=tip,
                      history=[dict(txid=txid, height=3, atoms=100_000_000)],
                      signer_allowed=True, broadcast_allowed=True, fusion_snapshot=snapshot,
                      reservation_count=1, payment_review=None, payment_signed=False,
                      pending_confirm_txid=txid)
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ, {'WAM_UI_SETTINGS_PATH': str(Path(directory) / 'ui.ini')}):
            for language in ('en', 'vi', 'ja', 'zh-Hans'):
                with self.subTest(language=language):
                    settings = QSettings(os.environ['WAM_UI_SETTINGS_PATH'], QSettings.Format.IniFormat)
                    settings.setValue('ui_language', language)
                    settings.setValue('fusion_reduce_motion', True)
                    settings.sync()
                    owner = SimpleNamespace(state=ExecutorState(core_alive=True), busy=False, closed=False)
                    window = Bip39FusionWindow(owner)
                    window._poll.stop()
                    try:
                        self.assertEqual(window.send.text(), text('wallet.review_payment', language))
                        self.assertEqual(window.activate.text(), text('wallet.enable_sending', language))
                        self.assertEqual(window.sync.toolTip(), text('wallet.refresh_tooltip', language))
                        self.assertEqual(window.status.toolTip(), text('owner.core_not_opened', language))
                        if language != 'en':
                            self.assertNotEqual(window.send.text(), 'Review payment')
                            self.assertNotEqual(window.status.toolTip(), 'Native Core not opened')
                        window._on_ready('open', dict(receive_code=receive, account_id=account,
                                                      checkpoint_present=True))
                        self.assertEqual(window.receive.text(), receive)
                        self.assertEqual(window.account.text(), text('owner.account_prefix', language) + account)
                        window._on_ready('snapshot', result)
                        self.assertEqual(window.last_txid.text(), txid)
                        self.assertEqual(window.receive.text(), receive)
                        self.assertEqual(window.status.toolTip(), text('owner.awaiting_confirmation', language).format(txid=txid))
                        self.assertIn('100,000,000', window.balance.text())
                        self.assertIn(tip, window.tip.text())
                        self.assertIn(txid, window.history.toPlainText())
                        window.history_page.table.selectRow(0)
                        self.assertEqual(window.history_page.detail_id.text(), txid)
                        window._on_ready('intent_status', {'intents': []})
                        self.assertEqual(window.status.toolTip(), text('owner.intent_summary', language).format(
                            summary=text('owner.no_intents', language)) + text('owner.intent_protected', language))
                        window._on_denied('WALLET_INPUT_AMOUNT_INVALID')
                        self.assertIn(text('owner.refused_prefix', language), window.status.toolTip())
                        window.backup_page.set_phrase(words)
                        shown = [window.backup_page._grid.itemAt(i).widget().findChild(
                            QLabel, 'FusionCardValue').text() for i in range(12)]
                        self.assertEqual(shown, words)
                        window.backup_page.set_challenge({'challenge_id': '34' * 32, 'positions': [1, 5, 12]})
                        for position, (_, title, _) in zip([1, 5, 12], window.backup_page._verify_cards):
                            self.assertEqual(title.text(), text('recovery_word_position', language).format(position=position))
                        window._on_backup_challenge()
                        self.assertIn(text('wallet.backup_verify_unavailable', language), window.status.toolTip())
                        self.assertNotIn('WALLET_OPERATION_DENIED_STATE_RETAINED', window.status.toolTip())
                        self.assertEqual(window._last_error_code, 'WALLET_OPERATION_DENIED_STATE_RETAINED')
                        recovery = Bip39RecoveryVerifyDialog(window)
                        self.assertEqual(recovery._fields[0].accessibleName(),
                                         text('owner.recovery_word', language).format(position=1))
                        recovery.deleteLater()
                    finally:
                        window.backup_page.clear_phrase()
                        window.hide()
                        window.deleteLater()
                        app.processEvents()
