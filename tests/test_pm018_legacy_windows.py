"""PM-018 legacy window copy. English expectations come from 371f10e source.

The fixture stores source-transcribed English and the original expressions.
Rendering compares those expressions with the catalog calls. These checks do
not qualify Core, custody, or a frozen build.
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
from unittest.mock import patch
from types import SimpleNamespace

from wam_regtest.presentation.strings import CATALOG, text
from wam_regtest.wallet_read import format_wam

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / 'tests/pm018_english_literals.json').read_text())
MODULES = ('managed_gui', 'operational_gui', 'desktop')
PROTECTED = re.compile(
    r'WSP-1|SHA-256|BIP352|BIP39|REGTEST|V1-NET|TXID|Q05|Q06|wamrtsp1…|'
    r'\bWAM\b|\bCore\b|\bP2P\b|\bRPC\b|\bUTXO\b|\bQR\b|\bIP\b|\d+(?:\.\d+)?'
)
FONT_NAMES = {
    'Segoe UI', 'Arial', 'Helvetica Neue', 'Avenir Next',
    'Noto Sans', 'DejaVu Sans', 'Liberation Sans',
}
# OS application name (menu, Dock, window manager). Product identity, not a sentence.
APPLICATION_NAME = 'WAM Privacy Wallet REGTEST'


def shape(node):
    return ast.dump(node, include_attributes=False)


def is_t(node):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 't'


class Result:
    code = 'wamrtsp1examplecode'
    atoms = 125000000
    fee = 10000
    change_atoms = 4000
    input_count = 3

    def __str__(self):
        return 'ab' * 32

    def __radd__(self, other):
        return other + str(self)


def namespace(signed, session, platform, field):
    snap = SimpleNamespace(height=1234567, tip='cd' * 32, core_sha256='ef' * 32)
    return {
        'self': SimpleNamespace(signed=signed, session=session, _snapshot=snap,
                                _submitted_txid='ab' * 32),
        'snap': snap,
        'result': Result(),
        'row': SimpleNamespace(txid='12' * 32, block_height=77),
        'confirmed': SimpleNamespace(block_height=99),
        'field': field,
        'fields': ('block_height', 'txid'),
        'str': str,
        'format_wam': format_wam,
        'sys': SimpleNamespace(platform=platform),
        'PySide6': SimpleNamespace(__version__='6.6.1'),
        'core_compat': SimpleNamespace(CORE_RELEASE='v0.1.13', DISPLAY_NAME='WAM Core v0.1.13'),
        'custody': SimpleNamespace(anchor_label=lambda: 'macOS Keychain'),
        't': lambda key: text(key, 'en'),
    }


def _proven_source(module, data):
    """Post-move module text the structure proof applies to.

    Anchored to that file's git blob and content SHA-256, so a later edit of
    the live module does not freeze or void the proof. The current file is
    used while it still matches. Otherwise the blob is read from git and its
    SHA-256 is checked. Without git, or without that blob, the proof is
    skipped and must not pass.
    """
    path = ROOT / 'src/wam_regtest' / (module + '.py')
    current = path.read_bytes()
    if hashlib.sha256(current).hexdigest() == data['proven_source_sha256']:
        return current.decode()
    blob = data['proven_blob']
    try:
        proven = subprocess.run(
            ['git', '-C', str(ROOT), 'cat-file', '-p', blob],
            capture_output=True, check=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise unittest.SkipTest(
            'PM-018 proof blob %s is not available (%s)' % (blob[:12], error)) from error
    if hashlib.sha256(proven).hexdigest() != data['proven_source_sha256']:
        raise AssertionError('PM-018 proof blob content changed: ' + module)
    return proven.decode()


def _prove_structure(module, data, source):
    reverse = {}
    for record in data['moved']:
        original = ast.parse(record['original'], mode='eval').body
        replacement = ast.parse(record['replacement'], mode='eval').body
        fingerprint = shape(replacement)
        if fingerprint in reverse and shape(reverse[fingerprint]) != shape(original):
            raise AssertionError(record['replacement'])
        reverse[fingerprint] = original

    class Restore(ast.NodeTransformer):
        def visit(self, node):
            if shape(node) in reverse:
                return copy.deepcopy(reverse[shape(node)])
            return super().visit(node)

    fresh = ast.parse(source)
    fresh.body = [node for node in fresh.body
                  if not (isinstance(node, ast.ImportFrom) and node.module == 'bip39_locale')]
    restored = Restore().visit(fresh)
    got = hashlib.sha256(shape(restored).encode()).hexdigest()
    if got != data['fingerprint']:
        raise AssertionError('PM-018 structure fingerprint mismatch for %s: %s' % (module, got))


class LegacyCatalogTests(unittest.TestCase):
    def test_transcribed_english_matches_catalog_and_source_rendering(self):
        for key, literal in FIXTURE['english'].items():
            self.assertEqual(text(key, 'en').encode(), literal.encode(), key)
        for module, data in FIXTURE['modules'].items():
            reverse = {}
            for record in data['moved']:
                original = ast.parse(record['original'], mode='eval').body
                replacement = ast.parse(record['replacement'], mode='eval').body
                fingerprint = shape(replacement)
                if fingerprint in reverse:
                    self.assertEqual(shape(reverse[fingerprint]), shape(original), record['replacement'])
                reverse[fingerprint] = original
                for signed in (False, True):
                    for session in (None, object()):
                        for platform in ('darwin', 'win32', 'linux', 'freebsd'):
                            for field in ('txid', 'block_height', 'credit_atoms', 'debit_atoms'):
                                env = namespace(signed, session, platform, field)
                                # Fixture expressions only, with no builtins: same byte check as PM-017.
                                left = eval(compile(ast.Expression(original), '<source>', 'eval'),
                                            {'__builtins__': {}}, env)
                                right = eval(compile(ast.Expression(replacement), '<catalog>', 'eval'),
                                             {'__builtins__': {}}, env)
                                self.assertEqual(left, right, (module, record['replacement'], platform, field))

    def test_source_structure_matches_before_move(self):
        # D-PM018-1: separate from the English byte-identity test, and one
        # subTest per module, so a proof that must be skipped (no git history
        # and an edited module) skips only that module's proof.
        for module, data in FIXTURE['modules'].items():
            with self.subTest(module=module):
                _prove_structure(module, data, _proven_source(module, data))

    def test_tampered_structure_fingerprint_fails(self):
        module, data = next(iter(FIXTURE['modules'].items()))
        source = _proven_source(module, data)
        tampered = dict(data)
        tampered['fingerprint'] = 'f' * 64
        with self.assertRaises(AssertionError) as caught:
            _prove_structure(module, tampered, source)
        self.assertIn(module, str(caught.exception))
        self.assertIn('fingerprint mismatch', str(caught.exception))

    def test_used_keys_exist_and_resolve_inside_functions(self):
        seen = set()
        for module in MODULES:
            tree = ast.parse((ROOT / 'src/wam_regtest' / (module + '.py')).read_text())
            parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
            for node in ast.walk(tree):
                if not is_t(node):
                    continue
                parent = parents.get(node)
                while parent is not None and not isinstance(parent, (ast.FunctionDef, ast.Lambda, ast.AsyncFunctionDef)):
                    parent = parents.get(parent)
                self.assertIsNotNone(parent, module)
                if node.args and isinstance(node.args[0], ast.Constant):
                    seen.add(node.args[0].value)
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                        if inner.value.split('.', 1)[0] in ('managed', 'operational', 'desktop', 'fusion'):
                            seen.add(inner.value)
        self.assertTrue(set(FIXTURE['new_keys']) <= seen)
        for key in seen:
            for language, entries in CATALOG.items():
                self.assertIn(key, entries, (language, key))
                self.assertNotEqual(entries[key], key)

    def test_placeholders_protected_tokens_and_parity(self):
        formatter = string.Formatter()
        for key in FIXTURE['new_keys']:
            english = CATALOG['en'][key]
            expected_fields = [(name, spec, conv) for _, name, spec, conv in formatter.parse(english)
                               if name is not None]
            expected_tokens = PROTECTED.findall(english)
            for language, entries in CATALOG.items():
                value = entries[key]
                fields = [(name, spec, conv) for _, name, spec, conv in formatter.parse(value)
                          if name is not None]
                self.assertEqual(fields, expected_fields, (language, key))
                self.assertTrue(all(name.isidentifier() for name, _, _ in fields), (language, key))
                self.assertEqual(PROTECTED.findall(value), expected_tokens, (language, key))
                self.assertNotRegex(value, r'(?i)\b[0-9a-f]{64}\b', (language, key))
                self.assertNotRegex(value, r'(?i)\b(?:wamrtsp|bc1)[a-z0-9]{12,}', (language, key))
        self.assertEqual(set(CATALOG), {'en', 'zh-Hans', 'vi', 'ko', 'id', 'ja'})
        for language, entries in CATALOG.items():
            self.assertEqual(set(entries), set(CATALOG['en']), language)

    def test_font_names_are_the_only_remaining_prose(self):
        for module in MODULES:
            tree = ast.parse((ROOT / 'src/wam_regtest' / (module + '.py')).read_text())
            parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                value = node.value
                if not re.search(r'[A-Za-z]', value) or ' ' not in value:
                    continue
                if isinstance(parents.get(node), ast.Expr):
                    continue
                self.assertIn(value, FONT_NAMES | {APPLICATION_NAME}, f'{module}:{node.lineno}:{value!r}')

    def test_safety_prohibitions_stay_independent(self):
        expectations = {
            'operational.signing_warning': {
                'vi': 'Không bao giờ thử lại trong im lặng.',
                'ja': '通知なしに再試行されることは決してありません。',
                'zh-Hans': '切勿静默重试。',
                'ko': '조용히 다시 시도하지 않습니다.',
                'id': 'Tidak pernah mencoba ulang secara diam-diam.',
            },
            'operational.linux_experimental': {
                'vi': ('Không có thao tác sản xuất.', 'Không có thao tác với tiền thật.'),
                'ja': ('本番の操作はありません。', '実資金の操作はありません。'),
                'zh-Hans': ('没有生产操作。', '没有真实资金操作。'),
                'ko': ('프로덕션 작업은 없습니다.', '실제 자금 작업은 없습니다.'),
                'id': ('Tidak ada operasi produksi.', 'Tidak ada operasi dana nyata.'),
            },
            'operational.reauth_body': {
                'vi': ('Không được nhận nút bên ngoài.', 'Không thử lại giao dịch.',
                       'Không thay thế ví.', 'Không đặt lại lưu ký.'),
                'ja': ('外部ノードの採用は許可されません。', '取引の再試行は許可されません。',
                       'ウォレットの置き換えは許可されません。', '保管のリセットは許可されません。'),
                'zh-Hans': ('不允许采纳外部节点。', '不允许重试交易。',
                            '不允许更换钱包。', '不允许重置托管。'),
                'ko': ('외부 노드를 채택하지 않습니다.', '거래를 다시 시도하지 않습니다.',
                       '지갑을 교체하지 않습니다.', '보관을 초기화하지 않습니다.'),
                'id': ('Tidak mengadopsi node eksternal.', 'Tidak mencoba ulang transaksi.',
                       'Tidak mengganti dompet.', 'Tidak mengatur ulang kustodi.'),
            },
            'operational.network_verified': {
                'vi': ('Không có tuyến từ xa.', 'Không có proxy.', 'Không có dự phòng clearnet.'),
                'ja': ('リモート経路はありません。', 'プロキシはありません。',
                       'clearnet のフォールバックはありません。'),
                'zh-Hans': ('没有远程路由。', '没有代理。', '没有 clearnet 回退。'),
                'ko': ('원격 경로는 없습니다.', '프록시는 없습니다.', 'clearnet 대체 경로는 없습니다.'),
                'id': ('Tidak ada rute jarak jauh.', 'Tidak ada proksi.', 'Tidak ada fallback clearnet.'),
            },
        }
        for key, languages in expectations.items():
            for language, clauses in languages.items():
                value = text(key, language)
                for clause in clauses:
                    self.assertIn(clause, value, (key, language, clause))
        warning = text('operational.signing_warning', 'ja')
        self.assertNotIn('しないでください', warning)
        self.assertIn('決してありません', warning)

    def test_japanese_one_block_title_uses_confirm(self):
        # D-PM017-1: the confirm-one-block dialog title matches its confirm button.
        title = CATALOG['ja']['owner.confirm_title']
        self.assertEqual(title, 'REGTEST の一ブロックを確認')
        self.assertNotIn('承認', title)
        self.assertIn('確認', title)


class LegacyWindowTests(unittest.TestCase):
    def test_qt_application_does_not_read_ui_settings(self):
        from wam_regtest import desktop

        def denied(*_args, **_kwargs):
            raise AssertionError('qt_application read UI settings')

        with patch('wam_regtest.bip39_locale.ui_settings', denied), \
                patch('wam_regtest.ui_settings.ui_settings', denied):
            desktop._QT_APPLICATION = None
            app = desktop.qt_application()
        self.assertEqual(app.applicationDisplayName(), APPLICATION_NAME)

    def test_operational_window_translates_labels_and_keeps_identifiers(self):
        from PySide6.QtCore import QSettings
        from PySide6.QtWidgets import QCheckBox
        from wam_regtest.desktop import qt_application
        from wam_regtest.operational_gui import OperationalWalletWindow
        from wam_regtest.wallet_read import HistoryRow, WalletReadSnapshot
        from wam_sp.core import pub
        from wam_sp.keystore import ScanAccount

        app = qt_application()
        txid = 'ab' * 32
        receive = ScanAccount(0, 1, pub(2), birthday=1).payment_code()
        atoms = 125_000_000
        session = SimpleNamespace(
            locked=False, faulted=False,
            core_dir=Path('/tmp/wam-pm018-core'),
            datadir=Path('/tmp/wam-pm018-data'),
            source=Path('/tmp/wam-pm018-wsp'))
        snapshot = WalletReadSnapshot(
            'regtest', 105, 'cd' * 32, receive, atoms, 1,
            (HistoryRow(txid, 104, 2, atoms, 0),), 'ef' * 32,
            signer_allowed=True, broadcast_allowed=True)
        result = SimpleNamespace(code=receive, atoms=atoms, fee=10_000,
                                 change_atoms=4_000, input_count=2)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'ui.ini')
            with patch.dict(os.environ, {'WAM_UI_SETTINGS_PATH': path}):
                for language in ('en', 'vi', 'ja', 'zh-Hans'):
                    with self.subTest(language=language):
                        settings = QSettings(path, QSettings.Format.IniFormat)
                        settings.setValue('ui_language', language)
                        settings.sync()
                        window = OperationalWalletWindow(session)
                        window._sync_timer.stop()
                        window._theme_timer.stop()
                        try:
                            self.assertEqual(window.windowTitle(), text('operational.window_title', language))
                            self.assertEqual(window.prepare_button.text(), text('operational.prepare_payment', language))
                            self.assertEqual(window.navigation.item(0).text(), text('fusion.overview', language))
                            self.assertEqual(window.navigation.item(3).text(), text('fusion.send', language))
                            self.assertEqual(window.warning.text(), text('operational.warning', language))
                            shown = [box.text() for box in window.findChildren(QCheckBox)]
                            self.assertIn(text('operational.field_txid', language), shown)
                            self.assertIn(text('operational.field_block_height', language), shown)
                            if language != 'en':
                                self.assertNotEqual(window.prepare_button.text(), 'Prepare payment')
                                self.assertNotEqual(window.navigation.item(3).text(), 'Send')
                                self.assertNotIn('Txid', shown)
                            window._operation_ready('prepare', result)
                            review = window.review_text.toPlainText()
                            self.assertIn(receive, review)
                            self.assertIn('125000000', review)
                            self.assertIn(format_wam(atoms), review)
                            self.assertIn(text('operational.heading_review', language), review)
                            window.apply_snapshot(snapshot)
                            self.assertEqual(window.receive_code.text(), receive)
                            self.assertIn(format_wam(atoms), window.balance_text.text())
                            self.assertIn(snapshot.core_sha256, window.core_identity.text())
                            self.assertTrue(window.core_identity.text().startswith('SHA-256 / '))
                            self.assertNotIn(txid, window.core_identity.text())
                            self.assertEqual(window.disclosure_record.itemData(0), txid)
                            label = window.disclosure_record.itemText(0)
                            self.assertTrue(label.startswith(txid[:16]))
                            self.assertIn('104', label)
                            codes = []
                            window.operation_failed.connect(codes.append)
                            window._operation_denied('WALLET_INPUT_AMOUNT_INVALID')
                            self.assertEqual(codes, ['WALLET_INPUT_AMOUNT_INVALID'])
                            self.assertEqual(window.status.text(), text('errors.WALLET_INPUT_AMOUNT_INVALID', language))
                            self.assertNotIn(receive, window.status.text())
                        finally:
                            window.hide()
                            window.deleteLater()
                            app.processEvents()
