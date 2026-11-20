"""PM-024: the V0 UI gallery is a presentation fixture that can never act."""
import ast
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'src/wam_regtest/qualification/ui_gallery.py'
SCENES_PER_WINDOW = 31


class GalleryIsInert(unittest.TestCase):
    def test_imports_no_backend_core_custody_or_network_module(self):
        tree = ast.parse(MODULE.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add((node.level, node.module or '', tuple(a.name for a in node.names)))
            elif isinstance(node, ast.Import):
                imported.update((0, a.name, ()) for a in node.names)
        # Wallet modules only: relative imports and absolute wam_regtest.* ones
        # (wam_sp.core is WSP's public-key math, used for the test payment code).
        modules = {module for level, module, _names in imported
                   if level > 0 or module.startswith('wam_regtest')}
        forbidden = ('bip39_owner_backend', 'bip39_spend_session', 'core', 'core_supervisor',
                     'custody', 'json_rpc', 'shared_regtest', 'vault', 'wallet_session',
                     'bip39_seed_vault', 'network_policy')
        for module in modules:
            self.assertNotIn(module.split('.')[-1], forbidden, module)
        executor_names = {names for _l, module, names in imported if module == 'wallet_executor'}
        self.assertEqual(executor_names, {('ExecutorState',)})  # never WalletExecutor

    def test_production_executables_refuse_the_gallery_argv(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('production_packaging',
                                                      ROOT / 'scripts/production_packaging.py')
        packaging = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packaging)
        self.assertIn(['--ci-ui-gallery'], list(packaging.DEVELOPER_ARGV))
        self.assertIn("'--ci-ui-gallery'", (ROOT / 'scripts/build_macos_production.py').read_text())
        entry = (ROOT / 'src/wam_regtest/package_entry.py').read_text()
        self.assertIn('sys.argv[1:] == ["--ci-ui-gallery"]', entry)


class GalleryRenders(unittest.TestCase):
    def test_every_language_renders_every_scene_with_an_image_and_a_report(self):
        from wam_regtest.presentation.strings import SUPPORTED_LANGUAGES
        from wam_regtest.qualification.ui_gallery import render_gallery
        before = os.environ.get('WAM_UI_SETTINGS_PATH')
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'gallery'
            report = render_gallery(out, sizes=((900, 630),), themes=((2, 'dark'),))
            self.assertEqual(os.environ.get('WAM_UI_SETTINGS_PATH'), before)
            self.assertEqual(report['scene_count'], SCENES_PER_WINDOW * len(SUPPORTED_LANGUAGES))
            self.assertFalse(report['backend_or_core_started'])
            self.assertFalse(report['wallet_or_transaction_acceptance'])
            self.assertFalse(report['g6_or_owner_acceptance'])
            for name in report['scenes']:
                self.assertTrue((out / (name + '.png')).stat().st_size > 1000, name)
            saved = json.loads((out / 'gallery.json').read_text())
            self.assertEqual(saved['scene_count'], report['scene_count'])
            for language in SUPPORTED_LANGUAGES:
                self.assertTrue(any(s.endswith(f'--{language}-900x630-dark') for s in report['scenes']),
                                language)
            for finding in report['findings']:
                self.assertIn(finding['kind'], {'H_SCROLL', 'TEXT_CLIPPED_V', 'TEXT_OVERFLOW_H',
                                                'TEXT_CLIPPED_H', 'BUTTON_CLIPPED'})

    def test_refuses_when_the_native_store_is_enabled(self):
        from unittest.mock import patch
        from wam_regtest import ui_settings
        from wam_regtest.qualification.ui_gallery import render_gallery
        with tempfile.TemporaryDirectory() as tmp, patch.object(ui_settings, '_native', True):
            with self.assertRaisesRegex(RuntimeError, 'UI_GALLERY_NATIVE_STORE_DENIED'):
                render_gallery(Path(tmp) / 'g', languages=('en',), sizes=((900, 630),),
                               themes=((1, 'light'),))
            self.assertFalse((Path(tmp) / 'g').exists())

    def test_refuses_to_overwrite_an_existing_output(self):
        from wam_regtest.qualification.ui_gallery import render_gallery
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileExistsError):
                render_gallery(tmp, languages=('en',), sizes=((900, 630),), themes=((1, 'light'),))


class DetectorAccuracy(unittest.TestCase):
    """Codex PEER-079: each detector has a positive and a negative case."""

    def setUp(self):
        from PySide6.QtWidgets import QWidget
        from wam_regtest.desktop import qt_application
        self.app = qt_application()
        self.root = QWidget()
        self.root.resize(600, 400)
        self.addCleanup(self.root.deleteLater)

    def _kinds(self, widget, width, height):
        from wam_regtest.qualification.ui_gallery import _inspect
        widget.setParent(self.root)
        widget.setGeometry(0, 0, width, height)
        self.root.show()
        widget.show()  # a child added after its parent was shown starts hidden
        self.app.processEvents()
        findings = []
        _inspect(self.root, 'probe', findings)
        widget.hide()
        return [f['kind'] for f in findings]

    def _table(self, columns):
        from PySide6.QtWidgets import QTableWidget
        table = QTableWidget(1, columns)
        for column in range(columns):
            table.setColumnWidth(column, 150)
        return table

    def test_table_horizontal_scroll_is_reported_once(self):
        self.assertEqual(self._kinds(self._table(6), 300, 200), ['H_SCROLL'])
        self.assertEqual(self._kinds(self._table(1), 400, 200), [])

    def test_unwrapped_multiline_label_clipped_vertically(self):
        from PySide6.QtWidgets import QLabel
        self.assertIn('TEXT_CLIPPED_V', self._kinds(QLabel('one\ntwo\nthree'), 200, 15))
        self.assertEqual(self._kinds(QLabel('one\ntwo\nthree'), 200, 120), [])

    def test_rich_text_is_measured_as_rendered(self):
        from PySide6.QtWidgets import QLabel
        self.assertEqual(self._kinds(QLabel('<b>Hello</b>'), 90, 40), [])
        self.assertIn('TEXT_CLIPPED_H', self._kinds(QLabel('<b>Hello wide world</b>'), 20, 40))

    def test_rich_text_wraps_like_qlabel_word_wrap(self):
        # Codex PEER-081: an unbreakable rich-text run stays on one clipped line.
        from PySide6.QtWidgets import QLabel

        def wrapped(text):
            label = QLabel(text)
            label.setWordWrap(True)
            return label
        self.assertIn('TEXT_OVERFLOW_H', self._kinds(wrapped('<b>' + 'W' * 30 + '</b>'), 90, 100))
        self.assertNotIn('TEXT_CLIPPED_V', self._kinds(wrapped('<b>' + 'W' * 30 + '</b>'), 90, 20))
        self.assertEqual(self._kinds(wrapped('<b>short words wrap fine here</b>'), 90, 200), [])

    def test_multiline_button_text_is_measured_per_line(self):
        from PySide6.QtWidgets import QPushButton
        self.assertEqual(self._kinds(QPushButton('Hello\nworld'), 50, 50), [])
        self.assertEqual(self._kinds(QPushButton('&Save'), 60, 30), [])

    def test_button_preferred_width_is_not_clipping(self):
        from PySide6.QtWidgets import QPushButton
        self.assertEqual(self._kinds(QPushButton('OK'), 50, 30), [])
        self.assertIn('BUTTON_CLIPPED', self._kinds(QPushButton('A much longer button label'), 40, 30))


if __name__ == '__main__':
    unittest.main()
