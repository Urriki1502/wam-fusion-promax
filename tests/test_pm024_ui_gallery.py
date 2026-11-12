"""PM-024: the V0 UI gallery is a presentation fixture that can never act."""
import ast
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'src/wam_regtest/qualification/ui_gallery.py'
SCENES_PER_WINDOW = 19


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

    def test_refuses_to_overwrite_an_existing_output(self):
        from wam_regtest.qualification.ui_gallery import render_gallery
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileExistsError):
                render_gallery(tmp, languages=('en',), sizes=((900, 630),), themes=((1, 'light'),))


if __name__ == '__main__':
    unittest.main()
