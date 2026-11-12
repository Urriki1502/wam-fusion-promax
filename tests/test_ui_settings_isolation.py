"""PM-016 / W-TEST-01: tests and qualification never write the owner's real UI preferences."""
import ast
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REAL_STORE_HINT = 'com.wam-privacy-wallet.REGTEST'


class SuiteIsIsolated(unittest.TestCase):
    def test_suite_runs_with_an_isolated_ui_settings_file(self):
        """Fail-closed guard: if this fails, tests would write the real preferences."""
        path = os.environ.get('WAM_UI_SETTINGS_PATH')
        self.assertTrue(path, 'WAM_UI_SETTINGS_PATH is not set: run tests with PYTHONPATH=src:tests')
        self.assertTrue(Path(path).resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()), path)
        from wam_regtest.ui_settings import ui_settings
        store = ui_settings()
        self.assertEqual(Path(store.fileName()).resolve(), Path(path).resolve())
        self.assertNotIn(REAL_STORE_HINT, store.fileName())

    def test_writes_land_in_the_isolated_file_only(self):
        from wam_regtest.ui_settings import ui_settings
        store = ui_settings()
        store.setValue('last_bip39_profile', '/tmp/pm016-probe-profile')
        store.sync()
        self.assertIn('pm016-probe-profile', Path(os.environ['WAM_UI_SETTINGS_PATH']).read_text())

    def test_without_the_variable_the_real_app_keeps_its_native_store(self):
        from unittest.mock import patch
        from wam_regtest.ui_settings import ui_settings, ORGANIZATION, APPLICATION
        self.assertEqual((ORGANIZATION, APPLICATION), ('WAM Privacy Wallet', 'REGTEST'))
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('WAM_UI_SETTINGS_PATH', None)
            store = ui_settings()  # constructed only; nothing is written here
            self.assertIn(REAL_STORE_HINT, store.fileName())


class OneStore(unittest.TestCase):
    def test_no_module_opens_the_ui_store_directly(self):
        offenders = []
        for path in (ROOT / 'src/wam_regtest').rglob('*.py'):
            if path.name == 'ui_settings.py':
                continue
            for node in ast.walk(ast.parse(path.read_text())):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == 'QSettings'):
                    offenders.append('%s:%s' % (path.relative_to(ROOT), node.lineno))
        self.assertEqual(offenders, [])

    def test_frozen_pipeline_isolates_qualification_runs(self):
        text = (ROOT / 'scripts/build_macos_bundle.sh').read_text()
        self.assertIn('export WAM_UI_SETTINGS_PATH="$SOURCE_STAGE/runs/qualification-ui-settings.ini"', text)
        layout = (ROOT / 'src/wam_regtest/macos_build_layout.py').read_text()
        self.assertNotIn("'WAM_UI_", layout)  # frozen_environment must not strip it


if __name__ == '__main__':
    unittest.main()
