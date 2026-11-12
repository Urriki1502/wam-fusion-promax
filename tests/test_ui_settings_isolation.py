"""PM-016 / W-TEST-01: only the shipped production entry points may use the owner's real UI store.

Isolation is by construction (wam_regtest.ui_settings): every non-production
process, including any test run however invoked, uses an isolated INI file.
Every write in this module happens only after its destination is verified.
"""
import ast
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def _native_file_name():
    """Where the native store lives on this platform, constructed without writing."""
    from PySide6.QtCore import QSettings
    from wam_regtest.ui_settings import ORGANIZATION, APPLICATION
    return QSettings(ORGANIZATION, APPLICATION).fileName()


class IsolatedByDefault(unittest.TestCase):
    def setUp(self):
        import wam_regtest.ui_settings as ui
        self.ui = ui
        self.assertFalse(ui.native_store_enabled(), 'a test process must never have the native store enabled')

    def test_default_store_is_an_isolated_file_not_the_native_store(self):
        store = self.ui.ui_settings()
        self.assertNotEqual(Path(store.fileName()).resolve(), Path(_native_file_name()).resolve())
        self.assertTrue(Path(store.fileName()).resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())
                        or os.environ.get(self.ui.ENV_PATH))

    def test_without_the_variable_a_private_temp_file_is_used(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(self.ui.ENV_PATH, None)
            with patch.object(self.ui, '_private_path', None):
                path = Path(self.ui.ui_settings().fileName()).resolve()
                self.assertTrue(path.is_relative_to(Path(tempfile.gettempdir()).resolve()), path)
                self.assertNotEqual(path, Path(_native_file_name()).resolve())

    def test_writes_go_only_to_the_verified_isolated_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'ui.ini'
            with patch.dict(os.environ, {self.ui.ENV_PATH: str(target)}):
                store = self.ui.ui_settings()
                # Verify the destination BEFORE writing (Codex PEER-062 P1).
                self.assertEqual(Path(store.fileName()).resolve(), target.resolve())
                self.assertNotEqual(Path(store.fileName()).resolve(), Path(_native_file_name()).resolve())
                store.setValue('last_bip39_profile', '/tmp/pm016-probe-profile')
                store.sync()
            self.assertIn('pm016-probe-profile', target.read_text())


class ProductionOnlyNative(unittest.TestCase):
    def test_native_mode_uses_the_platform_native_store_and_ignores_the_variable(self):
        import wam_regtest.ui_settings as ui
        with patch.object(ui, '_native', True), patch.dict(os.environ, {ui.ENV_PATH: '/tmp/ignored.ini'}):
            store = ui.ui_settings()  # constructed only; nothing is written
            self.assertEqual(store.fileName(), _native_file_name())

    def test_exactly_the_three_production_entries_enable_the_native_store(self):
        callers = set()
        for path in (ROOT / 'src/wam_regtest').rglob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == 'use_native_store'):
                    callers.add(path.stem)
        self.assertEqual(callers, {'production_entry', 'windows_production_entry', 'linux_production_entry'})


class OneStore(unittest.TestCase):
    def test_no_module_opens_qsettings_directly(self):
        offenders = []
        for path in (ROOT / 'src/wam_regtest').rglob('*.py'):
            if path.name == 'ui_settings.py':
                continue
            for node in ast.walk(ast.parse(path.read_text())):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == 'QSettings'):
                    offenders.append('%s:%s' % (path.relative_to(ROOT), node.lineno))
        self.assertEqual(offenders, [])

    def test_frozen_pipeline_points_qualification_at_its_run_directory(self):
        text = (ROOT / 'scripts/build_macos_bundle.sh').read_text()
        self.assertIn('export WAM_UI_SETTINGS_PATH="$SOURCE_STAGE/runs/qualification-ui-settings.ini"', text)


if __name__ == '__main__':
    unittest.main()
