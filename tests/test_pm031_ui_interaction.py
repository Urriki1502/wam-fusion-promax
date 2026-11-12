"""PM-031: the interaction probe is inert and records focus, clicks and states."""
import ast
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'src/wam_regtest/qualification/ui_interaction.py'


class InteractionIsInert(unittest.TestCase):
    def test_imports_no_wallet_authority(self):
        tree = ast.parse(MODULE.read_text())
        wallet = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.level or (node.module or '').startswith('wam_regtest')):
                wallet.add(((node.module or '').split('.')[-1], tuple(a.name for a in node.names)))
        forbidden = {'bip39_owner_backend', 'bip39_spend_session', 'core', 'core_supervisor', 'custody',
                     'json_rpc', 'shared_regtest', 'vault', 'wallet_session', 'bip39_seed_vault', 'network_policy'}
        self.assertFalse({m for m, _ in wallet} & forbidden)
        self.assertEqual({names for m, names in wallet if m == 'wallet_executor'}, {('ExecutorState',)})

    def test_production_refuses_the_argv(self):
        spec = importlib.util.spec_from_file_location('pp', ROOT / 'scripts/production_packaging.py')
        packaging = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packaging)
        self.assertIn(['--ci-ui-interaction'], list(packaging.DEVELOPER_ARGV))
        self.assertIn("'--ci-ui-interaction'", (ROOT / 'scripts/build_macos_production.py').read_text())
        self.assertIn('sys.argv[1:] == ["--ci-ui-interaction"]',
                      (ROOT / 'src/wam_regtest/package_entry.py').read_text())


class InteractionRecords(unittest.TestCase):
    def test_records_navigation_states_and_focus_without_commands(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.qualification.ui_interaction import render_interaction
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(Bip39FusionWindow, '_command', side_effect=AssertionError('command issued')):
            report = render_interaction(Path(tmp) / 'out')
            saved = (Path(tmp) / 'out' / 'interaction.json').read_text()
        self.assertIn('UI_INTERACTION_RECORDED', saved)
        self.assertFalse(report['backend_or_core_started'])
        self.assertFalse(report['g6_or_owner_acceptance'])
        en = report['languages']['en']
        self.assertEqual(len(en['navigation']), 7)
        self.assertTrue(all(step['ok'] for step in en['navigation']))
        self.assertEqual(set(en['states']), {'locked', 'unlocked'})
        self.assertTrue(en['focus'])
        kinds = {f['kind'] for f in report['findings']}
        self.assertLessEqual(kinds, {'FOCUS_INVISIBLE', 'FOCUS_OUTSIDE', 'FOCUS_UNLABELLED',
                                     'FOCUS_STUCK', 'NAV_CLICK_MISMATCH'})

    def test_refuses_native_store(self):
        from wam_regtest import ui_settings
        from wam_regtest.qualification.ui_interaction import render_interaction
        with tempfile.TemporaryDirectory() as tmp, patch.object(ui_settings, '_native', True):
            with self.assertRaisesRegex(RuntimeError, 'UI_INTERACTION_NATIVE_STORE_DENIED'):
                render_interaction(Path(tmp) / 'out')


if __name__ == '__main__':
    unittest.main()
