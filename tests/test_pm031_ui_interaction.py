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


KINDS = {'FOCUS_INVISIBLE', 'FOCUS_OUTSIDE', 'FOCUS_UNLABELLED', 'FOCUS_TRAP', 'FOCUS_LOST',
         'FOCUS_STEP_LIMIT', 'NAV_CLICK_MISMATCH', 'PAGE_NOT_DISPLAYED'}


class InteractionRecords(unittest.TestCase):
    def _run(self, tmp, **patches):
        from wam_regtest.qualification.ui_interaction import render_interaction
        return render_interaction(Path(tmp) / 'out')

    def test_records_navigation_states_and_focus_without_commands(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(Bip39FusionWindow, '_command', return_value=False) as command:
            report = self._run(tmp)
            saved = (Path(tmp) / 'out' / 'interaction.json').read_text()
        # Codex PEER-090: exceptions raised inside Qt callbacks are swallowed,
        # so the mock must be checked directly.
        command.assert_not_called()
        self.assertIn('UI_INTERACTION_RECORDED', saved)
        self.assertFalse(report['backend_or_core_started'])
        self.assertFalse(report['g6_or_owner_acceptance'])
        self.assertIn('tab_focus_behavior', report['platform'])
        en = report['languages']['en']
        self.assertEqual(len(en['navigation']), 7)
        self.assertTrue(all(step['ok'] for step in en['navigation']))
        self.assertEqual(set(en['states']), {'initial_not_opened', 'verified_unlocked'})
        for pages in en['states'].values():
            self.assertTrue(all(page['displayed'] for page in pages.values()))
        self.assertIn(en['termination'], {'CYCLE_COMPLETE', 'FOCUS_TRAP', 'FOCUS_LOST', 'STEP_LIMIT'})
        self.assertLessEqual({f['kind'] for f in report['findings']}, KINDS)

    def test_page_that_does_not_follow_the_click_is_reported(self):
        from wam_regtest.fusion_motion import TransitionHost
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(TransitionHost, 'set_current', lambda self, index, reduced=False: None):
            report = self._run(tmp)
        kinds = [f['kind'] for f in report['findings']]
        self.assertIn('NAV_CLICK_MISMATCH', kinds)
        self.assertIn('PAGE_NOT_DISPLAYED', kinds)

    def test_lost_focus_is_reported_not_silently_passed(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch('PySide6.QtWidgets.QApplication.focusWidget', return_value=None):
            report = self._run(tmp)
        self.assertEqual(report['languages']['en']['termination'], 'FOCUS_LOST')
        self.assertIn('FOCUS_LOST', [f['kind'] for f in report['findings']])

    def test_table_trap_is_proven_by_revisiting_a_cell(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self._run(tmp)
        traps = [f for f in report['findings'] if f['kind'] == 'FOCUS_TRAP']
        # The overview activity table cycles its own cells (R-10). The trap is
        # only reported after Tab came back to an already visited cell.
        self.assertTrue(traps)
        self.assertGreater(traps[0]['cells_visited'], 1)

    def test_refuses_native_store(self):
        from wam_regtest import ui_settings
        from wam_regtest.qualification.ui_interaction import render_interaction
        with tempfile.TemporaryDirectory() as tmp, patch.object(ui_settings, '_native', True):
            with self.assertRaisesRegex(RuntimeError, 'UI_INTERACTION_NATIVE_STORE_DENIED'):
                render_interaction(Path(tmp) / 'out')


if __name__ == '__main__':
    unittest.main()
