"""PM-005: wallet control availability as a pure presentation function (audit F-08).

The R0 characterization (test_characterization_r0.ActionAvailability) pins the
window behaviour end to end. These tests pin the extracted function itself,
without Qt, against an oracle written from the pre-PM-005 _set_actions text.
"""
import ast
import itertools
import unittest
from pathlib import Path

from wam_regtest.presentation.action_state import (
    BASE_CONTROLS, ActionInputs, SharedInputs, apply_shared_profile, available_actions,
    fusion_actions)

ROOT = Path(__file__).resolve().parents[1]
BOOL_FIELDS = ('ready', 'spend_enabled', 'signed_ready', 'pending_confirm', 'approved_commitment',
               'recovered_unsigned_cancel', 'resumable_intent', 'unlock_allowed', 'test_funded',
               'quit_requested', 'busy', 'executor_closed', 'faulted', 'locked',
               'reauthentication_required')


def _oracle(i):
    """Literal transcription of Bip39TrialWindow._set_actions at 9687855."""
    busy = i.busy
    safe = not i.faulted
    spend_safe = (safe and not i.locked and not i.reauthentication_required
                  and i.core_alive is True)
    q = i.quit_requested
    idle_payment = (not i.approved_commitment and not i.signed_ready and not i.pending_confirm)
    return {
        'sync': i.ready and safe and not busy and not q,
        'fund': i.ready and safe and not i.test_funded and not i.spend_enabled and not busy and not q,
        'activate': i.ready and safe and not i.spend_enabled and not busy and not q,
        'send': (spend_safe and i.spend_enabled and not i.approved_commitment
                 and not i.recovered_unsigned_cancel and not busy and not q),
        'broadcast': spend_safe and i.spend_enabled and i.signed_ready and not busy and not q,
        'cancel': (spend_safe and i.spend_enabled
                   and (i.approved_commitment or i.recovered_unsigned_cancel)
                   and not i.signed_ready and not busy and not q),
        'confirm': spend_safe and i.spend_enabled and i.pending_confirm and not busy and not q,
        'recovery': spend_safe and i.spend_enabled and not i.pending_confirm and not busy and not q,
        'inspect': spend_safe and i.spend_enabled and not busy and not q,
        'intents': spend_safe and i.spend_enabled and idle_payment and not busy and not q,
        'resume': (spend_safe and i.spend_enabled and idle_payment and i.resumable_intent
                   and not busy and not q),
        'lock': i.ready and not busy and not q,
        'unlock': i.unlock_allowed and not i.ready and not busy and not q,
        'quit': not busy and not i.executor_closed,
    }


def _all_inputs():
    for bits in itertools.product((False, True), repeat=len(BOOL_FIELDS)):
        for core_alive in (True, False, None):
            yield ActionInputs(core_alive=core_alive, **dict(zip(BOOL_FIELDS, bits)))


class BaseActions(unittest.TestCase):
    def test_every_input_combination_matches_the_pre_extraction_predicates(self):
        count = 0
        for inputs in _all_inputs():
            got = available_actions(inputs)
            self.assertEqual(set(got), set(BASE_CONTROLS))
            want = _oracle(inputs)
            if got != want:
                self.fail('%s\n got %s\nwant %s' % (inputs, got, want))
            count += 1
        self.assertEqual(count, 2 ** len(BOOL_FIELDS) * 3)

    def test_nothing_spends_unless_the_owner_executor_reports_a_live_unlocked_core(self):
        for inputs in _all_inputs():
            if inputs.locked or inputs.faulted or inputs.reauthentication_required \
                    or inputs.core_alive is not True or not inputs.spend_enabled:
                got = available_actions(inputs)
                for name in ('send', 'broadcast', 'cancel', 'confirm', 'recovery',
                             'inspect', 'intents', 'resume'):
                    self.assertFalse(got[name], (name, inputs))

    def test_inputs_are_immutable(self):
        inputs = next(_all_inputs())
        with self.assertRaises(Exception):
            inputs.ready = True


class SharedAndFusion(unittest.TestCase):
    def test_shared_profile_overrides(self):
        for inputs in _all_inputs():
            base = available_actions(inputs)
            self.assertEqual(apply_shared_profile(base, None), base)
            for coordinator, connected in itertools.product((False, True), repeat=2):
                got = apply_shared_profile(base, SharedInputs(coordinator, connected))
                for name in BASE_CONTROLS:
                    if name in ('fund', 'confirm'):
                        want = base[name] and coordinator and connected
                    elif name in ('send', 'broadcast'):
                        want = base[name] and connected
                    else:
                        want = base[name]
                    self.assertEqual(got[name], want, (name, coordinator, connected))
            break  # one representative is enough for the override rule; full grid below
        ready = ActionInputs(ready=True, spend_enabled=True, signed_ready=True, pending_confirm=True,
                             approved_commitment=False, recovered_unsigned_cancel=False,
                             resumable_intent=False, unlock_allowed=False, test_funded=False,
                             quit_requested=False, busy=False, executor_closed=False,
                             faulted=False, locked=False, reauthentication_required=False,
                             core_alive=True)
        base = available_actions(ready)
        self.assertTrue(base['broadcast'] and base['confirm'])
        offline = apply_shared_profile(base, SharedInputs(coordinator=True, connected=False))
        self.assertFalse(offline['broadcast'] or offline['confirm'] or offline['send'])
        follower = apply_shared_profile(base, SharedInputs(coordinator=False, connected=True))
        self.assertFalse(follower['confirm'])
        self.assertTrue(follower['broadcast'])

    def test_fusion_controls_match_the_pre_extraction_text(self):
        for inputs in _all_inputs():
            for shared in (None, SharedInputs(True, True), SharedInputs(True, False)):
                actions = apply_shared_profile(available_actions(inputs), shared)
                got = fusion_actions(inputs, actions, shared)
                idle = not inputs.busy
                ready = inputs.ready and not inputs.faulted and not inputs.locked
                self.assertEqual(got, {
                    'reconcile': idle and not inputs.quit_requested and inputs.core_alive is True,
                    'custody_switch': idle and not inputs.quit_requested
                    and (actions['lock'] or actions['unlock']),
                    'custody_unlocked': not inputs.locked and inputs.ready,
                    'go_send': (ready and idle and inputs.spend_enabled
                                and inputs.core_alive is True
                                and not inputs.reauthentication_required
                                and (shared is None or shared.connected)),
                    'open_security': not inputs.quit_requested,
                })


def _imported_names(tree, package):
    """Fully qualified import targets of a module, for `import`, `from` and relatives."""
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package
                for _ in range(node.level - 1):
                    base = base.rpartition('.')[0]
                stem = base + ('.' + node.module if node.module else '')
            else:
                stem = node.module or ''
            names.append(stem)
            names.extend(stem + '.' + alias.name for alias in node.names)
    return names


def _package_of(path):
    """D-PM009-2: the package a file's relative imports resolve against.

    For a/b/c.py and for a/b/__init__.py alike it is ``a.b``, so nested
    sub-packages of a layer resolve correctly."""
    return '.'.join(path.parent.relative_to(ROOT / 'src').parts)


class PresentationLayerRule(unittest.TestCase):
    """D-PM005-2: covers `import` statements, relative imports and __init__.py."""

    def test_relative_imports_resolve_against_each_files_own_package(self):
        src = ROOT / 'src'
        nested = src / 'wam_regtest/domain/sub/mod.py'
        init = src / 'wam_regtest/domain/sub/__init__.py'
        self.assertEqual(_package_of(nested), 'wam_regtest.domain.sub')
        self.assertEqual(_package_of(init), 'wam_regtest.domain.sub')
        tree = ast.parse('from ...presentation import strings\nfrom ..presentation import x\n')
        names = _imported_names(tree, _package_of(nested))
        self.assertIn('wam_regtest.presentation.strings', names)  # caught at depth 3
        self.assertIn('wam_regtest.domain.presentation.x', names)

    def test_pure_presentation_modules_import_nothing(self):
        for name in ('__init__.py', 'action_state.py'):
            tree = ast.parse((ROOT / 'src/wam_regtest/presentation' / name).read_text())
            for target in _imported_names(tree, 'wam_regtest.presentation'):
                self.assertFalse(target.startswith(('PySide6', 'wam_regtest')), (name, target))

    def test_lower_layers_never_import_presentation(self):
        for layer in ('foundation', 'infrastructure', 'domain', 'application'):
            for path in (ROOT / 'src/wam_regtest' / layer).rglob('*.py'):
                package = _package_of(path)
                for target in _imported_names(ast.parse(path.read_text()), package):
                    self.assertFalse(target == 'wam_regtest.presentation'
                                     or target.startswith('wam_regtest.presentation.'),
                                     (path.name, target))


class FusionWindowSingleWriter(unittest.TestCase):
    """D-PM005-1: the REAL Fusion window, not the pure function, against an
    oracle transcribed from bip39_fusion_gui._set_actions at 9687855."""

    def setUp(self):
        import os
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        from PySide6.QtWidgets import QApplication
        from types import SimpleNamespace
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.wallet_executor import ExecutorState
        self.app = QApplication.instance() or QApplication([])
        self.owner = SimpleNamespace(state=ExecutorState(locked=False, faulted=False, core_alive=True),
                                     busy=False, closed=False)
        self.window = Bip39FusionWindow(self.owner)
        self.window._poll.stop()

    def tearDown(self):
        self.window._poll.stop()
        self.window.deleteLater()
        self.app.processEvents()

    def _oracle_go_send(self, w, shared_connected):
        state = w.executor.state
        ready = w._ready and not state.faulted and not state.locked
        idle = w._worker is None and not w.executor.busy and not w._delivering_result
        return bool(ready and idle and w._spend_enabled and state.core_alive is True
                    and not state.reauthentication_required
                    and (w.shared_profile is None or shared_connected))

    def test_go_send_has_one_writer_across_flags(self):
        import itertools
        from wam_regtest.wallet_executor import ExecutorState
        w = self.window
        from types import SimpleNamespace
        worker = object()  # D-PM009-1: an in-flight worker, by identity only
        try:
            for (ready, spend, busy, delivering, locked, reauth, faulted, core,
                 working, shared, connected, coordinator) in itertools.product(
                    (False, True), (False, True), (False, True), (False, True), (False, True),
                    (False, True), (False, True), (True, False, None),
                    (False, True), (False, True), (False, True), (False, True)):
                if not shared and (connected or coordinator):
                    continue  # connection/coordinator state only exists for a shared profile
                w._ready, w._spend_enabled, w._delivering_result = ready, spend, delivering
                w._worker = worker if working else None
                w.shared_profile = SimpleNamespace(coordinator=coordinator) if shared else None
                w._shared_connected = connected
                w.executor.busy = busy
                w.executor.state = ExecutorState(locked=locked, faulted=faulted,
                                                 reauthentication_required=reauth, core_alive=core)
                w._set_actions()
                self.assertEqual(w.overview.go_send.isEnabled(), self._oracle_go_send(w, connected),
                                 (ready, spend, busy, delivering, locked, reauth, faulted, core,
                                  working, shared, connected, coordinator))
        finally:
            w._worker = None
            w.shared_profile = None
            w._shared_connected = False

    def test_render_verified_no_longer_writes_go_send(self):
        source = (ROOT / 'src/wam_regtest/bip39_fusion_gui.py').read_text()
        tree = ast.parse(source)
        writers = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'setEnabled'
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == 'go_send'):
                writers.append(node.lineno)
        self.assertEqual(len(writers), 1, writers)


if __name__ == '__main__':
    unittest.main()
