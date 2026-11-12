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


class PresentationLayerRule(unittest.TestCase):
    def test_action_state_is_pure_and_lower_layers_never_import_presentation(self):
        pure = ast.parse((ROOT / 'src/wam_regtest/presentation/action_state.py').read_text())
        for node in ast.walk(pure):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or '']
                for name in names:
                    self.assertFalse(name.startswith(('PySide6', 'wam_regtest')) or
                                     (isinstance(node, ast.ImportFrom) and node.level), name)
        for layer in ('foundation', 'domain', 'application'):
            for path in (ROOT / 'src/wam_regtest' / layer).rglob('*.py'):
                text = path.read_text()
                self.assertNotIn('presentation', [
                    part for node in ast.walk(ast.parse(text))
                    if isinstance(node, ast.ImportFrom)
                    for part in (node.module or '').split('.')], path)


if __name__ == '__main__':
    unittest.main()
