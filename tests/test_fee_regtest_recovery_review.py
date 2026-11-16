"""PEER-148 regressions. PURE_ORCHESTRATION, never genuine-Core evidence."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wam_regtest.qualification import fee_regtest_recovery as recovery
from wam_regtest.qualification.fee_regtest import FIXTURES
from wam_regtest.wallet_session import PaymentReview
from wam_regtest.bip39_locale import t


class RecoveryReview(unittest.TestCase):
    def test_history_uses_projected_net_atoms_and_requires_one_exact_payment(self):
        txid = '6' * 64
        snapshot = {'history': ({'txid': txid, 'height': 103, 'atoms': -100310},)}
        self.assertTrue(recovery.history_debit_holds(snapshot, txid, 100000, 310))
        for rows in ((), snapshot['history'] * 2,
                     ({'txid': txid, 'height': 103, 'atoms': -100000},),
                     ({'txid': txid, 'credit_atoms': 0, 'debit_atoms': 100310},),
                     ({'txid': '7'*64, 'atoms': -100310},),
                     ({'txid': txid, 'atoms': '-100310'},)):
            self.assertFalse(recovery.history_debit_holds({'history': rows}, txid, 100000, 310))
        self.assertFalse(recovery.history_debit_holds({}, txid, 100000, 310))

    def test_resume_has_its_own_no_crypto_write_ahead_window(self):
        evidence = dict(raw_sha256='5'*64, txid='6'*64)
        submissions = [dict(states=['uncertain'], raw_sha256='5'*64, uncertain_evidence_txid='6'*64)]
        # Same event order as genuine run 7; Sign belongs to the earlier session.
        prefix = ['SAVE', 'ACTION_SIGN', 'POLICY_READ', 'MARK_SIGNED', 'SAVE', 'SIGN',
                  'ACTION_QUIT', 'ACTION_OPEN', 'ACTION_ACTIVATE', 'ACTION_INTENT_STATUS']
        window = ['ACTION_RESUME_INTENT', 'TESTMEMPOOLACCEPT', 'EVIDENCE_UNCERTAIN_SAVED',
                  'SAVE', 'SAVE_UNCERTAIN', 'TESTMEMPOOLACCEPT', 'SENDRAWTRANSACTION', 'SAVE']
        self.assertTrue(recovery.resume_order_holds(prefix + window, submissions, evidence))
        for mutation in ('SIGN', 'MARK_SIGNED', 'RELEASE_DRAFT'):
            self.assertFalse(recovery.resume_order_holds(prefix + window[:2] + [mutation] + window[2:], submissions, evidence))
        for bad in (window[1:], window + window, window[:-1],
                    [e for e in window if e != 'SAVE_UNCERTAIN'],
                    window[:2] + ['SENDRAWTRANSACTION'] + window[2:],
                    window[:2] + ['ACTION_BROADCAST'] + window[2:]):
            self.assertFalse(recovery.resume_order_holds(prefix + bad, submissions, evidence), bad)
        self.assertFalse(recovery.resume_order_holds(prefix + window, [], evidence))

    def test_both_recovery_paths_finish_with_only_owner_metadata_gap(self):
        for case in ('F3-11', 'F3-12'):
            with self.subTest(case=case):
                self.run_recovery_path(case)

    def run_recovery_path(self, case):
        fixture = next(f for f in FIXTURES if f.case == case)
        review = PaymentReview('wamrtsp1disposable', 100000, 310, 899690, 1, '7'*64, vsize=155,
                               available_after=0)
        evidence = dict(raw_sha256='5'*64, encrypted_sha256='9'*64, txid='6'*64, atoms=100000,
                        fee=310, vsize=155, commitment=review.commitment, token_sha256='8'*64, fee_quote=None)
        before = dict(reservation_sha256='1'*64, anchor_sha256='2'*64, identity_sha256='3'*64,
                      tip=[102, '4'*64], anchor_generation=4, faulted=False, prepared=False, signed=False,
                      reservation_states=[], reservations=0, reservation_rows=[],
                      balance=dict(confirmed_atoms=1000000, available_atoms=1000000), mempool=[])
        state = copy.deepcopy(before)
        events = []
        observations = dict(events=events, proposals=[310], releases=[], submissions=[], restart_start=0)
        final = dict(confirmed_atoms=899690, available_atoms=899690, pending_atoms=0,
                     pending_spent_atoms=0, reservation_count=1, reservation_states=("broadcast",),
                     reservation_state_counts=(("broadcast", 1),),
                     payment_review=None, payment_signed=False, recovered_unsigned_cancel_available=False,
                     pending_confirm_txid=None, history=({'txid': evidence['txid'], 'height': 103, 'atoms': -100310},))
        window = SimpleNamespace(recipient_input=SimpleNamespace(setText=lambda _: None),
            amount_input=SimpleNamespace(setText=lambda _: None), send=object(), broadcast=object(), confirm=object(),
            _last_review=review, _signed_ready=False, _pending_confirm_txid=None,
            _resumable_intent=evidence, intents=SimpleNamespace(click=lambda: None),
            last_txid=SimpleNamespace(text=lambda: ''))
        window.confirm = SimpleNamespace(isEnabled=lambda: window._pending_confirm_txid is not None)
        checks, result = {}, {}
        def submit(action):
            events.extend([action, 'TESTMEMPOOLACCEPT', 'EVIDENCE_UNCERTAIN_SAVED', 'SAVE',
                           'SAVE_UNCERTAIN', 'TESTMEMPOOLACCEPT', 'SENDRAWTRANSACTION', 'SAVE'])
            observations['submissions'].append(dict(states=['uncertain'], raw_sha256=evidence['raw_sha256'],
                                                     uncertain_evidence_txid=evidence['txid']))
            state.update(reservation_states=['broadcast'], mempool=[evidence['txid']])
            window._pending_confirm_txid = evidence['txid']
        def request(action, *args, **kwargs):
            if action == 'fee_inspect':
                return copy.deepcopy(state)
            if action == 'fee_signed_evidence':
                return dict(evidence)
            if action == 'fee_preflight':
                return dict(checks={'allowed': True}, final_vsize=155, raw_sha256=evidence['raw_sha256'],
                            txid=evidence['txid'], selected_inputs=[dict(txid='a'*64, vout=0, atoms=1000000)])
            if action == 'intent_status':
                return dict(write_attempted=False, automatic_resume=False, abandon_available=False,
                    mainnet_allowed=False, intents=[dict(state='signed', evidence='verified',
                    classification='SIGNED_NOT_SUBMITTED_RESUMABLE', txid=evidence['txid'], atoms=100000, fee=310)])
            if action == 'fee_resume_replay':
                return 'Q06_RESUME_SESSION_NOT_IDLE'
            if action == 'snapshot':
                if window._pending_confirm_txid:
                    return dict(final, confirmed_atoms=1000000, available_atoms=0,
                                pending_confirm_txid=evidence['txid'])
                return copy.deepcopy(final)
            self.fail(action)
        def approve_payment(app, w, button, caption, done, wait, checks, result, kind):
            # Enforce the actual button caption; the old mock ignored it.
            self.assertEqual(caption, t('pages.approve_sign' if kind == 'sign' else 'pages.approve_broadcast_2'))
            checks.update({'gui_'+kind+'_review': True, 'gui_'+kind+'_cancel_default': True,
                           'gui_no_manual_fee_field': True})
            if kind == 'sign':
                events.extend(['SAVE', 'ACTION_SIGN', 'POLICY_READ', 'MARK_SIGNED', 'SAVE', 'SIGN'])
                state.update(reservation_states=['signed'], reservations=1,
                             balance=dict(confirmed_atoms=1000000, available_atoms=0))
                w._signed_ready = True
            else:
                submit('ACTION_BROADCAST')
            self.assertTrue(done())
        def resume(*args):
            checks['explicit_resume_approval'] = True
            submit('ACTION_RESUME_INTENT')
        def restart():
            observations['restart_start'] = len(events)
            events.extend(['ACTION_QUIT', 'ACTION_OPEN', 'ACTION_ACTIVATE'])
            state['anchor_generation'] += 1
        def confirm(*args):
            window._pending_confirm_txid = None
            state.update(reservation_rows=[dict(txid="a"*64, vout=0, state="broadcast")])
        with patch('wam_regtest.qualification.fee_regtest_runner.quote_checks', return_value={'quote': True}), \
             patch.object(recovery, 'approve_resume', side_effect=resume):
            recovery.run_recovery(fixture, app=None, request=request, restart=restart,
                current_window=lambda: window, idle=lambda: True,
                wait=lambda predicate, code: self.assertTrue(predicate(), code), approve=confirm,
                approve_payment=approve_payment, observations=observations, before=before,
                destination=review.code, checks=checks, result=result)
        self.assertEqual({k for k, v in checks.items() if v is not True}, {'persisted_fee_metadata'})
        self.assertTrue(recovery.recovery_assertions(fixture) <= checks.keys())
