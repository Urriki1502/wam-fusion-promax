"""FE-006: shared admission checks and both session failure boundaries."""
from contextlib import nullcontext
from copy import deepcopy
from decimal import Decimal, localcontext
from hashlib import sha256
from threading import RLock
from types import SimpleNamespace
import json
import unittest
from unittest.mock import patch

from wam_regtest.cli_rpc import decode
from wam_sp.psbt import PSBT, Tx
from wam_regtest.domain.preflight import verify_preflight, PREFLIGHT_REJECT_REASONS
from wam_regtest.infrastructure.tx_size import serialized_vsize
from wam_regtest.wallet_session import WalletSession, WalletSessionError
from wam_regtest.bip39_spend_session import Q06OwnedSpendSession


class PreflightVerification(unittest.TestCase):
    def setUp(self):
        # Fixed consensus bytes, with a final key-path witness. Synthetic PSBT
        # wrapper only; vsize and txid use real serialized transaction bytes.
        self.tx = Tx((('11' * 32, 0),), ((9000, b'\x51\x20' + bytes(32)),))
        self.raw = self.tx.serialize([(bytes(65),)])
        self.txid = sha256(sha256(self.tx.serialize()).digest()).digest()[::-1].hex()
        self.vsize = serialized_vsize(self.raw)
        self.review = SimpleNamespace(fee=1000, vsize=self.vsize,
                                     rate_atoms_per_kvb=1000, commitment='c' * 64)
        self.reply = [{'allowed': True, 'txid': self.txid, 'vsize': self.vsize,
                       'fees': {'base': Decimal('0.00001000'),
                                'effective-feerate': Decimal(1000000 // self.vsize).scaleb(-8),
                                'effective-includes': [self.txid]}}]
        self.psbt = SimpleNamespace(finalize=lambda: self.raw, txid=lambda: self.txid)
        self.decode_patch = patch.object(PSBT, 'decode', return_value=self.psbt)
        self.decode_patch.start()
        self.addCleanup(self.decode_patch.stop)

    def check(self, reply=None, review=None):
        return verify_preflight(self.reply if reply is None else reply, b'signed',
                                self.review if review is None else review)

    def _session(self, resume, reply):
        session = (Q06OwnedSpendSession if resume else WalletSession).__new__(
            Q06OwnedSpendSession if resume else WalletSession)
        session.faulted = session._q06_uncertain = False
        session._signed = session._prepared = session._review = session._q06_pending_confirm = None
        session._tip = None
        session._lock = RLock()
        session.vault = SimpleNamespace(anchor=SimpleNamespace(lease=nullcontext))
        session._rpc = lambda: SimpleNamespace(call=lambda *args: reply)
        session._intent_status_unlocked = lambda: {'intents': [dict(
            token='a' * 32, txid=self.txid, state='signed',
            classification='SIGNED_NOT_SUBMITTED_RESUMABLE')]}
        session._read_payment_evidence = lambda *args: dict(
            signed_psbt=b'signed'.hex(), commitment='c' * 64, recipient='r', atoms=9000, fee=1000)
        if resume:
            invoke = lambda: session.resume_signed_intent('a' * 32, self.txid, approved=True)
        else:
            session._signed, session._review = b'signed', self.review
            invoke = lambda: session._preflight_not_submitted(session._rpc())
        return session, invoke

    def assert_latched_both(self, reply):
        for resume in (False, True):
            with self.subTest(resume=resume):
                session, invoke = self._session(resume, reply)
                with self.assertRaisesRegex(WalletSessionError, 'NOT_SUBMITTED_LOCK_RETAINED'):
                    invoke()
                self.assertTrue(session.faulted)

    def test_matching_acceptance_and_extras_no_authority_or_state_change(self):
        self.reply[0]['future'] = {'ignored': 1.5}
        self.assertIsNone(self.check())
        session, invoke = self._session(False, self.reply)
        before = vars(session).copy()
        self.assertIsNone(invoke())
        self.assertEqual(vars(session), before)
        self.reply[0]['fees'].pop('effective-includes')
        self.assertIsNone(self.check())

    def test_mismatches_latch_on_both_paths(self):
        cases = [('txid', 'f' * 64), ('txid', 'x' * 64), ('txid', None),
                 ('vsize', self.vsize + 1), ('vsize', True), ('vsize', float(self.vsize)),
                 ('fees.base', Decimal('0.00001001')), ('fees.base', Decimal('0.00000999')),
                 ('fees.base', 0.00001), ('fees.base', '0.00001'),
                 ('fees.base', Decimal('0.000010001')), ('fees.base', Decimal('NaN')),
                 ('fees.base', Decimal('1E+999999')),
                 ('fees.base', Decimal('1E-999999')),
                 ('fees.base', Decimal('-0.00001')), ('fees.base', True),
                 ('fees.effective-feerate', Decimal('0.00001')),
                 ('fees.effective-feerate', 0.00001),
                 ('fees.effective-feerate', Decimal('Infinity')),
                 ('fees.effective-includes', ['f' * 64]),
                 ('fees.effective-includes', [self.txid, self.txid]),
                 ('fees.effective-includes', self.txid)]
        for path, value in cases:
            with self.subTest(field=path, value=value):
                reply = deepcopy(self.reply)
                target = reply[0]
                keys = path.split('.')
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                with self.assertRaises(ValueError):
                    self.check(reply)
                self.assert_latched_both(reply)

    def test_missing_fields_latch_on_both_paths(self):
        for path in ('txid', 'vsize', 'fees', 'fees.base', 'fees.effective-feerate'):
            reply = deepcopy(self.reply)
            target = reply[0]
            keys = path.split('.')
            for key in keys[:-1]:
                target = target[key]
            del target[keys[-1]]
            with self.subTest(missing=path):
                self.assert_latched_both(reply)
        for reply in ([], {}, [None], [{'allowed': 1}], [{}, {}], [{'allowed': True, 'fees': []}]):
            self.assert_latched_both(reply)

    def test_review_vsize_and_quoted_rate(self):
        self.review.vsize += 1
        with self.assertRaises(ValueError):
            self.check()
        self.review.vsize = None
        self.assertIsNone(self.check())
        self.review.rate_atoms_per_kvb = 1000000 // self.vsize + 1
        with self.assertRaises(ValueError):
            self.check()
        self.review.rate_atoms_per_kvb = None
        self.assertIsNone(self.check())

    def test_all_rejection_reasons_definitive_without_economic_fields(self):
        for reason in (*PREFLIGHT_REJECT_REASONS, 'UNKNOWN PRIVATE CORE TEXT', None, [], 42):
            reply = [{'allowed': False}]
            if reason is not None:
                reply[0]['reject-reason'] = reason
            reply[0]['fees'] = 'irrelevant malformed economics on rejection'
            token = self.check(reply)
            self.assertIn(token, {*PREFLIGHT_REJECT_REASONS.values(), 'POLICY_REJECTED'})
            self.assertNotIn('UNKNOWN PRIVATE', token)
            for resume in (False, True):
                with self.subTest(reason=reason, resume=resume):
                    session, invoke = self._session(resume, reply)
                    with self.assertRaises(WalletSessionError) as caught:
                        invoke()
                    self.assertEqual(caught.exception.args, ('WALLET_BROADCAST_REJECTED_LOCK_RETAINED',))
                    self.assertFalse(session.faulted)
                    self.assertEqual(caught.exception.preflight_rejection, token)

    def test_decimal_decoder_to_comparison_never_float(self):
        raw = json.dumps(self.reply, default=str).replace('"0.00001000"', '0.00001000')
        rate = str(self.reply[0]['fees']['effective-feerate'])
        raw = raw.replace('"' + rate + '"', rate)
        reply = decode(raw.encode(), 'testmempoolaccept', [])
        self.assertIs(type(reply[0]['fees']['base']), Decimal)
        self.assertIs(type(reply[0]['fees']['effective-feerate']), Decimal)
        with localcontext() as ctx:
            ctx.prec = 2
            self.assertIsNone(self.check(reply))

    def test_fresh_broadcast_requires_matching_approval_before_rpc(self):
        session, _ = self._session(False, self.reply)
        session._rpc = lambda: self.fail('unauthorized preflight')
        with self.assertRaisesRegex(ValueError, 'BROADCAST_APPROVAL_REQUIRED'):
            session.broadcast('wrong commitment')

    def test_resume_requires_explicit_authorization_before_rpc(self):
        session, _ = self._session(True, self.reply)
        session._rpc = lambda: self.fail('unauthorized preflight')
        with self.assertRaisesRegex(ValueError, 'EXPLICIT_APPROVAL_REQUIRED'):
            session.resume_signed_intent('a' * 32, self.txid)
