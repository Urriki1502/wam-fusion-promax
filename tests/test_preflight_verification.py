"""FE-006: shared admission checks and both session failure boundaries."""
from contextlib import nullcontext
from copy import deepcopy
from decimal import Decimal, localcontext
from hashlib import sha256
from pathlib import Path
from threading import RLock
from types import SimpleNamespace
import ast
import json
import sqlite3
import unittest
from unittest.mock import patch

from wam_regtest.cli_rpc import decode
from wam_sp.psbt import PSBT, Tx
from wam_regtest.domain.preflight import verify_preflight, PREFLIGHT_REJECT_REASONS
from wam_regtest.infrastructure.tx_size import serialized_vsize
from wam_regtest.wallet_session import (
    WalletSession, WalletSessionError, _verify_session_preflight,
)
from wam_regtest.bip39_spend_session import Q06OwnedSpendSession


class PreflightVerification(unittest.TestCase):
    def test_domain_preflight_has_no_transport_or_runtime_imports(self):
        source = Path(__file__).resolve().parents[1] / 'src/wam_regtest/domain/preflight.py'
        forbidden = {'infrastructure', 'wam_sp', 'PySide6', 'PyQt6', 'PySide2', 'PyQt5'}
        for node in ast.walk(ast.parse(source.read_text())):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or '', *(alias.name for alias in node.names)]
            else:
                continue
            for module in modules:
                self.assertFalse(forbidden.intersection(module.split('.')), module)

    def setUp(self):
        # Fixed consensus bytes, with a final key-path witness. Synthetic PSBT
        # wrapper only; vsize and txid use real serialized transaction bytes.
        self.tx = Tx((('11' * 32, 0),), ((9000, b'\x51\x20' + bytes(32)),))
        self.raw = self.tx.serialize([(bytes(65),)])
        self.txid = sha256(sha256(self.tx.serialize()).digest()).digest()[::-1].hex()
        self.wtxid = sha256(sha256(self.raw).digest()).digest()[::-1].hex()
        self.vsize = serialized_vsize(self.raw)
        self.review = SimpleNamespace(fee=1000, vsize=self.vsize,
                                     rate_atoms_per_kvb=1000, commitment='c' * 64)
        self.reply = [{'allowed': True, 'txid': self.txid, 'wtxid': self.wtxid, 'vsize': self.vsize,
                       'fees': {'base': Decimal('0.00001000'),
                                'effective-feerate': Decimal(1000000 // self.vsize).scaleb(-8),
                                'effective-includes': [self.wtxid]}}]
        self.psbt = SimpleNamespace(finalize=lambda: self.raw, txid=lambda: self.txid, tx=self.tx)
        self.decode_patch = patch.object(PSBT, 'decode', return_value=self.psbt)
        self.decode_patch.start()
        self.addCleanup(self.decode_patch.stop)

    def check(self, reply=None, review=None):
        review = self.review if review is None else review
        return verify_preflight(self.reply if reply is None else reply,
                                txid=self.txid, wtxid=self.wtxid, vsize=self.vsize,
                                fee_atoms=review.fee,
                                quoted_rate_atoms_per_kvb=review.rate_atoms_per_kvb)

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
        signed_body = dict(
            signed_psbt=b'signed'.hex(), commitment='c' * 64, recipient='r', atoms=9000, fee=1000)

        def read_evidence(*args):
            # Signed evidence only. An 'uncertain' or 'broadcast' record is the
            # PM-088 write-ahead and is refused before this fixture's preflight.
            stage = args[1] if len(args) > 1 else None
            if stage in ('uncertain', 'broadcast'):
                return None
            return signed_body

        session._read_payment_evidence = read_evidence
        if resume:
            # resume_signed_intent reads locked (ring) and the reservation
            # rows before any preflight RPC. This fixture is a provably
            # never-submitted 'signed' intent.
            session.ring = SimpleNamespace()
            db = sqlite3.connect(':memory:')
            db.execute("CREATE TABLE reservations(txid TEXT, vout INT, token TEXT,"
                       " state TEXT, created INT)")
            db.execute("INSERT INTO reservations VALUES (?,?,?,?,0)",
                       ('11' * 32, 0, 'a' * 32, 'signed'))
            session.scanner = SimpleNamespace(
                store=SimpleNamespace(db=db, transaction=nullcontext))
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

    def test_mismatches_latch_on_both_paths(self):
        cases = [('wtxid', 'f' * 64), ('wtxid', self.txid),
                 ('wtxid', None), ('wtxid', 42), ('wtxid', 'x' * 64),
                 ('txid', 'f' * 64), ('txid', 'x' * 64), ('txid', None),
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
        for path in ('txid', 'wtxid', 'vsize', 'fees', 'fees.base',
                     'fees.effective-feerate', 'fees.effective-includes'):
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
        rpc = SimpleNamespace(call=lambda *args: self.reply)
        self.review.vsize += 1
        with self.assertRaises(ValueError):
            _verify_session_preflight(rpc, b'signed', self.review)
        self.review.vsize = None
        self.assertIsNone(_verify_session_preflight(rpc, b'signed', self.review))
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

    def test_effective_includes_binds_witness_hash_not_txid(self):
        self.assertNotEqual(self.txid, self.wtxid)
        self.assertIsNone(self.check())
        self.reply[0]['fees']['effective-includes'] = [self.txid]
        self.assert_latched_both(self.reply)

    def test_coherent_reply_cannot_substitute_a_different_witness_hash(self):
        self.reply[0]['wtxid'] = 'f' * 64
        self.reply[0]['fees']['effective-includes'] = ['f' * 64]
        self.assert_latched_both(self.reply)

    def test_final_witness_bytes_are_bound_even_when_txid_is_unchanged(self):
        # Mutate only the last signature byte, retaining non-witness txid/size.
        self.raw = self.raw[:-5] + bytes([self.raw[-5] ^ 1]) + self.raw[-4:]
        self.assertEqual(serialized_vsize(self.raw), self.vsize)
        self.assert_latched_both(self.reply)

    def test_truncated_rate_boundary_is_exact_and_keeps_quote_floor(self):
        expected = 1000000 // self.vsize
        self.assertNotEqual(1000000 % self.vsize, 0)
        for delta in (-1, 0, 1):
            self.reply[0]['fees']['effective-feerate'] = Decimal(expected + delta).scaleb(-8)
            if delta == 0:
                self.assertIsNone(self.check())
            else:
                self.assert_latched_both(self.reply)
        self.reply[0]['fees']['effective-feerate'] = Decimal(expected).scaleb(-8) + Decimal('0.000000001')
        self.assert_latched_both(self.reply)


class Rec1aTypedPreflightKeys(unittest.TestCase):
    """PM-087 REC-1a: typed keys live beside, not inside, the shared contract."""

    def test_already_in_chain_and_dust_get_their_own_typed_keys(self):
        from wam_regtest.preflight import (
            TYPED_PREFLIGHT_KEYS, typed_preflight_key, verify_preflight_typed)
        self.assertEqual(TYPED_PREFLIGHT_KEYS['txn-already-in-chain'], 'ALREADY_IN_CHAIN')
        self.assertEqual(TYPED_PREFLIGHT_KEYS['dust'], 'DUST_REJECTED')
        self.assertEqual(typed_preflight_key('txn-already-in-chain'), 'ALREADY_IN_CHAIN')
        self.assertEqual(typed_preflight_key('dust'), 'DUST_REJECTED')
        for reason, key in (('dust', 'DUST_REJECTED'),
                            ('txn-already-in-chain', 'ALREADY_IN_CHAIN'),
                            ('txn-already-in-mempool', 'ALREADY_IN_MEMPOOL'),
                            ('min relay fee not met', 'FEE_POLICY_REJECTED'),
                            ('non-final', 'POLICY_REJECTED'),
                            ('unseen private reason', 'POLICY_REJECTED')):
            with self.subTest(reason=reason):
                self.assertEqual(
                    verify_preflight_typed(
                        [{'allowed': False, 'reject-reason': reason}],
                        txid=None, wtxid=None, vsize=None, fee_atoms=None), key)

    def test_shared_domain_mapping_and_fee_behaviour_unchanged(self):
        from wam_regtest.domain.preflight import PREFLIGHT_REJECT_REASONS
        self.assertNotIn('dust', PREFLIGHT_REJECT_REASONS)
        self.assertNotIn('txn-already-in-chain', PREFLIGHT_REJECT_REASONS)
        reply = [{'allowed': False, 'reject-reason': 'dust'}]
        self.assertEqual(verify_preflight(reply, txid=None, wtxid=None,
                                          vsize=None, fee_atoms=None),
                         'POLICY_REJECTED')


class FE007CapturedReplies(unittest.TestCase):
    """Replay exact Core stdout with independently captured transaction facts.

    Core's P2WPKH fixtures are outside Fusion's P2TR-only size parser. Supply
    their independently measured vsize here; PreflightVerification above keeps
    the real wallet serializer/size checks on Fusion-format witness bytes.
    """
    def setUp(self):
        self.fixture = json.loads((Path(__file__).parent / 'fixtures' /
                                  'fe007_v013_preflight.json').read_text())

    def test_accepted_one_and_two_input_exact_core_replies(self):
        for name, fee in (('accept-1in2out', 2000), ('accept-2in2out', 3000)):
            with self.subTest(name=name):
                capture = self.fixture['accepted_raw'][name]
                raw = bytes.fromhex(capture['hex'])
                txid = capture['decoded']['txid']
                vsize = capture['decoded']['vsize']
                reply = decode(self.fixture['replies']['tma:' + name].encode(),
                               'testmempoolaccept', [])
                self.assertNotEqual(txid, capture['decoded']['hash'])
                facts = dict(txid=txid,
                             wtxid=sha256(sha256(raw).digest()).digest()[::-1].hex(),
                             vsize=vsize, fee_atoms=fee, quoted_rate_atoms_per_kvb=2000)
                with localcontext() as ctx:
                    ctx.prec = 2
                    self.assertIsNone(verify_preflight(reply, **facts))
                reply[0]['fees']['effective-feerate'] += Decimal('0.00000001')
                with self.assertRaises(ValueError):
                    verify_preflight(reply, **facts)

    def test_exact_core_rejections_need_no_economics_or_details(self):
        expected = {
            'reject-below-min-relay': 'FEE_POLICY_REJECTED',
            'reject-input-spent-confirmed': 'INPUT_SPENT_OR_CONFLICTED',
            'reject-non-final-locktime': 'POLICY_REJECTED',
            'reject-maxfeerate-default': 'POLICY_REJECTED',
            'already-in-mempool': 'ALREADY_IN_MEMPOOL',
            'rbf-boundary-minus1': 'FEE_POLICY_REJECTED',
            'rbf-adds-unconfirmed-input': 'CONFLICT_REJECTED',
        }
        for name, token in expected.items():
            with self.subTest(name=name):
                reply = decode(self.fixture['replies']['tma:' + name].encode(),
                               'testmempoolaccept', [])
                self.assertEqual(set(reply[0]), {'txid', 'wtxid', 'allowed', 'reject-reason'})
                self.assertEqual(verify_preflight(reply, txid=None, wtxid=None,
                                                 vsize=None, fee_atoms=None), token)
        for reason in ('bad-txns-inputs-missingorspent', 'UNKNOWN', None):
            reply = [{'allowed': False, 'reject-reason': reason}]
            self.assertEqual(verify_preflight(reply, txid=None, wtxid=None,
                                             vsize=None, fee_atoms=None), 'POLICY_REJECTED')
