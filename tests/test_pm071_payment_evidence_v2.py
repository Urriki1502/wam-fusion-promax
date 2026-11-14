"""PM-071: evidence-only fee basis in payment evidence v2 (D-FEE2-3 Option A).

Tests the v2 sealed payment-evidence format, strict fail-closed validation,
read-only v1 legacy annotation without file modification, legacy-unrecorded
propagation on resume, evidence-only non-authority on preflight and
reservations, and canonical FeeQuote equality under fee_metadata_holds.
"""
from contextlib import nullcontext
from decimal import Decimal
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mnemonic import Mnemonic
from preflight_fixtures import accepted_reply
from wam_regtest import custody
from wam_regtest.bip39_12 import Bip39Regtest12Keys
from wam_regtest.bip39_spend_session import Q06OwnedSpendSession, Q06SpendSessionError
from wam_regtest.domain import fee_policy
from wam_regtest.domain.fee_policy import (
    FeeQuote, MAX_RATE_ATOMS_PER_KVB, fee_for_vsize, parse_policy_inputs, quote)
from wam_regtest.domain.payment_evidence import (
    DIRECTORY_NAME, PaymentEvidenceStore, SEAL_PURPOSE,
    MAX_RATE_ATOMS_PER_KVB as EVIDENCE_MAX_RATE, _fee_for_vsize, _psbt_vsize)
from wam_regtest.infrastructure.tx_size import serialized_vsize
from wam_regtest.qualification.fee_regtest_recovery import fee_metadata_holds
from wam_regtest.qualification.fee_regtest_runner import backend_type, review_evidence
from wam_regtest.wallet_session import PaymentReview, WalletSession
from wam_sp.core import Input, pub, send
from wam_sp.keystore import seal, unseal
from wam_sp.psbt import PSBT
from wam_sp.scanner import Scanner
from wam_sp.transaction import p2wpkh
from wam_sp.watcher import GENESIS

SOURCE = Path(importlib.util.find_spec('wam_sp').origin).resolve().parents[2]
ROOT = Path(__file__).resolve().parents[1]
PASSWORD = b'pm071 disposable evidence password'
BINDING = 'public-test-owner-binding'
COMMITMENT = 'cd' * 32
INVALID = 'Q06_PAYMENT_EVIDENCE_INVALID'


def _policy_fixture():
    import re
    number = re.compile(r'-?\d+(\.\d+)?(E[+-]?\d+)?\Z', re.I)

    def decimalize(value, key=None):
        if isinstance(value, dict):
            return {name: decimalize(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [decimalize(item) for item in value]
        if isinstance(value, str) and key != 'subversion' and number.match(value):
            return Decimal(value)
        return value

    return decimalize(json.loads(
        (ROOT / 'tests/fixtures/fee_rpc_regtest_v013_empty.json').read_text()))


POLICY = _policy_fixture()


def _sample_quote(*, network='regtest', floor=1000, rate=2000, reasons=('NO_FEERATE_WITHOUT_ERRORS',)):
    return FeeQuote(
        network=network,
        rate_atoms_per_kvb=rate,
        floor_atoms_per_kvb=floor,
        source='NETWORK_FLOOR_2X',
        estimator='UNAVAILABLE',
        reasons=reasons,
        inputs_digest='ab' * 32,
    )


def _v1_pre_change_check(body, *, owner_binding, account_id, token, stage):
    """Exact pre-PM-071 v1-only reader check, documenting the downgrade consequence."""
    import re
    if (type(body) is not dict or body.get('version') != 1
            or body.get('owner_binding') != owner_binding
            or body.get('account_id') != account_id
            or body.get('token') != token or body.get('stage') != stage
            or type(body.get('signed_psbt')) is not str
            or type(body.get('commitment')) is not str
            or re.fullmatch('[0-9a-f]{64}', body['commitment']) is None
            or PSBT.decode(bytes.fromhex(body['signed_psbt'])).txid() != body.get('txid')):
        raise ValueError(INVALID)
    return body


class _Chain:
    def __init__(self, block):
        self.block = block

    def attest(self):
        return None

    def call(self, method, params=None):
        if method == 'getbestblockhash':
            return self.block['hash']
        if method == 'getblockcount':
            return 1
        if method == 'getblockhash':
            return GENESIS if params[0] == 0 else self.block['hash']
        if method == 'getblock':
            return self.block
        raise ValueError('PM071_SYNTHETIC_RPC_METHOD_DENIED')


class _Core:
    def __init__(self, test):
        self.test = test
        self.mempool = set()
        self.mempoolminfee = POLICY['getmempoolinfo']['mempoolminfee']
        self.calls = []

    @property
    def verified_network(self):
        return 'regtest'

    def attest(self):
        return None

    def _call(self, method, params):
        if method == 'getrawmempool':
            return sorted(self.mempool)
        raise ValueError('PM071_RPC_DENIED')

    def call(self, method, params=None):
        self.calls.append(method)
        if method == 'getbestblockhash':
            return self.test.tip
        if method == 'getblockcount':
            return 1
        if method == 'getnetworkinfo':
            return dict(POLICY['getnetworkinfo'])
        if method == 'getmempoolinfo':
            info = dict(POLICY['getmempoolinfo'])
            info['mempoolminfee'] = self.mempoolminfee
            return info
        if method == 'estimatesmartfee':
            return dict(POLICY['estimatesmartfee_%d_conservative' % params[0]])
        if method == 'estimaterawfee':
            return POLICY['estimaterawfee_%d' % params[0]]
        if method == 'gettxout':
            return {'value': 0.001, 'scriptPubKey': {'hex': '5120' + self.test.coin['public_key']}}
        if method == 'testmempoolaccept':
            return accepted_reply(self.test.signed, fee=self.test.review.fee)
        if method == 'sendrawtransaction':
            txid = PSBT.decode(self.test.signed).txid()
            self.mempool.add(txid)
            return txid
        raise ValueError('PM071_RPC_DENIED')


class _Vault:
    def __init__(self, keys):
        self.keys = keys
        self.saved = []
        self.cipher = None
        self.anchor = SimpleNamespace(
            wallet_id='d' * 32, value=(1, 'a' * 64), lease=lambda: nullcontext())
        self.anchor.read = lambda: self.anchor.value
        self._expected = self.anchor.value

    def save(self, keys, scanner, password):
        self.saved.append(tuple(sorted(scanner.store.db.execute(
            'SELECT txid,vout,token,state,created FROM reservations').fetchall())))
        self.cipher = scanner.checkpoint(password)
        self.anchor.value = (self.anchor.value[0] + 1, sha256(self.cipher).hexdigest())
        self._expected = self.anchor.value


@unittest.skipUnless(sys.platform == 'darwin', 'native macOS private storage')
class PaymentEvidenceV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pm071-evidence-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve()
        self.keys = Bip39Regtest12Keys(
            Mnemonic('english').to_mnemonic(bytes(16)),
            source=SOURCE, authorized_disposable=True)
        recipient = Bip39Regtest12Keys(
            Mnemonic('english').to_mnemonic(bytes([1] * 16)),
            source=SOURCE, authorized_disposable=True)
        self.addCleanup(self.keys.close)
        self.addCleanup(recipient.close)
        self.code = recipient.accounts()[0].payment_code()
        funding = Input('05' * 32, 0, p2wpkh(91), witness=(bytes(72), pub(91)), secret=91)
        output = send([funding], [self.keys.accounts()[0].payment_code()])[0]
        self.block = {
            'height': 1,
            'hash': sha256(b'pm071 synthetic evidence chain').hexdigest(),
            'previousblockhash': GENESIS,
            'tx': [{
                'txid': 'ab' * 32,
                'vin': [{
                    'txid': funding.txid, 'vout': 0,
                    'scriptSig': {'hex': ''},
                    'txinwitness': [v.hex() for v in funding.witness],
                    'prevout': {'scriptPubKey': {'hex': funding.script.hex()}},
                }],
                'vout': [{
                    'n': 0, 'value': 0.001,
                    'scriptPubKey': {'hex': (b'\x51\x20' + output).hex()},
                }],
            }],
        }
        self.scanner = self._scanner('runtime.sqlite')
        self.coin = self.scanner.coins()[0]
        self.tip = self.scanner.store.tip()[1]
        self.core = _Core(self)
        self.account_id = self.keys.public_metadata()['account_id']
        for item in (
                patch('wam_regtest.bip39_spend_session._owned'),
                patch('wam_regtest.bip39_spend_session._owner_binding',
                      return_value=BINDING)):
            item.start()
            self.addCleanup(item.stop)
        self.store = PaymentEvidenceStore(self.path, custody)
        self.vault = _Vault(self.keys)
        self.session = self._session(self.scanner, self.vault)
        self.review = self.session.prepare_auto(self.code, 50_000)
        self.session.sign(self.review.commitment)
        self.signed = self.session._signed
        self.token = self.session._prepared.proposal.token
        self.txid = PSBT.decode(self.signed).txid()
        self.vsize = serialized_vsize(PSBT.decode(self.signed).finalize())

    def _scanner(self, name, cipher=None):
        scanner = Scanner(self.path / name, self.keys.accounts())
        self.addCleanup(scanner.close)
        if cipher is not None:
            scanner.restore(cipher, PASSWORD)
        scanner.sync(_Chain(self.block))
        scanner.assert_current()
        return scanner

    def _session(self, scanner, vault):
        owner = SimpleNamespace(core=self.path, directory=self.path, cli=self.path,
                                receipt={'wamd_sha256': '0' * 64})
        guard = SimpleNamespace(check=lambda: None, close=lambda: None)
        session = Q06OwnedSpendSession(owner, SOURCE, self.keys, scanner, guard, vault, PASSWORD)
        p = patch.object(WalletSession, '_rpc', lambda _self: self.core)
        p.start()
        self.addCleanup(p.stop)
        session.snapshot = lambda *a, **k: SimpleNamespace(height=1, tip=self.tip)
        return session

    def _restart(self):
        scanner = self._scanner('restart-%d.sqlite' % len(self.vault.saved), self.vault.cipher)
        return self._session(scanner, self.vault)

    def _read_raw_body(self, token, stage):
        raw = custody.storage().read(self.path / DIRECTORY_NAME, f'{token}-{stage}.enc')
        return json.loads(unseal(raw, PASSWORD, SEAL_PURPOSE))

    def _replace_sealed(self, token, stage, body):
        path = self.path / DIRECTORY_NAME / f'{token}-{stage}.enc'
        if path.exists():
            path.unlink()
        encrypted = seal(json.dumps(body, sort_keys=True).encode(), PASSWORD, SEAL_PURPOSE)
        custody.storage().publish(self.path / DIRECTORY_NAME, f'{token}-{stage}.enc', encrypted)

    def _read(self, token=None, stage='signed'):
        return self.store.read(
            self.token if token is None else token,
            stage,
            owner_binding=lambda: BINDING,
            account_id=lambda: self.account_id,
            password=PASSWORD,
        )

    def _reservations(self, scanner):
        return sorted(scanner.store.db.execute(
            'SELECT txid,vout,token,state,created FROM reservations').fetchall())

    def test_vsize_and_policy_constants_match_reference(self):
        psbt = PSBT.decode(self.signed)
        self.assertEqual(_psbt_vsize(psbt), self.vsize)
        self.assertEqual(EVIDENCE_MAX_RATE, MAX_RATE_ATOMS_PER_KVB)
        self.assertEqual(_fee_for_vsize(self.vsize, 2000), fee_for_vsize(self.vsize, 2000))

    def test_v1_file_reads_as_legacy_unrecorded_and_file_bytes_are_unchanged(self):
        v1_body = self._read_raw_body(self.token, 'signed')
        v1_body['version'] = 1
        del v1_body['fee_basis']
        self._replace_sealed(self.token, 'signed', v1_body)
        enc_path = self.path / DIRECTORY_NAME / f'{self.token}-signed.enc'
        sha_before = sha256(enc_path.read_bytes()).hexdigest()

        read_body = self._read(stage='signed')
        sha_after = sha256(enc_path.read_bytes()).hexdigest()
        self.assertEqual(sha_before, sha_after)
        self.assertEqual(read_body['version'], 1)
        self.assertEqual(read_body['fee_basis'], {'kind': 'legacy-unrecorded'})
        # On disk, the sealed plaintext stays untouched v1.
        self.assertNotIn('fee_basis', self._read_raw_body(self.token, 'signed'))

    def test_v2_round_trip_for_each_kind(self):
        # 1. kind == 'quote' (written by setUp via prepare_auto + sign)
        quoted = self._read(stage='signed')
        self.assertEqual(quoted['version'], 2)
        self.assertEqual(quoted['fee_basis']['kind'], 'quote')
        self.assertIsInstance(quoted['fee_basis']['quote']['reasons'], tuple)
        self.assertEqual(quoted['fee_basis']['quote']['rate_atoms_per_kvb'],
                         self.review.fee_quote.rate_atoms_per_kvb)

        # 2. kind == 'explicit'
        explicit_token = 'e' * 32
        explicit_review = SimpleNamespace(
            commitment=COMMITMENT, code=self.code, atoms=50_000, fee=self.review.fee)
        self.store.write('signed', signed=self.signed, review=explicit_review,
                         token=explicit_token, owner_binding=lambda: BINDING,
                         account_id=lambda: self.account_id, password=PASSWORD)
        explicit = self._read(token=explicit_token, stage='signed')
        self.assertEqual(explicit['version'], 2)
        self.assertEqual(explicit['fee_basis'], {'kind': 'explicit'})

        # 3. kind == 'legacy-unrecorded'
        legacy_token = 'f' * 32
        self.store.write('uncertain', signed=self.signed, review=explicit_review,
                         token=legacy_token, owner_binding=lambda: BINDING,
                         account_id=lambda: self.account_id, password=PASSWORD,
                         legacy_unrecorded=True)
        legacy = self._read(token=legacy_token, stage='uncertain')
        self.assertEqual(legacy['version'], 2)
        self.assertEqual(legacy['fee_basis'], {'kind': 'legacy-unrecorded'})

    def test_invalid_versions_fail_closed(self):
        base = self._read_raw_body(self.token, 'signed')
        for bad_version in (0, 3, 99, '2', True, None):
            with self.subTest(version=bad_version):
                body = dict(base, version=bad_version)
                self._replace_sealed(self.token, 'signed', body)
                with self.assertRaises(ValueError) as caught:
                    self._read(stage='signed')
                self.assertEqual(caught.exception.args, (INVALID,))

    def test_missing_or_nondict_fee_basis_is_invalid(self):
        base = self._read_raw_body(self.token, 'signed')
        missing = dict(base)
        del missing['fee_basis']
        self._replace_sealed(self.token, 'signed', missing)
        with self.assertRaises(ValueError) as caught:
            self._read(stage='signed')
        self.assertEqual(caught.exception.args, (INVALID,))

        for bad in (None, 'quote', [], 123, True):
            with self.subTest(fee_basis=bad):
                body = dict(base, fee_basis=bad)
                self._replace_sealed(self.token, 'signed', body)
                with self.assertRaises(ValueError) as caught:
                    self._read(stage='signed')
                self.assertEqual(caught.exception.args, (INVALID,))

    def test_bad_kind_is_invalid(self):
        base = self._read_raw_body(self.token, 'signed')
        for bad_kind in ('unknown', '', None, 1, 'QUOTE'):
            with self.subTest(kind=bad_kind):
                body = dict(base, fee_basis={'kind': bad_kind})
                self._replace_sealed(self.token, 'signed', body)
                with self.assertRaises(ValueError) as caught:
                    self._read(stage='signed')
                self.assertEqual(caught.exception.args, (INVALID,))

    def test_unknown_or_missing_keys_and_wrong_types_are_invalid(self):
        base = self._read_raw_body(self.token, 'signed')
        # Unknown/missing top-level key in v2
        extra_top = dict(base, extra='bad')
        self._replace_sealed(self.token, 'signed', extra_top)
        with self.assertRaises(ValueError) as caught:
            self._read(stage='signed')
        self.assertEqual(caught.exception.args, (INVALID,))

        missing_top = dict(base)
        del missing_top['recipient']
        self._replace_sealed(self.token, 'signed', missing_top)
        with self.assertRaises(ValueError) as caught:
            self._read(stage='signed')
        self.assertEqual(caught.exception.args, (INVALID,))

        # Unknown/missing key in explicit / legacy-unrecorded fee_basis
        for kind in ('explicit', 'legacy-unrecorded'):
            self._replace_sealed(self.token, 'signed', dict(base, fee_basis={'kind': kind, 'extra': 1}))
            with self.assertRaises(ValueError) as caught:
                self._read(stage='signed')
            self.assertEqual(caught.exception.args, (INVALID,))

        # Missing or extra key in quote fee_basis and inside quote dict
        self._replace_sealed(self.token, 'signed', dict(base, fee_basis={'kind': 'quote'}))
        with self.assertRaises(ValueError) as caught:
            self._read(stage='signed')
        self.assertEqual(caught.exception.args, (INVALID,))

        extra_fb = dict(base, fee_basis={'kind': 'quote', 'quote': base['fee_basis']['quote'], 'extra': 1})
        self._replace_sealed(self.token, 'signed', extra_fb)
        with self.assertRaises(ValueError) as caught:
            self._read(stage='signed')
        self.assertEqual(caught.exception.args, (INVALID,))

        for key in list(base['fee_basis']['quote']):
            with self.subTest(missing_quote_key=key):
                q = dict(base['fee_basis']['quote'])
                del q[key]
                self._replace_sealed(self.token, 'signed', dict(base, fee_basis={'kind': 'quote', 'quote': q}))
                with self.assertRaises(ValueError) as caught:
                    self._read(stage='signed')
                self.assertEqual(caught.exception.args, (INVALID,))

        q_extra = dict(base['fee_basis']['quote'], incrementalfee=1000)
        self._replace_sealed(self.token, 'signed', dict(base, fee_basis={'kind': 'quote', 'quote': q_extra}))
        with self.assertRaises(ValueError) as caught:
            self._read(stage='signed')
        self.assertEqual(caught.exception.args, (INVALID,))

        # Wrong types inside quote
        wrong_types = [
            ('network', 123),
            ('floor_atoms_per_kvb', True),
            ('floor_atoms_per_kvb', '1000'),
            ('floor_atoms_per_kvb', 1000.0),
            ('rate_atoms_per_kvb', True),
            ('rate_atoms_per_kvb', '2000'),
            ('source', 42),
            ('estimator', None),
            ('reasons', 'NO_FEERATE_WITHOUT_ERRORS'),
            ('reasons', [123]),
            ('inputs_digest', 99),
        ]
        for field, val in wrong_types:
            with self.subTest(field=field, val=val):
                q = dict(base['fee_basis']['quote'], **{field: val})
                self._replace_sealed(self.token, 'signed', dict(base, fee_basis={'kind': 'quote', 'quote': q}))
                with self.assertRaises(ValueError) as caught:
                    self._read(stage='signed')
                self.assertEqual(caught.exception.args, (INVALID,))

    def test_quote_domain_bounds_and_fee_coverage_validation(self):
        base = self._read_raw_body(self.token, 'signed')
        quote_base = dict(base['fee_basis']['quote'])

        # Network mismatch
        for net in ('mainnet', 'testnet', 'signet', ''):
            with self.subTest(network=net):
                q = dict(quote_base, network=net)
                self._replace_sealed(self.token, 'signed', dict(base, fee_basis={'kind': 'quote', 'quote': q}))
                with self.assertRaises(ValueError) as caught:
                    self._read(stage='signed')
                self.assertEqual(caught.exception.args, (INVALID,))

        # floor < 1
        for floor in (0, -1):
            with self.subTest(floor=floor):
                q = dict(quote_base, floor_atoms_per_kvb=floor)
                self._replace_sealed(self.token, 'signed', dict(base, fee_basis={'kind': 'quote', 'quote': q}))
                with self.assertRaises(ValueError) as caught:
                    self._read(stage='signed')
                self.assertEqual(caught.exception.args, (INVALID,))

        # rate < floor
        q_below_floor = dict(quote_base, floor_atoms_per_kvb=3000, rate_atoms_per_kvb=2000)
        self._replace_sealed(self.token, 'signed', dict(base, fee_basis={'kind': 'quote', 'quote': q_below_floor}))
        with self.assertRaises(ValueError) as caught:
            self._read(stage='signed')
        self.assertEqual(caught.exception.args, (INVALID,))

        # rate > MAX_RATE_ATOMS_PER_KVB
        q_over_max = dict(quote_base, rate_atoms_per_kvb=MAX_RATE_ATOMS_PER_KVB + 1)
        self._replace_sealed(self.token, 'signed', dict(base, fee_basis={'kind': 'quote', 'quote': q_over_max}))
        with self.assertRaises(ValueError) as caught:
            self._read(stage='signed')
        self.assertEqual(caught.exception.args, (INVALID,))

        # fee < fee_for_vsize(vsize(signed_psbt), recorded_rate)
        # Note: floor can be satisfied while recorded rate is NOT covered.
        recorded_rate = 2000
        need = fee_for_vsize(self.vsize, recorded_rate)
        self.assertEqual(base['fee'], need)
        q_high_rate = dict(quote_base, floor_atoms_per_kvb=1000, rate_atoms_per_kvb=recorded_rate)
        low_fee_body = dict(base, fee=need - 1, fee_basis={'kind': 'quote', 'quote': q_high_rate})
        self._replace_sealed(self.token, 'signed', low_fee_body)
        with self.assertRaises(ValueError) as caught:
            self._read(stage='signed')
        self.assertEqual(caught.exception.args, (INVALID,))

    def test_recorded_quote_stays_valid_under_later_higher_current_network_floor(self):
        # Historical quote was recorded at floor=1000, rate=2000.
        # Simulate a later, much higher current network floor (e.g. 50_000 atoms/kvB).
        self.core.mempoolminfee = Decimal('0.00050000')
        self.core.calls.clear()
        reopened = self._restart()
        body = reopened._read_payment_evidence(self.token, 'signed')
        self.assertEqual(body['version'], 2)
        self.assertEqual(body['fee_basis']['kind'], 'quote')
        self.assertEqual(body['fee_basis']['quote']['floor_atoms_per_kvb'], 1000)
        self.assertEqual(body['fee_basis']['quote']['rate_atoms_per_kvb'], 2000)
        # No RPC read was made to validate historical evidence.
        self.assertEqual(self.core.calls, [])
        status = reopened.signed_intent_status()
        self.assertEqual(status['intents'][0]['classification'], 'SIGNED_NOT_SUBMITTED_RESUMABLE')

    def test_create_only_second_write_still_fails(self):
        enc_path = self.path / DIRECTORY_NAME / f'{self.token}-signed.enc'
        before_bytes = enc_path.read_bytes()
        with self.assertRaises(Q06SpendSessionError) as caught:
            self.session._retain_signed_payment('signed')
        self.assertEqual(caught.exception.args, ('Q06_PAYMENT_EVIDENCE_PRESERVED_NO_RETRY',))
        self.assertTrue(self.session.faulted)
        self.assertTrue(self.session._q06_uncertain)
        self.assertEqual(enc_path.read_bytes(), before_bytes)

    def test_old_binary_v1_only_reader_rejects_v2_file(self):
        raw_v2 = self._read_raw_body(self.token, 'signed')
        self.assertEqual(raw_v2['version'], 2)
        with self.assertRaises(ValueError) as caught:
            _v1_pre_change_check(
                raw_v2,
                owner_binding=BINDING,
                account_id=self.account_id,
                token=self.token,
                stage='signed',
            )
        self.assertEqual(caught.exception.args, (INVALID,))

    def test_resume_of_v1_intent_writes_legacy_unrecorded_never_explicit(self):
        v1_body = self._read_raw_body(self.token, 'signed')
        v1_body['version'] = 1
        del v1_body['fee_basis']
        self._replace_sealed(self.token, 'signed', v1_body)
        signed_path = self.path / DIRECTORY_NAME / f'{self.token}-signed.enc'
        signed_sha_before = sha256(signed_path.read_bytes()).hexdigest()

        restarted = self._restart()
        result = restarted.resume_signed_intent(self.token, self.txid, approved=True)
        self.assertEqual(result['txid'], self.txid)
        self.assertEqual(sha256(signed_path.read_bytes()).hexdigest(), signed_sha_before)
        self.assertNotIn('fee_basis', self._read_raw_body(self.token, 'signed'))

        for stage in ('uncertain', 'broadcast'):
            raw_stage = self._read_raw_body(self.token, stage)
            self.assertEqual(raw_stage['version'], 2)
            self.assertEqual(raw_stage['fee_basis'], {'kind': 'legacy-unrecorded'})
            self.assertNotEqual(raw_stage['fee_basis']['kind'], 'explicit')

    def test_resume_review_has_no_rate_or_vsize_attributes_and_preflight_receives_none(self):
        restarted = self._restart()
        seen_reviews = []
        from wam_regtest import bip39_spend_session as spend_mod
        original_preflight = spend_mod._verify_session_preflight

        def spy_preflight(rpc, signed, review):
            seen_reviews.append(review)
            self.assertFalse(hasattr(review, 'rate_atoms_per_kvb'))
            self.assertFalse(hasattr(review, 'vsize'))
            self.assertIsInstance(review.fee_quote, FeeQuote)
            return original_preflight(rpc, signed, review)

        with patch.object(spend_mod, '_verify_session_preflight', side_effect=spy_preflight):
            result = restarted.resume_signed_intent(self.token, self.txid, approved=True)

        self.assertEqual(result['txid'], self.txid)
        self.assertEqual(len(seen_reviews), 1)
        for stage in ('uncertain', 'broadcast'):
            stage_body = restarted._read_payment_evidence(self.token, stage)
            self.assertEqual(stage_body['version'], 2)
            self.assertEqual(stage_body['fee_basis']['kind'], 'quote')
            self.assertEqual(stage_body['fee_basis']['quote'],
                             self._read(stage='signed')['fee_basis']['quote'])

    def test_reservations_are_untouched_by_evidence_reads_and_writes(self):
        restarted = self._restart()
        before = self._reservations(restarted.scanner)
        self.assertTrue(before)
        self.assertEqual({row[3] for row in before}, {'signed'})

        # Reading signed evidence and writing/reading a separate evidence file do not alter reservations.
        self._read(stage='signed')
        restarted._read_payment_evidence(self.token, 'signed')
        extra_review = SimpleNamespace(
            commitment=COMMITMENT, code=self.code, atoms=50_000, fee=self.review.fee,
            fee_quote=self.review.fee_quote)
        self.store.write('uncertain', signed=self.signed, review=extra_review,
                         token='a' * 32, owner_binding=lambda: BINDING,
                         account_id=lambda: self.account_id, password=PASSWORD)
        self.store.read('a' * 32, 'uncertain', owner_binding=lambda: BINDING,
                        account_id=lambda: self.account_id, password=PASSWORD)
        self.assertEqual(self._reservations(restarted.scanner), before)

    def test_canonical_quote_equality_under_fee_metadata_holds(self):
        Backend = backend_type()
        backend = object.__new__(Backend)
        backend._spend_session = self.session
        signed_ev = backend.signed_evidence()
        in_memory_ev = review_evidence(self.review)

        self.assertIsInstance(in_memory_ev['fee_quote']['reasons'], tuple)
        self.assertIsInstance(signed_ev['fee_quote']['reasons'], tuple)
        self.assertTrue(fee_metadata_holds(signed_ev['fee_quote'], in_memory_ev['fee_quote']))

        # Also verify non-empty reasons tuple round-trips canonically through JSON.
        inputs = parse_policy_inputs(
            'regtest',
            POLICY['getnetworkinfo'],
            POLICY['getmempoolinfo'],
            {2: {'blocks': 2, 'errors': ['insufficient']},
             6: {'blocks': 6, 'errors': ['insufficient']},
             25: {'blocks': 25, 'errors': ['insufficient']}},
            {6: None},
        )
        quoted = quote(inputs)
        self.assertEqual(quoted.reasons, ('NO_FEERATE_WITHOUT_ERRORS',))
        token = 'b' * 32
        review = PaymentReview(
            self.code, 50_000, self.review.fee, 49_000, 1, COMMITMENT,
            rate_atoms_per_kvb=quoted.rate_atoms_per_kvb,
            rate_source=quoted.source,
            rate_classification=quoted.estimator,
            vsize=self.vsize,
            total_debit=50_000 + self.review.fee,
            available_before=100_000,
            available_after=0,
            overpay_atoms=0,
            fee_quote=quoted,
            replaceable=True,
        )
        self.store.write('signed', signed=self.signed, review=review, token=token,
                         owner_binding=lambda: BINDING, account_id=lambda: self.account_id,
                         password=PASSWORD)
        persisted = self.store.read(token, 'signed', owner_binding=lambda: BINDING,
                                    account_id=lambda: self.account_id, password=PASSWORD)
        self.assertTrue(fee_metadata_holds(
            persisted['fee_basis']['quote'], review_evidence(review)['fee_quote']))

        # Explicit and legacy-unrecorded return fee_quote=None in signed_evidence and never pass fee_metadata_holds.
        v1_body = self._read_raw_body(self.token, 'signed')
        v1_body['version'] = 1
        del v1_body['fee_basis']
        self._replace_sealed(self.token, 'signed', v1_body)
        v1_ev = backend.signed_evidence()
        self.assertIsNone(v1_ev['fee_quote'])
        self.assertFalse(fee_metadata_holds(v1_ev['fee_quote'], in_memory_ev['fee_quote']))

    def test_fresh_broadcast_persists_v2_quote_across_all_stages(self):
        txid = self.session.broadcast(self.review.commitment)
        self.assertEqual(txid, self.txid)
        expected_quote = review_evidence(self.review)['fee_quote']
        for stage in ('signed', 'uncertain', 'broadcast'):
            body = self._read(stage=stage)
            self.assertEqual(body['version'], 2)
            self.assertEqual(body['fee_basis'], {'kind': 'quote', 'quote': expected_quote})

    def test_invalid_v2_quote_fails_closed_without_changing_reservations(self):
        base = self._read_raw_body(self.token, 'signed')
        tampered_quote = dict(base['fee_basis']['quote'], rate_atoms_per_kvb=100_000)
        tampered = dict(base, fee_basis={'kind': 'quote', 'quote': tampered_quote})
        self._replace_sealed(self.token, 'signed', tampered)

        restarted = self._restart()
        before = self._reservations(restarted.scanner)
        status = restarted.signed_intent_status()
        self.assertEqual(status['intents'][0]['classification'], 'OPERATOR_REVIEW_EVIDENCE_INVALID')
        with self.assertRaises(Q06SpendSessionError) as caught:
            restarted.resume_signed_intent(self.token, self.txid, approved=True)
        self.assertEqual(caught.exception.args, ('Q06_RESUME_NOT_ELIGIBLE',))
        self.assertEqual(self._reservations(restarted.scanner), before)


if __name__ == '__main__':
    unittest.main()
