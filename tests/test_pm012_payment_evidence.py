"""PM-012 characterization of Q06 payment evidence at 5431219.

GUI-free. Drives Q06OwnedSpendSession._retain_signed_payment and
_read_payment_evidence with a disposable PSBT and a fake owner. No Core.

Pins the evidence directory, ``<token>-<stage>.enc`` names, sealed JSON,
seal password and purpose, create-only refusal, read refusals for a
mismatched token, stage or txid, and the fault latch when sealing fails.
Product source is unchanged.
"""
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mnemonic import Mnemonic
from wam_regtest.bip39_12 import Bip39Regtest12Keys
from wam_regtest.wallet_session import PaymentReview
from wam_sp.core import Input, pub, send
from wam_sp.psbt import PSBT
from wam_sp.transaction import p2wpkh
from wam_sp.scanner import Scanner
from wam_sp.wallet import Intent, Signer, Wallet
from wam_sp.watcher import GENESIS

SOURCE = Path(importlib.util.find_spec('wam_sp').origin).resolve().parents[2]
PASSWORD = b'pm012 disposable evidence password'
BINDING = 'public-test-binding'
COMMITMENT = 'cd' * 32
PRESERVED = 'Q06_PAYMENT_EVIDENCE_PRESERVED_NO_RETRY'
INVALID = 'Q06_PAYMENT_EVIDENCE_INVALID'
DIRECTORY_NAME = 'q06-payment-evidence'


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
        raise ValueError('PM012_SYNTHETIC_RPC_METHOD_DENIED')


@unittest.skipUnless(sys.platform == 'darwin', 'native macOS private storage')
class PaymentEvidenceCharacterization(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pm012-evidence-')
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
        account = self.keys.accounts()[0]
        funding = Input(
            '05' * 32, 0, p2wpkh(91),
            witness=(bytes(72), pub(91)), secret=91)
        output = send([funding], [account.payment_code()])[0]
        block = {
            'height': 1,
            'hash': sha256(b'pm012 synthetic evidence chain').hexdigest(),
            'previousblockhash': GENESIS,
            'tx': [{
                'txid': 'ab' * 32,
                'vin': [{
                    'txid': funding.txid, 'vout': 0,
                    'scriptSig': {'hex': ''},
                    'txinwitness': [item.hex() for item in funding.witness],
                    'prevout': {'scriptPubKey': {'hex': funding.script.hex()}},
                }],
                'vout': [{
                    'n': 0, 'value': 0.001,
                    'scriptPubKey': {'hex': (b'\x51\x20' + output).hex()},
                }],
            }],
        }
        scanner = Scanner(self.path / 'current.sqlite', self.keys.accounts())
        self.addCleanup(scanner.close)
        scanner.sync(_Chain(block))
        scanner.assert_current()
        self.intent = Intent(recipient.accounts()[0].payment_code(), 50_000)
        proposal = Wallet(scanner).propose((self.intent,), 1000)
        signer = Signer(self.keys)
        self.prepared = signer.prepare(proposal)
        self.signed = signer.sign(self.prepared, (self.intent,), 1000)
        self.token = self.prepared.proposal.token
        self.txid = PSBT.decode(self.signed).txid()
        self.review = PaymentReview(
            self.intent.code, 50_000, 1000, 49_000, 1, COMMITMENT)
        self.account_id = self.keys.public_metadata()['account_id']
        for item in (
                patch('wam_regtest.bip39_spend_session._owned'),
                patch('wam_regtest.bip39_spend_session._owner_binding',
                      return_value=BINDING)):
            item.start()
            self.addCleanup(item.stop)

    def _session(self):
        from wam_regtest.bip39_spend_session import Q06OwnedSpendSession
        session = object.__new__(Q06OwnedSpendSession)
        session._q06_owner = SimpleNamespace(directory=self.path)
        session._q06_guard = SimpleNamespace(check=lambda: None)
        session._prepared = self.prepared
        session._signed = self.signed
        session._review = self.review
        session.ring = self.keys
        session._password = PASSWORD
        session.faulted = False
        session._q06_uncertain = False
        return session

    def _directory(self):
        return self.path / DIRECTORY_NAME

    def _name(self, stage):
        return self.token + '-' + stage + '.enc'

    def _expected(self, stage):
        return {
            'account_id': self.account_id,
            'atoms': 50_000,
            'commitment': COMMITMENT,
            'fee': 1000,
            'owner_binding': BINDING,
            'recipient': self.intent.code,
            'signed_psbt': self.signed.hex(),
            'stage': stage,
            'token': self.token,
            'txid': self.txid,
            'version': 1,
        }

    def _ciphertext(self, stage):
        from wam_regtest import custody
        return custody.storage().read(self._directory(), self._name(stage))

    def test_directory_name_filename_sealed_fields_and_round_trip(self):
        from wam_sp.keystore import unseal
        session = self._session()
        session._retain_signed_payment('signed')
        directory = self._directory()
        self.assertEqual(directory.name, DIRECTORY_NAME)
        self.assertEqual(directory.parent, self.path)
        self.assertEqual(
            sorted(path.name for path in directory.iterdir()),
            [self._name('signed')])
        self.assertRegex(self.token, r'[0-9a-f]{32}')
        self.assertNotEqual(self.txid, '0' * 64)
        ciphertext = self._ciphertext('signed')
        self.assertTrue(ciphertext.startswith(b'WAMSP02\x00'))
        expected = self._expected('signed')
        plaintext = unseal(ciphertext, PASSWORD, b'recovery')
        self.assertEqual(plaintext, json.dumps(expected, sort_keys=True).encode())
        self.assertEqual(json.loads(plaintext), expected)
        self.assertIs(type(expected['version']), int)
        self.assertIs(type(expected['atoms']), int)
        self.assertIs(type(expected['fee']), int)
        with self.assertRaisesRegex(ValueError, 'BACKUP_AUTHENTICATION'):
            unseal(ciphertext, b'wrong-pm012-password', b'recovery')
        with self.assertRaisesRegex(ValueError, 'BACKUP_AUTHENTICATION'):
            unseal(ciphertext, PASSWORD, b'intent')
        self.assertEqual(session._read_payment_evidence(self.token, 'signed'), expected)
        self.assertIsNone(session._read_payment_evidence(self.token, 'broadcast'))
        self.assertIsNone(session._read_payment_evidence('ab' * 16, 'signed'))
        self.assertFalse(session.faulted)
        self.assertFalse(session._q06_uncertain)
        session._password = b'wrong-pm012-password'
        with self.assertRaisesRegex(ValueError, 'BACKUP_AUTHENTICATION'):
            session._read_payment_evidence(self.token, 'signed')
        self.assertFalse(session.faulted)
        self.assertFalse(session._q06_uncertain)

    def test_second_write_of_the_same_stage_refuses_and_preserves(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        session = self._session()
        session._retain_signed_payment('signed')
        session._retain_signed_payment('uncertain')
        signed_bytes = self._ciphertext('signed')
        uncertain_bytes = self._ciphertext('uncertain')
        self.assertEqual(
            session._read_payment_evidence(self.token, 'uncertain'),
            self._expected('uncertain'))
        self.assertFalse(session.faulted)
        self.assertFalse(session._q06_uncertain)
        with self.assertRaises(Q06SpendSessionError) as caught:
            session._retain_signed_payment('signed')
        self.assertEqual(caught.exception.args, (PRESERVED,))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(session.faulted)
        self.assertTrue(session._q06_uncertain)
        self.assertEqual(self._ciphertext('signed'), signed_bytes)
        self.assertEqual(self._ciphertext('uncertain'), uncertain_bytes)
        self.assertEqual(
            sorted(path.name for path in self._directory().iterdir()),
            [self._name('signed'), self._name('uncertain')])
        self.assertEqual(
            session._read_payment_evidence(self.token, 'signed'),
            self._expected('signed'))

    def test_mismatched_txid_on_write_refuses_without_creating_evidence(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        session = self._session()
        with self.assertRaises(Q06SpendSessionError) as caught:
            session._retain_signed_payment('signed', txid='0' * 64)
        self.assertEqual(caught.exception.args, (PRESERVED,))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(session.faulted)
        self.assertTrue(session._q06_uncertain)
        self.assertFalse(os.path.lexists(self._directory()))
        self.assertIs(session._signed, self.signed)

    def test_read_refuses_mismatched_token_stage_or_txid_without_latching(self):
        from wam_regtest import custody
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        from wam_sp.keystore import seal, unseal
        session = self._session()
        session._retain_signed_payment('signed')
        original = self._ciphertext('signed')
        plain = json.loads(unseal(original, PASSWORD, b'recovery'))
        cases = (
            ('token', 'b' * 32),
            ('stage', 'broadcast'),
            ('txid', 'c' * 64),
        )
        for field, value in cases:
            with self.subTest(field=field):
                body = dict(plain)
                body[field] = value
                self.assertNotEqual(body[field], plain[field])
                replacement = seal(
                    json.dumps(body, sort_keys=True).encode(), PASSWORD, b'recovery')
                os.unlink(self._directory() / self._name('signed'))
                custody.storage().publish(
                    self._directory(), self._name('signed'), replacement)
                with self.assertRaises(ValueError) as caught:
                    session._read_payment_evidence(self.token, 'signed')
                self.assertEqual(caught.exception.args, (INVALID,))
                self.assertNotIsInstance(caught.exception, Q06SpendSessionError)
                self.assertFalse(session.faulted)
                self.assertFalse(session._q06_uncertain)
                os.unlink(self._directory() / self._name('signed'))
                custody.storage().publish(
                    self._directory(), self._name('signed'), original)
        self.assertEqual(
            session._read_payment_evidence(self.token, 'signed'),
            self._expected('signed'))

    def test_sealing_failure_latches_uncertain_and_fault_without_a_file(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        session = self._session()
        with patch('wam_sp.keystore.seal', side_effect=RuntimeError('SEAL_DOWN')):
            with self.assertRaises(Q06SpendSessionError) as caught:
                session._retain_signed_payment('signed')
        self.assertEqual(caught.exception.args, (PRESERVED,))
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn('SEAL_DOWN', caught.exception.args)
        self.assertTrue(session.faulted)
        self.assertTrue(session._q06_uncertain)
        directory = self._directory()
        self.assertTrue(directory.is_dir())
        self.assertEqual(list(directory.iterdir()), [])
        self.assertIs(session._signed, self.signed)
