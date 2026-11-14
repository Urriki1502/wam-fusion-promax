"""PM-006 characterization of the payment state machine at cac1184.

GUI-free. Drives Q06OwnedSpendSession with the real reservation store, signer
and create-only evidence files, and a fake Core. No product change.

Pins the transitions the app relies on today: draft cancel, signed evidence,
write-ahead uncertain before submission, broadcast failure with no retry,
explicit resume of a signed or uncertain intent without re-signing, confirm
success and ambiguity, and exactly-one pending-broadcast recovery.
"""
from preflight_fixtures import accepted_reply
from contextlib import contextmanager, nullcontext
from hashlib import sha256
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mnemonic import Mnemonic
from wam_regtest.bip39_12 import Bip39Regtest12Keys
from wam_sp.core import Input, pub, send
from wam_sp.psbt import PSBT
from wam_sp.scanner import Scanner
from wam_sp.transaction import p2wpkh
from wam_sp.wallet import Signer
from wam_sp.watcher import GENESIS

SOURCE = Path(importlib.util.find_spec('wam_sp').origin).resolve().parents[2]
PASSWORD = b'pm006 disposable public test password'
EVIDENCE_ORDER = ('signed', 'uncertain', 'broadcast')
TX_A, TX_B = 'a' * 64, 'b' * 64
IN_1, IN_2 = ('1' * 64, 0), ('2' * 64, 1)


def _states(scanner):
    return tuple(row[0] for row in scanner.store.db.execute(
        'SELECT state FROM reservations ORDER BY txid, vout'))


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
        raise ValueError('PM006_SYNTHETIC_RPC_METHOD_DENIED')


class _Core:
    """Fake Core. Records the durable picture at sendrawtransaction entry."""

    def __init__(self, test):
        self.test = test
        self.mempool = set()
        self.send = None
        self.on_submit = None
        self.at_submit = []
        self.submit_attempts = 0
        self.mine_attempts = 0
        self.mine_error = None
        self.height = 1

    def attest(self):
        return None

    def _call(self, method, params):
        if method == 'getrawmempool':
            return sorted(self.mempool)
        if method == 'generatetoaddress':
            self.mine_attempts += 1
            if self.mine_error is not None:
                raise self.mine_error
            self.height += 1
            return [self.test.tip]
        raise ValueError('PM006_RPC_DENIED')

    def call(self, method, params=None):
        if method == 'getbestblockhash':
            return self.test.tip
        if method == 'getblockcount':
            return self.height
        if method == 'gettxout':
            return {'value': 0.001,
                    'scriptPubKey': {'hex': '5120' + self.test.coin['public_key']}}
        if method == 'testmempoolaccept':
            return accepted_reply(self.test.signed)
        if method == 'sendrawtransaction':
            self.submit_attempts += 1
            if self.on_submit is not None:
                self.at_submit.append(self.on_submit())
            if isinstance(self.send, BaseException):
                raise self.send
            txid = PSBT.decode(self.test.signed).txid()
            self.mempool.add(txid)
            return txid
        raise ValueError('PM006_RPC_DENIED')


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
        self.saved.append(set(_states(scanner)))
        self.cipher = scanner.checkpoint(password)
        self.anchor.value = (self.anchor.value[0] + 1, sha256(self.cipher).hexdigest())
        self._expected = self.anchor.value


@unittest.skipUnless(sys.platform == 'darwin', 'native macOS encrypted evidence storage')
class PaymentStateMachine(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='pm006-')
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name).resolve()
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
            'height': 1, 'hash': sha256(b'pm006 synthetic chain').hexdigest(),
            'previousblockhash': GENESIS, 'tx': [{
                'txid': 'ab' * 32,
                'vin': [{'txid': funding.txid, 'vout': 0, 'scriptSig': {'hex': ''},
                         'txinwitness': [item.hex() for item in funding.witness],
                         'prevout': {'scriptPubKey': {'hex': funding.script.hex()}}}],
                'vout': [{'n': 0, 'value': 0.001,
                          'scriptPubKey': {'hex': (b'\x51\x20' + output).hex()}}]}],
        }
        self.scanner = self._open_scanner('runtime.sqlite')
        self.scanner.sync(_Chain(self.block))
        self.scanner.assert_current()
        self.coin = self.scanner.coins()[0]
        self.tip = self.scanner.store.tip()[1]
        self.core = _Core(self)
        self.sign_calls = 0
        original = Signer.sign

        def counting(signer, *args, **kwargs):
            self.sign_calls += 1
            return original(signer, *args, **kwargs)

        for item in (
                patch.object(Signer, 'sign', counting),
                patch('wam_regtest.bip39_spend_session._owned'),
                patch('wam_regtest.bip39_spend_session._owner_binding',
                      return_value='public-test-owner-binding'),
                patch('wam_regtest.wallet_session.WalletSession._rpc',
                      lambda _self: self.core)):
            item.start()
            self.addCleanup(item.stop)

    def _open_scanner(self, name, cipher=None):
        scanner = Scanner(self.path / name, self.keys.accounts())
        self.addCleanup(scanner.close)
        if cipher is not None:
            scanner.restore(cipher, PASSWORD)
        return scanner

    def _session(self, scanner, vault):
        from wam_regtest.bip39_spend_session import Q06OwnedSpendSession
        owner = SimpleNamespace(
            core=self.path, directory=self.path, cli=self.path,
            receipt={'wamd_sha256': '0' * 64})
        guard = SimpleNamespace(check=lambda: None, close=lambda: None)
        session = Q06OwnedSpendSession(
            owner, SOURCE, self.keys, scanner, guard, vault, PASSWORD)
        session.snapshot = lambda *args, **kwargs: SimpleNamespace(height=1, tip=self.tip)
        return session

    def _evidence(self, token):
        directory = self.path / 'q06-payment-evidence'
        return tuple(stage for stage in EVIDENCE_ORDER
                     if os.path.lexists(directory / (token + '-' + stage + '.enc')))

    def _picture(self, session, token):
        return {
            'states': _states(session.scanner),
            'evidence': self._evidence(token),
            'prepared': session._prepared is not None,
            'signed': session._signed is not None,
            'review': session._review is not None,
            'faulted': session.faulted,
            'uncertain': session._q06_uncertain,
            'pending': session._q06_pending_confirm,
            'payment_signed': session.payment_signed,
            'pending_confirm_txid': session.pending_confirm_txid,
        }

    def _prepare(self):
        self.vault = _Vault(self.keys)
        session = self._session(self.scanner, self.vault)
        review = session.prepare(self.code, 50_000, 1000)
        self.token = session._prepared.proposal.token
        return session, review

    def _sign(self):
        session, review = self._prepare()
        session.sign(review.commitment)
        self.signed = session._signed
        self.txid = PSBT.decode(self.signed).txid()
        return session, review

    def _restart(self):
        # Same recovery the TX-03 tests use: restore the anchored checkpoint,
        # then sync the fake chain so the scanner is current before resume.
        scanner = self._open_scanner('restart.sqlite', self.vault.cipher)
        scanner.sync(_Chain(self.block))
        scanner.assert_current()
        return self._session(scanner, self.vault)

    def _arm_submit(self, session):
        token = self.token
        self.core.on_submit = lambda: self._picture(session, token)

    def test_prepare_cancel_releases_the_draft(self):
        session, _review = self._prepare()
        self.assertEqual(self._picture(session, self.token), {
            'states': ('draft',), 'evidence': (),
            'prepared': True, 'signed': False, 'review': True,
            'faulted': False, 'uncertain': False, 'pending': None,
            'payment_signed': False, 'pending_confirm_txid': None,
        })
        self.assertEqual(self.sign_calls, 0)
        session.cancel()
        self.assertEqual(self._picture(session, self.token), {
            'states': (), 'evidence': (),
            'prepared': False, 'signed': False, 'review': False,
            'faulted': False, 'uncertain': False, 'pending': None,
            'payment_signed': False, 'pending_confirm_txid': None,
        })
        self.assertEqual(self.core.submit_attempts, 0)

    def test_prepare_sign_records_signed_reservation_and_evidence(self):
        session, _review = self._sign()
        self.assertEqual(self.sign_calls, 1)
        self.assertEqual(self._picture(session, self.token), {
            'states': ('signed',), 'evidence': ('signed',),
            'prepared': True, 'signed': True, 'review': True,
            'faulted': False, 'uncertain': False, 'pending': None,
            'payment_signed': True, 'pending_confirm_txid': None,
        })
        self.assertTrue((self.path / 'q06-payment-evidence'
                         / (self.token + '-signed.enc')).is_file())
        self.assertEqual(self.core.submit_attempts, 0)

    def test_broadcast_writes_uncertain_before_submission_then_sets_pending(self):
        session, review = self._sign()
        self._arm_submit(session)
        txid = session.broadcast(review.commitment)
        self.assertEqual(txid, self.txid)
        self.assertEqual(self.core.submit_attempts, 1)
        self.assertEqual(self.core.at_submit, [{
            'states': ('uncertain',), 'evidence': ('signed', 'uncertain'),
            'prepared': True, 'signed': True, 'review': True,
            'faulted': False, 'uncertain': False, 'pending': None,
            'payment_signed': True, 'pending_confirm_txid': None,
        }])
        self.assertEqual(self.vault.saved[-2:], [{'uncertain'}, {'broadcast'}])
        self.assertEqual(self._picture(session, self.token), {
            'states': ('broadcast',),
            'evidence': ('signed', 'uncertain', 'broadcast'),
            'prepared': False, 'signed': False, 'review': False,
            'faulted': False, 'uncertain': False, 'pending': self.txid,
            'payment_signed': False, 'pending_confirm_txid': self.txid,
        })
        self.assertEqual(self.sign_calls, 1)

    def test_broadcast_rpc_failure_keeps_uncertain_and_does_not_retry(self):
        from wam_regtest.wallet_session import WalletSessionError
        session, review = self._sign()
        self.core.send = RuntimeError('PUBLIC_TRANSPORT_LOSS')
        self._arm_submit(session)
        with self.assertRaises(WalletSessionError) as caught:
            session.broadcast(review.commitment)
        self.assertEqual(caught.exception.args, ('WALLET_BROADCAST_UNCERTAIN_LOCK_RETAINED',))
        self.assertEqual(self.core.at_submit[0]['states'], ('uncertain',))
        self.assertEqual(self.core.at_submit[0]['evidence'], ('signed', 'uncertain'))
        self.assertEqual(self._picture(session, self.token), {
            'states': ('uncertain',), 'evidence': ('signed', 'uncertain'),
            'prepared': True, 'signed': False, 'review': True,
            'faulted': True, 'uncertain': False, 'pending': None,
            'payment_signed': False, 'pending_confirm_txid': None,
        })
        with self.assertRaises(WalletSessionError) as retry:
            session.broadcast(review.commitment)
        self.assertEqual(retry.exception.args, ('WALLET_BROADCAST_APPROVAL_REQUIRED',))
        self.assertEqual(self.core.submit_attempts, 1)
        self.assertEqual(self.sign_calls, 1)
        self.assertEqual(_states(session.scanner), ('uncertain',))

    def test_resume_signed_intent_requires_approval_and_never_resigns(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        session, _review = self._sign()
        with self.assertRaisesRegex(Q06SpendSessionError, 'SESSION_NOT_IDLE'):
            session.resume_signed_intent(self.token, self.txid, approved=True)
        self.assertEqual(self.core.submit_attempts, 0)
        self.assertEqual(_states(session.scanner), ('signed',))
        restarted = self._restart()
        before = self._picture(restarted, self.token)
        self.assertEqual(before['states'], ('signed',))
        self.assertEqual(before['evidence'], ('signed',))
        self.assertFalse(before['prepared'] or before['signed'] or before['faulted'])
        with self.assertRaisesRegex(Q06SpendSessionError, 'EXPLICIT_APPROVAL_REQUIRED'):
            restarted.resume_signed_intent(self.token, self.txid)
        self.assertEqual(self._picture(restarted, self.token), before)
        self.assertEqual(self.core.submit_attempts, 0)
        signs = self.sign_calls
        self._arm_submit(restarted)
        result = restarted.resume_signed_intent(self.token, self.txid, approved=True)
        self.assertEqual(result['resigned'], False)
        self.assertEqual(result['automatic'], False)
        self.assertEqual(result['txid'], self.txid)
        self.assertEqual(self.sign_calls, signs)
        self.assertEqual(self.core.submit_attempts, 1)
        self.assertEqual(self.core.at_submit[0]['states'], ('uncertain',))
        self.assertEqual(self.core.at_submit[0]['evidence'], ('signed', 'uncertain'))
        self.assertIsNone(self.core.at_submit[0]['pending'])
        self.assertEqual(self._picture(restarted, self.token), {
            'states': ('broadcast',),
            'evidence': ('signed', 'uncertain', 'broadcast'),
            'prepared': False, 'signed': False, 'review': False,
            'faulted': False, 'uncertain': False, 'pending': self.txid,
            'payment_signed': False, 'pending_confirm_txid': self.txid,
        })

    def test_resume_uncertain_intent_requires_approval_and_never_resigns(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        from wam_regtest.wallet_session import WalletSessionError
        session, review = self._sign()
        self.core.send = RuntimeError('PUBLIC_TRANSPORT_LOSS')
        with self.assertRaisesRegex(WalletSessionError, 'UNCERTAIN_LOCK_RETAINED'):
            session.broadcast(review.commitment)
        self.core.send = None
        restarted = self._restart()
        before = self._picture(restarted, self.token)
        self.assertEqual(before['states'], ('uncertain',))
        self.assertEqual(before['evidence'], ('signed', 'uncertain'))
        self.assertIsNone(before['pending'])
        with self.assertRaisesRegex(Q06SpendSessionError, 'EXPLICIT_APPROVAL_REQUIRED'):
            restarted.resume_signed_intent(self.token, self.txid, approved=False)
        self.assertEqual(self._picture(restarted, self.token), before)
        signs = self.sign_calls
        self._arm_submit(restarted)
        result = restarted.resume_signed_intent(self.token, self.txid, approved=True)
        self.assertEqual((result['txid'], result['resigned'], result['automatic']),
                         (self.txid, False, False))
        self.assertEqual(self.sign_calls, signs)
        self.assertEqual(self.core.submit_attempts, 2)
        self.assertEqual(self.core.at_submit[0]['states'], ('uncertain',))
        self.assertNotIn('broadcast', self.core.at_submit[0]['evidence'])
        self.assertEqual(self._picture(restarted, self.token)['states'], ('broadcast',))
        self.assertEqual(self._picture(restarted, self.token)['evidence'],
                         ('signed', 'uncertain', 'broadcast'))
        self.assertEqual(self._picture(restarted, self.token)['pending'], self.txid)
        self.assertFalse(restarted.faulted or restarted._q06_uncertain)

    def test_confirm_pending_success_mines_once_and_keeps_broadcast(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        session, review = self._sign()
        session.broadcast(review.commitment)
        before = self._picture(session, self.token)
        session.snapshot = lambda *args, **kwargs: SimpleNamespace(
            height=self.core.height, tip=self.tip,
            history=(SimpleNamespace(txid=self.txid, confirmations=1),))
        receipt = session.confirm_pending(self.txid)
        self.assertEqual(receipt['status'], 'Q06_REGTEST_EXACT_SEND_CONFIRMED')
        self.assertEqual(receipt['txid'], self.txid)
        self.assertEqual(self.core.mine_attempts, 1)
        after = self._picture(session, self.token)
        self.assertEqual(after['states'], ('broadcast',))
        self.assertEqual(after['evidence'], before['evidence'])
        self.assertIsNone(after['pending'])
        self.assertFalse(after['faulted'] or after['uncertain'] or after['payment_signed'])
        with self.assertRaisesRegex(Q06SpendSessionError, 'EXACT_PENDING_TX_REQUIRED'):
            session.confirm_pending(self.txid)
        self.assertEqual(self.core.mine_attempts, 1)
        self.assertEqual(_states(session.scanner), ('broadcast',))

    def test_confirm_pending_ambiguity_latches_and_does_not_mine_again(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        session, review = self._sign()
        session.broadcast(review.commitment)
        self.core.mine_error = RuntimeError('MUTATION_OUTCOME_UNKNOWN')
        with self.assertRaisesRegex(Q06SpendSessionError, 'Q06_CONFIRM_UNCERTAIN_NO_RETRY'):
            session.confirm_pending(self.txid)
        self.assertEqual(self.core.mine_attempts, 1)
        picture = self._picture(session, self.token)
        self.assertEqual(picture['states'], ('broadcast',))
        self.assertTrue(picture['faulted'] and picture['uncertain'])
        self.assertEqual(picture['pending'], self.txid)
        self.assertEqual(picture['evidence'], ('signed', 'uncertain', 'broadcast'))
        with self.assertRaises(Q06SpendSessionError):
            session.confirm_pending(self.txid)
        self.assertEqual(self.core.mine_attempts, 1)
        self.assertEqual(_states(session.scanner), ('broadcast',))

    def test_reopen_restores_exactly_one_pending_broadcast(self):
        session, review = self._sign()
        session.broadcast(review.commitment)
        self.assertIsNotNone(session.pending_confirm_txid)
        reopened = self._restart()
        self.assertIsNone(reopened.pending_confirm_txid)
        seen = []
        original = reopened._read_payment_evidence

        def recording(token, stage):
            seen.append((token, stage))
            return original(token, stage)

        reopened._read_payment_evidence = recording
        states_before = _states(reopened.scanner)
        signs = self.sign_calls
        restored = reopened._recover_pending_broadcast()
        self.assertEqual(restored, self.txid)
        self.assertEqual(reopened.pending_confirm_txid, self.txid)
        self.assertEqual(seen, [(self.token, 'broadcast')])
        self.assertEqual(_states(reopened.scanner), states_before)
        self.assertEqual(states_before, ('broadcast',))
        self.assertEqual(self._evidence(self.token), ('signed', 'uncertain', 'broadcast'))
        self.assertEqual(self.sign_calls, signs)
        self.assertEqual(self.core.mine_attempts, 0)
        self.assertEqual(self.core.submit_attempts, 1)
        self.assertFalse(reopened.faulted or reopened._q06_uncertain)
        # A second call must not replace the restored txid.
        self.assertIsNone(reopened._recover_pending_broadcast())
        self.assertEqual(reopened.pending_confirm_txid, self.txid)


def _body(txid, psbt_hex):
    return {'txid': txid, 'signed_psbt': psbt_hex}


_PSBT_INPUTS = {bytes.fromhex('01'): [IN_1], bytes.fromhex('02'): [IN_2]}


def _decode(raw):
    return SimpleNamespace(tx=SimpleNamespace(inputs=_PSBT_INPUTS[raw]))


def _fake_recovery_session(rows, evidence, mempool):
    from wam_regtest.bip39_spend_session import Q06OwnedSpendSession
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE reservations(txid TEXT, vout INT, token TEXT, state TEXT)')
    db.execute('CREATE TABLE history(txid TEXT, height INT)')
    db.executemany('INSERT INTO reservations VALUES (?,?,?,?)', rows)
    states = [row[3] for row in rows]

    @contextmanager
    def transaction():
        yield

    session = object.__new__(Q06OwnedSpendSession)
    session._lock = threading.RLock()
    session._q06_uncertain = False
    session.faulted = False
    session._q06_pending_confirm = None
    session.scanner = SimpleNamespace(store=SimpleNamespace(db=db, transaction=transaction))
    session._read_payment_evidence = lambda token, stage: evidence.get(token)
    session._rpc = lambda: SimpleNamespace(_call=lambda method, params: list(mempool))
    session._states = lambda: tuple(
        row[0] for row in db.execute('SELECT state FROM reservations ORDER BY token'))
    session._initial_states = tuple(states)
    return session


@unittest.skipUnless(importlib.util.find_spec('wam_sp') is not None,
                     'Requires the pinned WSP source on sys.path')
class PendingBroadcastExactlyOne(unittest.TestCase):
    """The exactly-one refusal, driven through _recover_pending_broadcast.

    One funded coin cannot produce two real broadcast tokens. This fixture
    is the same in-memory reservation table the recovery method reads.
    """

    def _recover(self, session):
        with patch('wam_sp.psbt.PSBT.decode', side_effect=_decode):
            return session._recover_pending_broadcast()

    def test_one_unconfirmed_broadcast_is_restored_and_two_are_not(self):
        one = _fake_recovery_session(
            [(IN_1[0], IN_1[1], 't1', 'broadcast')],
            {'t1': _body(TX_A, '01')}, (TX_A,))
        self.assertEqual(self._recover(one), TX_A)
        self.assertEqual(one._q06_pending_confirm, TX_A)
        self.assertEqual(one._states(), one._initial_states)
        self.assertFalse(one.faulted or one._q06_uncertain)

        two = _fake_recovery_session(
            [(IN_1[0], IN_1[1], 't1', 'broadcast'),
             (IN_2[0], IN_2[1], 't2', 'broadcast')],
            {'t1': _body(TX_A, '01'), 't2': _body(TX_B, '02')},
            (TX_A, TX_B))
        self.assertIsNone(self._recover(two))
        self.assertIsNone(two._q06_pending_confirm)
        self.assertEqual(two._states(), two._initial_states)
        self.assertFalse(two.faulted or two._q06_uncertain)


if __name__ == '__main__':
    unittest.main()
