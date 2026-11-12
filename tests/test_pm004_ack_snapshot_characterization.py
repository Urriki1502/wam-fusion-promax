"""PM-004 characterization of backup acknowledgement and the owned-spend snapshot.

Pins behaviour at 861462c, before the backend decomposition. The same cases
must pass after the domain/application extraction: on-disk path, JSON schema,
MAC input, challenge rules, the never-downgrade rule, error codes, and the
exact public snapshot dict. reservation_states was added by PM-011 (R2, W-TX-03).
"""
import hmac
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from mnemonic import Mnemonic

from wam_regtest.bip39_12 import Bip39Regtest12Keys
from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend, Q06ReadOnlyError
from wam_regtest.wallet_read import HistoryRow, WalletReadSnapshot

SOURCE = Path(importlib.util.find_spec('wam_sp').origin).resolve().parents[2]
PASSWORD = b'Q06 standalone trial password'
PHRASE = Mnemonic('english').to_mnemonic(bytes(16))
SEED = 'bip39-12-' + ('a' * 32)
SECRET = b'public-test-ack-key-not-a-seed'
TXID_A = '11' * 32
TXID_B = '22' * 32
TIP = 'ab' * 32
PENDING = '44' * 32


def _mac(seed_name, secret):
    return hmac.new(secret, f'{seed_name}:acknowledged'.encode(), 'sha256').hexdigest()


def _record(seed_name, acknowledged, deferred, secret=None):
    data = {'version': 1, 'acknowledged': acknowledged, 'deferred': deferred,
            'seed_id': seed_name}
    if acknowledged and secret is not None:
        data['mac'] = _mac(seed_name, secret)
    return json.dumps(data, separators=(',', ':')).encode()


class _FakeSession:
    """Duck-typed spend session. Private fields match today's snapshot reads.

    Properties match the read-only accessors the projection will use, and
    return the same values, so this fixture stays valid across the move.
    """

    def __init__(self, item, *, review, signed, pending, recovered):
        self._review = review
        self._signed = signed
        self._q06_pending_confirm = pending
        self._item = item
        self.scanner = object()
        self.snapshot_offsets = []
        self._recovered = recovered

    def snapshot(self, history_offset=0):
        self.snapshot_offsets.append(history_offset)
        return self._item

    def recovered_unsigned_cancel_available(self):
        return self._recovered

    @property
    def payment_review(self):
        return self._review

    @property
    def payment_signed(self):
        return self._signed is not None

    @property
    def pending_confirm_txid(self):
        return self._q06_pending_confirm


class AckSnapshotCharacterization(unittest.TestCase):
    def setUp(self):
        if sys.platform == 'darwin':
            from wam_regtest.custody import private_temporary_directory
            self.tmp = private_temporary_directory('pm004-ack-')
        else:
            self.tmp = tempfile.TemporaryDirectory(prefix='pm004-ack-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.backend = Bip39ReadOnlyBackend(self.root, Path('/synthetic-core'), SOURCE)
        self.folder = self.root / SEED
        self.ack_path = self.root / 'q06-gui-state' / 'ack' / (SEED + '.json')

    def test_ack_path_schema_mac_and_read_results(self):
        self.assertEqual(self.backend._q06_ack_dir(), self.root / 'q06-gui-state' / 'ack')
        self.assertEqual(self.backend._q06_ack_path(self.folder), self.ack_path)
        self.assertEqual(self.backend._q06_read_ack(self.folder), (None, None, True))
        self.assertEqual(self.backend._q06_read_ack(self.folder, SECRET), (None, None, True))

        self.backend._q06_write_ack(self.folder, False, deferred=True)
        deferred = _record(SEED, False, True)
        self.assertEqual(self.ack_path.read_bytes(), deferred)
        self.assertEqual(self.backend._q06_read_ack(self.folder), (False, True, True))

        self.backend._q06_write_ack(self.folder, True, secret=SECRET)
        acknowledged = _record(SEED, True, False, SECRET)
        self.assertEqual(self.ack_path.read_bytes(), acknowledged)
        self.assertIn(b'"mac":"' + _mac(SEED, SECRET).encode() + b'"', acknowledged)
        self.assertEqual(self.backend._q06_read_ack(self.folder), (True, False, True))
        self.assertEqual(self.backend._q06_read_ack(self.folder, SECRET), (True, False, True))
        self.assertEqual(self.backend._q06_read_ack(self.folder, b'wrong-public-key'),
                         (False, True, False))

        both = {'version': 1, 'acknowledged': True, 'deferred': True,
                'seed_id': SEED, 'mac': _mac(SEED, SECRET)}
        self.ack_path.write_bytes(json.dumps(both, separators=(',', ':')).encode())
        self.ack_path.chmod(0o600)
        self.assertEqual(self.backend._q06_read_ack(self.folder, SECRET), (False, True, False))

    def _open_seed(self, folder=None):
        folder = self.folder if folder is None else folder
        self.backend._secret = bytearray(PASSWORD)
        self.backend._seed_folder = folder
        self.backend._core = lambda: object()

    def _keys(self):
        keys = Bip39Regtest12Keys(PHRASE, source=SOURCE, authorized_disposable=True)
        self.addCleanup(keys.close)
        return keys

    def test_backup_verify_writes_seed_mac_and_wrong_words_do_not(self):
        self._open_seed()
        keys = self._keys()
        secret = keys.backup_ack_key()
        with (patch('wam_regtest.bip39_seed_vault.read_seed_phrase', return_value=PHRASE),
              patch('wam_regtest.bip39_seed_vault._owner_binding', return_value='0' * 64),
              patch('wam_regtest.bip39_seed_vault.open_owned_seed_container') as opened):
            opened.return_value.__enter__ = lambda *args, **kwargs: keys
            opened.return_value.__exit__ = lambda *args, **kwargs: None
            challenge = self.backend.execute('backup_challenge', (), {})
            self.assertEqual(sorted(challenge['positions']), list(challenge['positions']))
            self.assertEqual(len(set(challenge['positions'])), 3)
            self.assertTrue(all(1 <= position <= 12 for position in challenge['positions']))
            self.assertEqual(len(challenge['challenge_id']), 64)
            self.assertEqual(challenge['expires_in_seconds'], 120)
            words = PHRASE.split()
            wrong = self.backend.execute(
                'backup_verify', (challenge['challenge_id'], ['wrong'] * 3), {})
            self.assertIs(wrong, False)
            self.assertFalse(self.ack_path.exists())
            with self.assertRaises(Q06ReadOnlyError) as consumed:
                self.backend.execute(
                    'backup_verify', (challenge['challenge_id'],
                                      [words[p - 1] for p in challenge['positions']]), {})
            self.assertEqual(consumed.exception.args, ('Q06_GUI_BACKUP_CHALLENGE_DENIED',))

            fresh = self.backend.execute('backup_challenge', (), {})
            answers = [words[p - 1] for p in fresh['positions']]
            self.assertIs(self.backend.execute(
                'backup_verify', (fresh['challenge_id'], answers), {}), True)
        self.assertEqual(self.ack_path.read_bytes(), _record(SEED, True, False, secret))
        self.assertEqual(self.backend._q06_read_ack(self.folder, secret), (True, False, True))

    def test_verify_defer_and_pending_error_codes(self):
        with self.assertRaises(Q06ReadOnlyError) as no_seed:
            self.backend.execute('backup_defer', (), {})
        self.assertEqual(no_seed.exception.args, ('Q06_GUI_BACKUP_DEFER_NO_SEED',))
        self._open_seed()
        with self.assertRaises(Q06ReadOnlyError) as extra:
            self.backend.execute('backup_defer', ('extra',), {})
        self.assertEqual(extra.exception.args, ('Q06_GUI_BACKUP_DEFER_ARGS_DENIED',))
        other = self.root / ('bip39-12-' + ('b' * 32))
        with self.assertRaises(Q06ReadOnlyError) as mismatch:
            self.backend.execute('acknowledge_create_pending', (str(other),), {})
        self.assertEqual(mismatch.exception.args, ('Q06_GUI_ACK_FOLDER_MISMATCH',))
        self.backend._secret = None
        with self.assertRaises(Q06ReadOnlyError) as locked:
            self.backend.execute('backup_challenge', (), {})
        self.assertEqual(locked.exception.args, ('Q06_GUI_BACKUP_VERIFY_LOCKED',))

    def test_verified_ack_is_never_downgraded_and_a_forged_claim_is(self):
        self._open_seed()
        keys = self._keys()
        secret = keys.backup_ack_key()
        with (patch('wam_regtest.bip39_seed_vault.read_seed_phrase', return_value=PHRASE),
              patch('wam_regtest.bip39_seed_vault._owner_binding', return_value='0' * 64),
              patch('wam_regtest.bip39_seed_vault.open_owned_seed_container') as opened):
            opened.return_value.__enter__ = lambda *args, **kwargs: keys
            opened.return_value.__exit__ = lambda *args, **kwargs: None
            challenge = self.backend.execute('backup_challenge', (), {})
            answers = [PHRASE.split()[p - 1] for p in challenge['positions']]
            self.assertIs(self.backend.execute(
                'backup_verify', (challenge['challenge_id'], answers), {}), True)
            verified = self.ack_path.read_bytes()
            self.assertEqual(verified, _record(SEED, True, False, secret))
            self.assertTrue(self.backend._q06_ack_authenticated(self.folder))
            self.backend.execute('acknowledge_create_pending', (str(self.folder),), {})
            self.assertEqual(self.ack_path.read_bytes(), verified)
            self.backend.execute('backup_defer', (), {})
            self.assertEqual(self.ack_path.read_bytes(), verified)
        self.assertIsNone(self.backend._secret)
        self.assertTrue(self.backend.public_state()['locked'])

        self._open_seed()
        self.backend._q06_write_ack(self.folder, True)
        self.assertFalse(self.backend._q06_ack_authenticated(self.folder))
        with patch('wam_regtest.bip39_seed_vault.open_owned_seed_container') as opened:
            opened.return_value.__enter__ = lambda *args, **kwargs: keys
            opened.return_value.__exit__ = lambda *args, **kwargs: None
            self.backend.execute('backup_defer', (), {})
        data = json.loads(self.ack_path.read_text())
        self.assertEqual(data, {'version': 1, 'acknowledged': False, 'deferred': True,
                                'seed_id': SEED})
        self.assertNotIn('mac', data)
        self.assertTrue(self.backend.public_state()['locked'])

    def _backend_with_session(self, session):
        backend = object.__new__(Bip39ReadOnlyBackend)
        backend._spend_session = session
        backend._public = {'profile': 'q06', 'account_id': 'public-identity'}
        return backend

    def test_session_snapshot_dict_matches_the_fake_session(self):
        review = {'commitment': '33' * 32, 'fee': 1000}
        item = WalletReadSnapshot(
            chain='regtest', height=120, tip=TIP, receive_code='wamrtsp1public',
            confirmed_atoms=49000, confirmed_utxos=1,
            history=(
                HistoryRow(TXID_A, 100, 21, 50000, 1000),
                HistoryRow(TXID_B, 90, 31, 0, 2000),
            ),
            core_sha256='cd' * 32,
            reservation_count=2,
            reservation_states=('broadcast',),
        )
        session = _FakeSession(item, review=review, signed=b'not-a-real-psbt',
                               pending=PENDING, recovered=True)
        backend = self._backend_with_session(session)
        with patch('wam_sp.wallet.Wallet') as wallet:
            wallet.return_value.balance.return_value = {'available_atoms': 47000}
            result = backend._session_snapshot()
            wallet.assert_called_once_with(session.scanner)
        self.assertEqual(session.snapshot_offsets, [0])
        self.assertEqual(result, {
            'status': 'Q06_REGTEST_BIP39_OWNED_SPEND_VERIFIED',
            'profile': 'q06',
            'account_id': 'public-identity',
            'receive_code': 'wamrtsp1public',
            'height': 120,
            'tip': TIP,
            'confirmed_atoms': 49000,
            'available_atoms': 47000,
            'history_count_shown': 2,
            'history': (
                {'txid': TXID_A, 'height': 100, 'atoms': 49000},
                {'txid': TXID_B, 'height': 90, 'atoms': -2000},
            ),
            'reservation_count': 2,
            # PM-011 (W-TX-03, intentional public-dict addition): verified state set.
            'reservation_states': ('broadcast',),
            'payment_review': review,
            'payment_signed': True,
            'recovered_unsigned_cancel_available': True,
            'pending_confirm_txid': PENDING,
            'fusion_snapshot': item,
            'signer_allowed': True,
            'broadcast_allowed': True,
            'mainnet_allowed': False,
        })
        # PM-011 / R2 landed: the verified state set is now part of the public dict.
        self.assertEqual(result['reservation_states'], ('broadcast',))
        self.assertIs(result['fusion_snapshot'], item)
        self.assertIs(result['payment_review'], review)

        idle_item = WalletReadSnapshot(
            chain='regtest', height=1, tip=TIP, receive_code='wamrtsp1public',
            confirmed_atoms=0, confirmed_utxos=0, history=(),
            core_sha256='cd' * 32, reservation_count=0,
        )
        idle = _FakeSession(idle_item, review=None, signed=None, pending=None, recovered=False)
        idle_backend = self._backend_with_session(idle)
        with patch('wam_sp.wallet.Wallet') as wallet:
            wallet.return_value.balance.return_value = {'available_atoms': 0}
            idle_result = idle_backend._session_snapshot(7)
        self.assertEqual(idle.snapshot_offsets, [7])
        self.assertEqual(idle_result['history'], ())
        self.assertEqual(idle_result['history_count_shown'], 0)
        self.assertIsNone(idle_result['payment_review'])
        self.assertIs(idle_result['payment_signed'], False)
        self.assertIs(idle_result['recovered_unsigned_cancel_available'], False)
        self.assertIsNone(idle_result['pending_confirm_txid'])
        self.assertEqual(idle_result['reservation_count'], 0)
        self.assertEqual(idle_result['available_atoms'], 0)
        # PM-011: present, and None when the read model did not verify states.
        self.assertIsNone(idle_result['reservation_states'])

        empty = object.__new__(Bip39ReadOnlyBackend)
        empty._spend_session = None
        with self.assertRaises(Q06ReadOnlyError) as missing:
            empty._session_snapshot()
        self.assertEqual(missing.exception.args, ('Q06_GUI_SPEND_NOT_ACTIVE',))


if __name__ == '__main__':
    unittest.main()
