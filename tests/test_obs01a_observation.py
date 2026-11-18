"""OBS-01a: one read-only transaction-observation policy (Contracts G and I).

Synthetic scanner store and Core RPC doubles only; no genuine Core here.
Observation never signs, submits, releases, syncs or persists: every test
drives only the read paths and pins the fixed refusal tokens of the three
adapters in bip39_spend_session.
"""
import sqlite3
import threading
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

TIP_HEIGHT = 10


def BH(height):
    return '%064x' % (0xB10C0000 + height)


def TX(number):
    return '%064x' % number


TIP = BH(TIP_HEIGHT)
IN_1 = (TX(0x1001), 0)
IN_2 = (TX(0x1002), 1)
PUBKEY = 'ab' * 32
ATOMS = 100_000


class TransportFailure(Exception):
    """Stands in for a WalletSessionError raised by the RPC transport."""


class FakeStore:
    def __init__(self):
        self.db = sqlite3.connect(':memory:', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.db.executescript(
            'CREATE TABLE blocks(height INTEGER PRIMARY KEY, hash TEXT, previous TEXT);'
            'CREATE TABLE coins(txid TEXT, vout INTEGER, atoms INTEGER,'
            ' public_key TEXT, spent INTEGER);'
            'CREATE TABLE history(txid TEXT, height INTEGER);'
            'CREATE TABLE reservations(txid TEXT, vout INTEGER, token TEXT, state TEXT);')
        for height in range(0, TIP_HEIGHT + 1):
            self.db.execute('INSERT INTO blocks VALUES (?,?,?)',
                            (height, BH(height), BH(height - 1) if height else '0' * 64))
        self.db.commit()

    def tip(self):
        row = self.db.execute(
            'SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1').fetchone()
        return (row[0], row[1]) if row else (0, '0' * 64)

    @contextmanager
    def transaction(self):
        self.lock.acquire()
        try:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield self.db
            except Exception:
                self.db.execute('ROLLBACK')
                raise
            else:
                self.db.execute('COMMIT')
        finally:
            self.lock.release()

    def add_coin(self, outpoint=IN_1, atoms=ATOMS, spent=None):
        self.db.execute('INSERT INTO coins VALUES (?,?,?,?,?)',
                        (outpoint[0], outpoint[1], atoms, PUBKEY, spent))
        self.db.commit()

    def add_history(self, txid, height):
        self.db.execute('INSERT INTO history VALUES (?,?)', (txid, height))
        self.db.commit()


class FakeRpc:
    """Read-only Core double. Records (via, method) for every call."""

    def __init__(self):
        self.info = {'blocks': TIP_HEIGHT, 'headers': TIP_HEIGHT,
                     'initialblockdownload': False}
        self.height = TIP_HEIGHT
        self.mempool = []
        self.mempool_reads = None  # successive replies; the last one repeats
        self.txouts = {}
        self.calls = []
        self.failure = None
        self.best_hash = TIP

    def _record(self, via, method):
        self.calls.append((via, method))
        if self.failure is not None:
            raise self.failure

    def _call(self, method, params):
        self._record('_call', method)
        if method == 'getblockchaininfo':
            return dict(self.info)
        if method == 'getrawmempool':
            if self.mempool_reads:
                reply = self.mempool_reads[0]
                if len(self.mempool_reads) > 1:
                    self.mempool_reads.pop(0)
                return list(reply)
            return sorted(self.mempool)
        raise AssertionError(method)

    def call(self, method, params=None):
        self._record('call', method)
        if method == 'getbestblockhash':
            return self.best_hash
        if method == 'getblockcount':
            return self.height
        if method == 'getblockhash':
            return BH(params[0])
        if method == 'gettxout':
            return self.txouts.get((params[0], params[1]))
        raise AssertionError(method)


def valid_txout():
    return {'bestblock': TIP, 'value': 0.001,
            'scriptPubKey': {'hex': '5120' + PUBKEY}}


def make_scanner(store, ready=True, verified_tip='tip'):
    return SimpleNamespace(
        store=store, ready=ready,
        verified_tip=store.tip() if verified_tip == 'tip' else verified_tip)


def make_env():
    store = FakeStore()
    store.add_coin(IN_1)
    store.add_coin(IN_2)
    rpc = FakeRpc()
    rpc.txouts[IN_1] = valid_txout()
    rpc.txouts[IN_2] = valid_txout()
    return store, make_scanner(store), rpc


class GenericContract(unittest.TestCase):
    def observe(self, scanner, rpc, txid):
        from wam_regtest.tx_observation import observe_generic
        return observe_generic(scanner, rpc, txid)

    def test_incoming_confirmed_tx(self):
        store, scanner, rpc = make_env()
        store.add_history(TX(0x2000), 4)
        result = self.observe(scanner, rpc, TX(0x2000))
        self.assertEqual(result['state'], 'CONFIRMED')
        self.assertEqual(result['height'], 4)
        self.assertEqual(result['block_hash'], BH(4))
        self.assertEqual(result['depth'], TIP_HEIGHT - 4 + 1)
        self.assertEqual(result['observed_tip'], (TIP_HEIGHT, TIP))
        self.assertIs(result['core_ibd'], False)
        self.assertIs(result['atomic'], False)

    def test_unowned_txid_not_found_locally(self):
        _store, scanner, rpc = make_env()
        result = self.observe(scanner, rpc, TX(0x2BAD))
        self.assertEqual(result['state'], 'NOT_FOUND_LOCALLY')
        self.assertIsNone(result['height'])

    def test_arbitrary_txid_in_mempool(self):
        _store, scanner, rpc = make_env()
        rpc.mempool = [TX(0x2BAD)]
        result = self.observe(scanner, rpc, TX(0x2BAD))
        self.assertEqual(result['state'], 'IN_MEMPOOL')

    def test_corrupt_history_row_hash_mismatch_refuses(self):
        from wam_regtest.tx_observation import ObservationRefused
        store, scanner, rpc = make_env()
        store.add_history(TX(0x2000), 4)
        rpc.call  # keep reference
        original = rpc.call

        def call(method, params=None):
            if method == 'getblockhash':
                return BH(999)
            return original(method, params)

        rpc.call = call
        with self.assertRaises(ObservationRefused) as caught:
            self.observe(scanner, rpc, TX(0x2000))
        self.assertEqual(caught.exception.reason, 'CONTRADICTION')

    def test_duplicate_history_rows_refuse(self):
        from wam_regtest.tx_observation import ObservationRefused
        store, scanner, rpc = make_env()
        store.add_history(TX(0x2000), 4)
        store.add_history(TX(0x2000), 5)
        with self.assertRaises(ObservationRefused):
            self.observe(scanner, rpc, TX(0x2000))


class IntentContract(unittest.TestCase):
    def observe(self, scanner, rpc, txid, outpoints):
        from wam_regtest.tx_observation import observe_intents
        return observe_intents(scanner, rpc, {txid: tuple(outpoints)})[txid]

    def test_confirmed_requires_every_input_spent_at_same_height(self):
        store, scanner, rpc = make_env()
        store.db.execute('UPDATE coins SET spent=4 WHERE txid=?', (IN_1[0],))
        store.db.commit()
        store.add_history(TX(0x3000), 4)
        result = self.observe(scanner, rpc, TX(0x3000), [IN_1])
        self.assertEqual(result['state'], 'CONFIRMED')
        self.assertEqual(result['depth'], TIP_HEIGHT - 4 + 1)

    def test_confirmed_with_unspent_input_is_contradiction(self):
        store, scanner, rpc = make_env()
        store.add_history(TX(0x3000), 4)
        result = self.observe(scanner, rpc, TX(0x3000), [IN_1])
        self.assertEqual(result['state'], 'UNKNOWN')
        self.assertEqual(result['reason'], 'CONTRADICTION')

    def test_our_tx_plus_unrelated_own_tx_in_same_block(self):
        store, scanner, rpc = make_env()
        store.db.execute('UPDATE coins SET spent=4 WHERE txid=?', (IN_1[0],))
        store.db.commit()
        store.add_history(TX(0x3000), 4)
        store.add_history(TX(0x3001), 4)  # unrelated own tx, same block
        result = self.observe(scanner, rpc, TX(0x3000), [IN_1])
        self.assertEqual(result['state'], 'CONFIRMED')

    def test_block_conflicted_reports_minimum_and_all_heights(self):
        store, scanner, rpc = make_env()
        store.db.execute('UPDATE coins SET spent=7 WHERE txid=?', (IN_1[0],))
        store.db.execute('UPDATE coins SET spent=3 WHERE txid=?', (IN_2[0],))
        store.db.commit()
        result = self.observe(scanner, rpc, TX(0x3000), [IN_1, IN_2])
        self.assertEqual(result['state'], 'BLOCK_CONFLICTED')
        self.assertEqual(result['height'], 3)
        self.assertEqual(result['conflict_heights'], [3, 7])
        self.assertEqual(result['block_hash'], BH(3))

    def test_two_inputs_spent_in_one_block(self):
        store, scanner, rpc = make_env()
        store.db.execute('UPDATE coins SET spent=6')
        store.db.commit()
        result = self.observe(scanner, rpc, TX(0x3000), [IN_1, IN_2])
        self.assertEqual(result['state'], 'BLOCK_CONFLICTED')
        self.assertEqual(result['conflict_heights'], [6])

    def test_unanchored_conflict_height_is_contradiction(self):
        store, scanner, rpc = make_env()
        store.db.execute('UPDATE coins SET spent=8 WHERE txid=?', (IN_1[0],))
        store.db.commit()
        original = rpc.call

        def call(method, params=None):
            if method == 'getblockhash':
                return BH(999)
            return original(method, params)

        rpc.call = call
        result = self.observe(scanner, rpc, TX(0x3000), [IN_1])
        self.assertEqual((result['state'], result['reason']),
                         ('UNKNOWN', 'CONTRADICTION'))

    def test_in_mempool(self):
        _store, scanner, rpc = make_env()
        rpc.mempool = [TX(0x3000)]
        result = self.observe(scanner, rpc, TX(0x3000), [IN_1])
        self.assertEqual(result['state'], 'IN_MEMPOOL')

    def test_input_unavailable_when_gettxout_null(self):
        _store, scanner, rpc = make_env()
        rpc.txouts[IN_1] = None
        result = self.observe(scanner, rpc, TX(0x3000), [IN_1])
        self.assertEqual(result['state'], 'INPUT_UNAVAILABLE')

    def test_not_seen_locally(self):
        _store, scanner, rpc = make_env()
        result = self.observe(scanner, rpc, TX(0x3000), [IN_1, IN_2])
        self.assertEqual(result['state'], 'NOT_SEEN_LOCALLY')

    def test_missing_coin_row_is_inputs_unverified(self):
        _store, scanner, rpc = make_env()
        result = self.observe(scanner, rpc, TX(0x3000), [(TX(0x9999), 0)])
        self.assertEqual((result['state'], result['reason']),
                         ('UNKNOWN', 'INPUTS_UNVERIFIED'))

    def test_confirmed_history_with_missing_coin_is_inputs_unverified(self):
        store, scanner, rpc = make_env()
        store.add_history(TX(0x3000), 4)
        result = self.observe(scanner, rpc, TX(0x3000), [(TX(0x9999), 0)])
        self.assertEqual((result['state'], result['reason']),
                         ('UNKNOWN', 'INPUTS_UNVERIFIED'))

    def test_invalid_vout_is_inputs_unverified(self):
        _store, scanner, rpc = make_env()
        for vout in (-1, 2 ** 32, '0', True, None):
            with self.subTest(vout=vout):
                result = self.observe(scanner, rpc, TX(0x3000), [(IN_1[0], vout)])
                self.assertEqual(result['reason'], 'INPUTS_UNVERIFIED')

    def test_reorg_rollback_clears_stale_conflict(self):
        store, scanner, rpc = make_env()
        store.db.execute('UPDATE coins SET spent=8 WHERE txid=?', (IN_1[0],))
        store.db.commit()
        first = self.observe(scanner, rpc, TX(0x3000), [IN_1])
        self.assertEqual(first['state'], 'BLOCK_CONFLICTED')
        # Roll back above ancestor 5 exactly like Store._rollback does.
        store.db.execute('UPDATE coins SET spent=NULL WHERE spent>5')
        store.db.execute('DELETE FROM blocks WHERE height>5')
        store.db.execute('DELETE FROM history WHERE height>5')
        store.db.commit()
        scanner.verified_tip = store.tip()
        rpc.height = 5
        rpc.best_hash = BH(5)
        rpc.info.update(blocks=5, headers=5)
        rpc.txouts[IN_1] = dict(valid_txout(), bestblock=BH(5))
        result = self.observe(scanner, rpc, TX(0x3000), [IN_1])
        self.assertEqual(result['state'], 'NOT_SEEN_LOCALLY')


class Prerequisites(unittest.TestCase):
    def observe(self, scanner, rpc):
        from wam_regtest.tx_observation import observe_generic
        return observe_generic(scanner, rpc, TX(0x3000))

    def reason(self, scanner, rpc):
        from wam_regtest.tx_observation import ObservationRefused
        with self.assertRaises(ObservationRefused) as caught:
            self.observe(scanner, rpc)
        return caught.exception.reason

    def test_partial_scan_is_scanner_behind(self):
        _store, scanner, rpc = make_env()
        scanner.ready = False
        scanner.verified_tip = None
        self.assertEqual(self.reason(scanner, rpc), 'SCANNER_BEHIND')

    def test_stale_tip_with_core_ibd_true_is_ordinary(self):
        _store, scanner, rpc = make_env()
        rpc.info['initialblockdownload'] = True
        result = self.observe(scanner, rpc)
        self.assertIs(result['core_ibd'], True)
        self.assertEqual(result['state'], 'NOT_FOUND_LOCALLY')

    def test_latched_core_ibd_false_with_stale_store_tip_is_scanner_behind(self):
        store, scanner, rpc = make_env()
        scanner.verified_tip = (TIP_HEIGHT - 1, BH(TIP_HEIGHT - 1))
        self.assertEqual(self.reason(scanner, rpc), 'SCANNER_BEHIND')

    def test_syncing_header_relations(self):
        for headers in (TIP_HEIGHT + 1, -1, TIP_HEIGHT - 1):
            with self.subTest(headers=headers):
                _store, scanner, rpc = make_env()
                rpc.info['headers'] = headers
                self.assertEqual(self.reason(scanner, rpc), 'SYNCING')

    def test_invalid_blockchaininfo_values(self):
        cases = [
            {'blocks': -2}, {'blocks': 1_000_001}, {'headers': -2},
            {'headers': 1_000_001}, {'blocks': True}, {'blocks': '10'},
            {'blocks': 10.0}, {'headers': None}, {'blocks': None},
            {'initialblockdownload': None}, {'initialblockdownload': 0},
            {'initialblockdownload': 1}, {'initialblockdownload': 'true'},
            {'initialblockdownload': 'false'},
        ]
        for patch_info in cases:
            with self.subTest(patch=patch_info):
                _store, scanner, rpc = make_env()
                rpc.info.update(patch_info)
                self.assertEqual(self.reason(scanner, rpc), 'INVALID_REPLY')

    def test_malformed_ibd_beats_syncing_gap(self):
        _store, scanner, rpc = make_env()
        rpc.info.update(headers=-1, initialblockdownload='true')
        self.assertEqual(self.reason(scanner, rpc), 'INVALID_REPLY')

    def test_zero_peers_with_equal_heights_is_ordinary(self):
        # The observer never asks for a peer count; equal heights proceed.
        _store, scanner, rpc = make_env()
        result = self.observe(scanner, rpc)
        self.assertEqual(result['state'], 'NOT_FOUND_LOCALLY')
        self.assertNotIn('getconnectioncount', [m for _v, m in rpc.calls])


class Races(unittest.TestCase):
    def test_tip_moved_between_reads_retries_once_then_refuses(self):
        from wam_regtest.tx_observation import ObservationRefused
        _store, scanner, rpc = make_env()
        original = rpc.call
        seen = {'best': 0}

        def call(method, params=None):
            if method == 'getbestblockhash':
                seen['best'] += 1
                # Opening read is the tip; every bracket re-read moved.
                return TIP if seen['best'] % 2 == 1 else BH(999)
            return original(method, params)

        rpc.call = call
        with self.assertRaises(ObservationRefused) as caught:
            from wam_regtest.tx_observation import observe_generic
            observe_generic(scanner, rpc, TX(0x3000))
        self.assertEqual(caught.exception.reason, 'TIP_MOVED')
        self.assertEqual(seen['best'], 4)  # two attempts, bracketed twice

    def test_mempool_membership_change_retries_then_tip_moved(self):
        from wam_regtest.tx_observation import ObservationRefused
        _store, scanner, rpc = make_env()
        rpc.mempool_reads = [[TX(0x3000)], [], [TX(0x3000)], []]
        with self.assertRaises(ObservationRefused) as caught:
            from wam_regtest.tx_observation import observe_generic
            observe_generic(scanner, rpc, TX(0x3000))
        self.assertEqual(caught.exception.reason, 'TIP_MOVED')
        self.assertEqual(rpc.calls.count(('_call', 'getrawmempool')), 4)

    def test_duplicate_mempool_id_is_invalid(self):
        from wam_regtest.tx_observation import ObservationRefused
        _store, scanner, rpc = make_env()
        rpc.mempool = [TX(0x3000), TX(0x3000)]
        with self.assertRaises(ObservationRefused) as caught:
            from wam_regtest.tx_observation import observe_generic
            observe_generic(scanner, rpc, TX(0x3000))
        self.assertEqual(caught.exception.reason, 'INVALID_REPLY')

    def test_non_hex_mempool_id_is_invalid(self):
        from wam_regtest.tx_observation import ObservationRefused
        _store, scanner, rpc = make_env()
        rpc.mempool = ['not-a-txid']
        with self.assertRaises(ObservationRefused) as caught:
            from wam_regtest.tx_observation import observe_generic
            observe_generic(scanner, rpc, TX(0x3000))
        self.assertEqual(caught.exception.reason, 'INVALID_REPLY')


class GettxoutValidation(unittest.TestCase):
    def observe(self, scanner, rpc):
        from wam_regtest.tx_observation import observe_intents
        return observe_intents(scanner, rpc, {TX(0x3000): (IN_1,)})[TX(0x3000)]

    def test_valid_boundary_values(self):
        _store, scanner, rpc = make_env()
        rpc.txouts[IN_1] = {'bestblock': TIP, 'value': 0.001,
                            'scriptPubKey': {'hex': '5120' + PUBKEY}}
        self.assertEqual(self.observe(scanner, rpc)['state'], 'NOT_SEEN_LOCALLY')

    def test_invalid_replies_refuse_whole_acquisition(self):
        from wam_regtest.tx_observation import ObservationRefused
        bad = [
            dict(valid_txout(), bestblock=BH(1)),
            dict(valid_txout(), value=0.00000001),   # 1 atom, wrong amount
            dict(valid_txout(), value=22000000.0),   # max-range, wrong amount
            dict(valid_txout(), value=0.0015),       # non-integral atoms
            dict(valid_txout(), value=True),
            dict(valid_txout(), value=float('nan')),
            dict(valid_txout(), value=float('inf')),
            dict(valid_txout(), value='0.001'),
            dict(valid_txout(), scriptPubKey={'hex': '0014' + '00' * 20}),
            {'value': 0.001, 'scriptPubKey': {'hex': '5120' + PUBKEY}},
            'not-a-dict',
        ]
        for reply in bad:
            with self.subTest(reply=repr(reply)[:40]):
                _store, scanner, rpc = make_env()
                rpc.txouts[IN_1] = reply
                with self.assertRaises(ObservationRefused) as caught:
                    self.observe(scanner, rpc)
                self.assertEqual(caught.exception.reason, 'INVALID_REPLY')

    def test_null_means_input_unavailable_not_invalid(self):
        _store, scanner, rpc = make_env()
        rpc.txouts[IN_1] = None
        self.assertEqual(self.observe(scanner, rpc)['state'], 'INPUT_UNAVAILABLE')


class ZeroWriteGuard(unittest.TestCase):
    def test_insert_inside_observer_is_denied_and_fails_closed(self):
        from wam_regtest.tx_observation import guarded_store_read
        store, _scanner, _rpc = make_env()

        def write_attempt(db):
            try:
                db.execute("INSERT INTO history VALUES ('%s', 1)" % TX(0x7777))
            except sqlite3.DatabaseError:
                pass  # caught by the caller; the guard must still fail it
            return 'read-result'

        with self.assertRaises(Exception):
            guarded_store_read(store, write_attempt)
        self.assertEqual(store.db.execute(
            'SELECT count(*) FROM history').fetchone()[0], 0)

    def test_authorizer_removed_after_success_and_failure(self):
        from wam_regtest.tx_observation import guarded_store_read
        store, _scanner, _rpc = make_env()
        guarded_store_read(store, lambda db: db.execute(
            'SELECT count(*) FROM coins').fetchone()[0])
        store.db.execute("INSERT INTO history VALUES ('%s', 1)" % TX(0x7777))
        store.db.rollback()
        with self.assertRaises(RuntimeError):
            guarded_store_read(store, lambda db: (_ for _ in ()).throw(
                RuntimeError('boom')))
        store.db.execute("INSERT INTO history VALUES ('%s', 1)" % TX(0x7777))
        store.db.rollback()

    def test_no_file_opened_for_writing_and_rpc_reads_only(self):
        import builtins
        import os
        _store, scanner, rpc = make_env()
        opened = []
        real_open, real_os_open = builtins.open, os.open

        def spy_open(file, mode='r', *args, **kwargs):
            opened.append(mode)
            return real_open(file, mode, *args, **kwargs)

        def spy_os_open(file, flags, *args, **kwargs):
            opened.append(flags)
            return real_os_open(file, flags, *args, **kwargs)

        from wam_regtest.tx_observation import observe_generic
        with patch('builtins.open', spy_open), patch('os.open', spy_os_open):
            observe_generic(scanner, rpc, TX(0x3000))
        write_modes = [m for m in opened
                       if (isinstance(m, str) and any(c in m for c in 'wax+'))
                       or (isinstance(m, int) and m & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))]
        self.assertEqual(write_modes, [])
        methods = {method for _via, method in rpc.calls}
        self.assertLessEqual(methods, {'getblockchaininfo', 'getbestblockhash',
                                       'getblockcount', 'getblockhash',
                                       'getrawmempool', 'gettxout'})

    def test_concurrent_observers_serialize_on_store_lock(self):
        _store, scanner, rpc = make_env()
        store = scanner.store
        done = []
        store.lock.acquire()
        try:
            worker = threading.Thread(
                target=lambda: done.append(
                    __import__('wam_regtest.tx_observation', fromlist=['x'])
                    .observe_generic(scanner, rpc, TX(0x3000))))
            worker.start()
            worker.join(0.3)
            self.assertEqual(done, [])  # still blocked on the store RLock
        finally:
            store.lock.release()
        worker.join(5)
        self.assertEqual(len(done), 1)


# ---- The three bip39_spend_session adapters --------------------------------

_PSBT_INPUTS = {b'\x01': [IN_1], b'\x02': [IN_2], b'\x03': [IN_1, IN_2]}


def _decode_psbt(raw):
    return SimpleNamespace(tx=SimpleNamespace(inputs=_PSBT_INPUTS[raw]))


def _body(txid, key):
    return {'txid': txid, 'signed_psbt': key.hex(), 'recipient': 'wamrtsp1public',
            'atoms': 50_000, 'fee': 1000, 'commitment': 'c' * 64}


def _spend_session(store, rpc, evidence, states=('signed',)):
    from wam_regtest.bip39_spend_session import Q06OwnedSpendSession
    session = object.__new__(Q06OwnedSpendSession)
    session._lock = threading.RLock()
    session._q06_uncertain = False
    session.faulted = False
    session._q06_pending_confirm = None
    session.scanner = make_scanner(store)
    session.snapshot = lambda *a, **k: SimpleNamespace(height=TIP_HEIGHT, tip=TIP)
    session._rpc = lambda: rpc
    session._read_payment_evidence = lambda token, stage: evidence.get(token)
    return session


def _intent_env():
    store, scanner, rpc = make_env()
    return store, rpc


class AdapterContracts(unittest.TestCase):
    def setUp(self):
        patcher = patch('wam_sp.psbt.PSBT.decode', side_effect=_decode_psbt)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _intent_session(self, store, rpc, evidence, rows):
        store.db.executemany('INSERT INTO reservations VALUES (?,?,?,?)', rows)
        store.db.commit()
        return _spend_session(store, rpc, evidence)

    def test_intent_status_maps_every_observation_state(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        store, rpc = _intent_env()
        txid = TX(0x3000)
        session = self._intent_session(
            store, rpc, {'t1': _body(txid, b'\x01')},
            [(IN_1[0], IN_1[1], 't1', 'signed')])
        [item] = session.signed_intent_status()['intents']
        self.assertEqual(item['classification'], 'SIGNED_NOT_SUBMITTED_RESUMABLE')
        self.assertEqual(item['observation']['state'], 'NOT_SEEN_LOCALLY')
        self.assertIs(item['observation']['core_ibd'], False)
        rpc.mempool = [txid]
        [item] = session.signed_intent_status()['intents']
        self.assertEqual(item['classification'], 'IN_MEMPOOL_AWAITING_CONFIRMATION')
        rpc.mempool = []
        rpc.txouts[IN_1] = None
        [item] = session.signed_intent_status()['intents']
        self.assertEqual(item['classification'],
                         'OPERATOR_REVIEW_INPUT_SPENT_OR_CONFLICTED')
        self.assertEqual(item['observation']['state'], 'INPUT_UNAVAILABLE')

    def test_intent_status_contradiction_uses_new_classification(self):
        store, rpc = _intent_env()
        store.db.execute('UPDATE coins SET spent=4 WHERE txid=?', (IN_1[0],))
        store.db.commit()
        store.add_history(TX(0x3000), 4)  # confirmed, but IN_2 was not spent
        session = self._intent_session(
            store, rpc, {'t1': _body(TX(0x3000), b'\x03')},
            [(IN_1[0], IN_1[1], 't1', 'signed'),
             (IN_2[0], IN_2[1], 't1', 'signed')])
        [item] = session.signed_intent_status()['intents']
        self.assertEqual(item['classification'],
                         'OPERATOR_REVIEW_OBSERVATION_CONTRADICTION')
        self.assertEqual(item['observation']['state'], 'UNKNOWN')

    def test_syncing_refuses_all_three_adapters_with_fixed_tokens(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        for headers in (TIP_HEIGHT + 1, -1, TIP_HEIGHT - 1):
            with self.subTest(headers=headers):
                store, rpc = _intent_env()
                rpc.info['headers'] = headers
                session = self._intent_session(
                    store, rpc, {'t1': _body(TX(0x3000), b'\x01')},
                    [(IN_1[0], IN_1[1], 't1', 'signed')])
                with self.assertRaises(Q06SpendSessionError) as caught:
                    session.signed_intent_status()
                self.assertEqual(caught.exception.args,
                                 ('Q06_INTENT_STATUS_UNVERIFIED',))
                with self.assertRaises(Q06SpendSessionError) as caught:
                    session.inspect_confirmed(TX(0x3000))
                self.assertEqual(caught.exception.args,
                                 ('Q06_INSPECT_HISTORY_UNVERIFIED',))
                store.db.execute(
                    "INSERT INTO reservations VALUES (?,?,?,'broadcast')",
                    (IN_2[0], IN_2[1], 't2'))
                store.db.commit()
                session._read_payment_evidence = lambda token, stage: (
                    _body(TX(0x4000), b'\x02'))
                with self.assertRaises(Q06SpendSessionError) as caught:
                    session._recover_pending_broadcast()
                self.assertEqual(caught.exception.args,
                                 ('Q06_PENDING_BROADCAST_UNVERIFIED',))
                self.assertIsNone(session._q06_pending_confirm)

    def test_transport_failure_propagates_unchanged_from_all_adapters(self):
        store, rpc = _intent_env()
        rpc.failure = TransportFailure('core gone')
        session = self._intent_session(
            store, rpc, {'t1': _body(TX(0x3000), b'\x01')},
            [(IN_1[0], IN_1[1], 't1', 'signed')])
        with self.assertRaises(TransportFailure):
            session.signed_intent_status()
        with self.assertRaises(TransportFailure):
            session.inspect_confirmed(TX(0x3000))

    def test_inspect_confirmed_adds_tx_height_and_block_hash(self):
        store, rpc = _intent_env()
        store.add_history(TX(0x3000), 4)
        session = _spend_session(store, rpc, {})
        found = session.inspect_confirmed(TX(0x3000))
        self.assertEqual(found['status'], 'Q06_CONFIRMED_IN_VERIFIED_HISTORY')
        self.assertEqual(found['tx_height'], 4)
        self.assertEqual(found['tx_block_hash'], BH(4))
        self.assertEqual(found['height'], TIP_HEIGHT)
        missing = session.inspect_confirmed(TX(0x3001))
        self.assertEqual(missing['status'], 'Q06_TX_NOT_IN_CONFIRMED_HISTORY')
        self.assertIsNone(missing['tx_height'])
        self.assertIsNone(missing['tx_block_hash'])

    def test_zero_one_and_two_token_statuses(self):
        store, rpc = _intent_env()
        session = self._intent_session(store, rpc, {}, [])
        self.assertEqual(session.signed_intent_status()['intents'], [])
        store, rpc = _intent_env()
        session = self._intent_session(
            store, rpc,
            {'t1': _body(TX(0x3000), b'\x01'), 't2': _body(TX(0x4000), b'\x02')},
            [(IN_1[0], IN_1[1], 't1', 'signed'),
             (IN_2[0], IN_2[1], 't2', 'uncertain')])
        store.add_history(TX(0x3000), 4)
        store.db.execute('UPDATE coins SET spent=4 WHERE txid=?', (IN_1[0],))
        store.db.commit()
        items = {i['token']: i for i in session.signed_intent_status()['intents']}
        self.assertEqual(items['t1']['classification'],
                         'CONFIRMED_IN_VERIFIED_HISTORY')
        self.assertEqual(items['t2']['classification'],
                         'UNCERTAIN_NOT_OBSERVED_RESUMABLE')

    def test_bad_evidence_for_another_token_never_reaches_observation(self):
        store, rpc = _intent_env()
        session = self._intent_session(
            store, rpc, {'t2': _body(TX(0x4000), b'\x02')},
            [(IN_1[0], IN_1[1], 't1', 'signed'),
             (IN_2[0], IN_2[1], 't2', 'signed')])
        items = {i['token']: i for i in session.signed_intent_status()['intents']}
        self.assertEqual(items['t1']['classification'],
                         'OPERATOR_REVIEW_SIGNED_EVIDENCE_MISSING')
        self.assertIsNone(items['t1']['observation'])
        self.assertEqual(items['t2']['classification'],
                         'SIGNED_NOT_SUBMITTED_RESUMABLE')

    def test_resumable_status_still_requires_explicit_approval(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        store, rpc = _intent_env()
        session = self._intent_session(
            store, rpc, {'t1': _body(TX(0x3000), b'\x01')},
            [(IN_1[0], IN_1[1], 't1', 'signed')])
        session.vault = SimpleNamespace(
            anchor=SimpleNamespace(lease=lambda: __import__('contextlib').nullcontext()))
        session._prepared = session._signed = session._review = None
        with self.assertRaises(Q06SpendSessionError) as caught:
            session.resume_signed_intent('t1', TX(0x3000))
        self.assertEqual(caught.exception.args,
                         ('Q06_RESUME_EXPLICIT_APPROVAL_REQUIRED',))
        self.assertEqual(
            store.db.execute('SELECT state FROM reservations').fetchall()[0][0],
            'signed')
        self.assertNotIn('sendrawtransaction', [m for _v, m in rpc.calls])


if __name__ == '__main__':
    unittest.main()


