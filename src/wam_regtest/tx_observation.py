"""OBS-01a: one read-only transaction-observation policy (REGTEST only).

Observation is NOT custody. It never changes reservations, never signs,
submits, releases or syncs, and is never persisted. The caller runs
``snapshot()`` first (which may scan and save); this module never calls
``snapshot()``, ``sync``, ``_save``, a checkpoint, an anchor write or
``Store(...)``. Every result is a time-local LOCAL sample (``atomic`` is
always False): a hint only, never proof for an irreversible action.

Whole-acquisition prerequisites are checked in a fixed order; the first
failure refuses the whole acquisition with :class:`ObservationRefused`:

1. ``getblockchaininfo`` type/range validation (INVALID_REPLY), then the
   headers/blocks relation (SYNCING unless ``headers == blocks``);
2. scanner currency (SCANNER_BEHIND);
3. the tip bracket, retried once (TIP_MOVED).

Transport/decoder exceptions raised by the RPC object itself are never
caught or normalized here; they propagate unchanged so trust revocation
and fault state are preserved by the caller.
"""
import math
import re
import sqlite3
from decimal import Decimal

_TXID = re.compile(r'[0-9a-f]{64}')
_MAX_HEIGHT = 1_000_000

_SQLITE_OK = sqlite3.SQLITE_OK
_SQLITE_DENY = sqlite3.SQLITE_DENY
_ALLOW_ACTIONS = frozenset((
    getattr(sqlite3, 'SQLITE_READ', 20),
    getattr(sqlite3, 'SQLITE_SELECT', 21),
    getattr(sqlite3, 'SQLITE_FUNCTION', 31),
))
_TRANSACTION_ACTION = getattr(sqlite3, 'SQLITE_TRANSACTION', 22)
_TRANSACTION_ARGS = frozenset(('BEGIN', 'COMMIT', 'ROLLBACK'))


class ObservationRefused(Exception):
    """Whole-acquisition UNKNOWN. ``reason`` is a fixed public token."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class _TipMoved(Exception):
    """Internal: the bracket or mempool membership changed; retry once."""


def guarded_store_read(store, read_fn):
    """Run ``read_fn(db)`` under the store RLock and its transaction.

    A sqlite authorizer allowlist permits reads only; any denied write
    attempt is recorded and turns the read into a hard failure, even if
    the caller caught the resulting DatabaseError. The authorizer is
    always removed again, on success, failure and retry alike.
    """
    denied = []
    db = store.db

    def authorizer(action, arg1, _arg2, _database, _source):
        if action in _ALLOW_ACTIONS:
            return _SQLITE_OK
        if action == _TRANSACTION_ACTION and arg1 in _TRANSACTION_ARGS:
            return _SQLITE_OK
        denied.append(action)
        return _SQLITE_DENY

    with store.lock:
        with store.transaction():
            db.set_authorizer(authorizer)
            try:
                result = read_fn(db)
            finally:
                db.set_authorizer(None)
    if denied:
        raise ObservationRefused('STORE_WRITE_DENIED')
    return result


def _is_txid(value):
    return type(value) is str and _TXID.fullmatch(value) is not None


def _chain_tip(rpc):
    """Prerequisite 1: validated getblockchaininfo, then the tip hash."""
    info = rpc._call('getblockchaininfo', [])
    if type(info) is not dict:
        raise ObservationRefused('INVALID_REPLY')
    blocks = info.get('blocks')
    headers = info.get('headers')
    ibd = info.get('initialblockdownload')
    if type(blocks) is not int or not 0 <= blocks <= _MAX_HEIGHT:
        raise ObservationRefused('INVALID_REPLY')
    if (type(headers) is not int
            or not (headers == -1 or 0 <= headers <= _MAX_HEIGHT)):
        raise ObservationRefused('INVALID_REPLY')
    if type(ibd) is not bool:
        raise ObservationRefused('INVALID_REPLY')
    if headers != blocks:
        # headers == -1, headers > blocks and headers < blocks alike:
        # conservative unavailability, never a per-item contradiction.
        raise ObservationRefused('SYNCING')
    best = rpc.call('getbestblockhash')
    if not _is_txid(best):
        raise ObservationRefused('INVALID_REPLY')
    return (blocks, best), ibd


def _mempool(rpc):
    reply = rpc._call('getrawmempool', [])
    if type(reply) is not list or any(not _is_txid(item) for item in reply):
        raise ObservationRefused('INVALID_REPLY')
    if len(set(reply)) != len(reply):
        raise ObservationRefused('INVALID_REPLY')
    return frozenset(reply)


def _block_hash(rpc, height):
    reply = rpc.call('getblockhash', [height])
    if not _is_txid(reply):
        raise ObservationRefused('INVALID_REPLY')
    return reply


def _read_store(store, txids, outpoints):
    """All store facts for one acquisition, in one guarded read."""

    def read(db):
        row = db.execute(
            'SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1'
        ).fetchone()
        data = {
            'tip': (row[0], row[1]) if row else (0, '0' * 64),
            'history': {},
            'coins': {},
            'blocks': {},
        }
        heights = set()
        for txid in txids:
            rows = db.execute(
                'SELECT height FROM history WHERE txid=?', (txid,)).fetchall()
            data['history'][txid] = [r[0] for r in rows]
            heights.update(h for h in data['history'][txid]
                           if type(h) is int)
        for outpoint in outpoints:
            coin = db.execute(
                'SELECT atoms, public_key, spent FROM coins'
                ' WHERE txid=? AND vout=?', outpoint).fetchone()
            data['coins'][outpoint] = (
                None if coin is None else
                {'atoms': coin[0], 'public_key': coin[1], 'spent': coin[2]})
            if coin is not None and type(coin[2]) is int:
                heights.add(coin[2])
        for height in heights:
            block = db.execute(
                'SELECT hash FROM blocks WHERE height=?', (height,)).fetchone()
            data['blocks'][height] = None if block is None else block[0]
        return data

    return guarded_store_read(store, read)


def _base(state, tip, core_ibd, **extra):
    result = {'state': state, 'height': None, 'block_hash': None,
              'conflict_heights': [], 'depth': None, 'reason': None,
              'observed_tip': tip, 'core_ibd': core_ibd, 'atomic': False}
    result.update(extra)
    return result


def _anchored_hash(rpc, data, height):
    """Stored block hash at height, verified against Core; else None."""
    stored = data['blocks'].get(height)
    if stored is None or stored != _block_hash(rpc, height):
        return None
    return stored


def _generic(txid, data, mempool, rpc, tip, core_ibd):
    rows = data['history'][txid]
    if len(rows) > 1:
        raise ObservationRefused('CONTRADICTION')
    if len(rows) == 1:
        height = rows[0]
        if type(height) is not int or not 1 <= height <= tip[0]:
            raise ObservationRefused('CONTRADICTION')
        block_hash = _anchored_hash(rpc, data, height)
        if block_hash is None:
            raise ObservationRefused('CONTRADICTION')
        return _base('CONFIRMED', tip, core_ibd, height=height,
                     block_hash=block_hash, depth=tip[0] - height + 1)
    if txid in mempool:
        return _base('IN_MEMPOOL', tip, core_ibd)
    return _base('NOT_FOUND_LOCALLY', tip, core_ibd)


def _txout_atoms(value, coin):
    """Atoms for a gettxout value, or raise INVALID_REPLY."""
    from wam_sp.scanner import atoms as _atoms
    if type(value) is bool or type(value) not in (int, float):
        raise ObservationRefused('INVALID_REPLY')
    if type(value) is float and not math.isfinite(value):
        raise ObservationRefused('INVALID_REPLY')
    try:
        amount = _atoms(Decimal(str(value)))
    except Exception:
        raise ObservationRefused('INVALID_REPLY') from None
    if amount != coin['atoms']:
        raise ObservationRefused('INVALID_REPLY')
    return amount


def _intent(txid, outpoints, data, mempool, rpc, tip, core_ibd):
    rows = data['history'][txid]
    for outpoint in outpoints:
        vout = outpoint[1]
        if (type(vout) is not int or not 0 <= vout < 2 ** 32
                or data['coins'].get(outpoint) is None):
            return _base('UNKNOWN', tip, core_ibd, reason='INPUTS_UNVERIFIED')
    if len(rows) > 1:
        return _base('UNKNOWN', tip, core_ibd, reason='CONTRADICTION')
    if len(rows) == 1:
        height = rows[0]
        block_hash = (None if type(height) is not int
                      or not 1 <= height <= tip[0]
                      else _anchored_hash(rpc, data, height))
        if block_hash is None:
            return _base('UNKNOWN', tip, core_ibd, reason='CONTRADICTION')
        for outpoint in outpoints:
            coin = data['coins'].get(outpoint)
            if coin is None or coin['spent'] != height:
                return _base('UNKNOWN', tip, core_ibd, reason='CONTRADICTION')
        return _base('CONFIRMED', tip, core_ibd, height=height,
                     block_hash=block_hash, depth=tip[0] - height + 1)
    spent_values = [data['coins'][o]['spent'] for o in outpoints
                    if data['coins'][o]['spent'] is not None]
    if any(type(height) is not int for height in spent_values):
        return _base('UNKNOWN', tip, core_ibd, reason='CONTRADICTION')
    spent = sorted(set(spent_values))
    if spent:
        for height in spent:
            if (type(height) is not int or not 1 <= height <= tip[0]
                    or _anchored_hash(rpc, data, height) is None):
                return _base('UNKNOWN', tip, core_ibd, reason='CONTRADICTION')
        return _base('BLOCK_CONFLICTED', tip, core_ibd, height=spent[0],
                     block_hash=data['blocks'][spent[0]],
                     conflict_heights=spent)
    if txid in mempool:
        return _base('IN_MEMPOOL', tip, core_ibd)
    unavailable = False
    for outpoint in outpoints:
        coin = data['coins'][outpoint]
        reply = rpc.call('gettxout', [outpoint[0], outpoint[1], True])
        if reply is None:
            unavailable = True
            continue
        if type(reply) is not dict:
            raise ObservationRefused('INVALID_REPLY')
        script = reply.get('scriptPubKey')
        if (reply.get('bestblock') != tip[1]
                or type(script) is not dict
                or script.get('hex') != '5120' + str(coin['public_key'])):
            raise ObservationRefused('INVALID_REPLY')
        _txout_atoms(reply.get('value'), coin)
    if unavailable:
        return _base('INPUT_UNAVAILABLE', tip, core_ibd)
    return _base('NOT_SEEN_LOCALLY', tip, core_ibd)


def _attempt(scanner, rpc, requests):
    """One acquisition. requests: {txid: outpoints tuple or None=generic}."""
    tip, core_ibd = _chain_tip(rpc)
    if getattr(scanner, 'ready', None) is not True:
        raise ObservationRefused('SCANNER_BEHIND')
    mempool = _mempool(rpc)
    outpoints = set()
    for inputs in requests.values():
        if inputs:
            outpoints.update(inputs)
    data = _read_store(scanner.store, list(requests), sorted(outpoints))
    verified = getattr(scanner, 'verified_tip', None)
    if (not isinstance(verified, (tuple, list)) or tuple(verified) != tip
            or data['tip'] != tip):
        raise ObservationRefused('SCANNER_BEHIND')
    results = {}
    for txid, inputs in requests.items():
        results[txid] = (_generic(txid, data, mempool, rpc, tip, core_ibd)
                         if inputs is None else
                         _intent(txid, inputs, data, mempool, rpc, tip, core_ibd))
    mempool_after = _mempool(rpc)
    if any((txid in mempool) != (txid in mempool_after) for txid in requests):
        raise _TipMoved()
    best = rpc.call('getbestblockhash')
    height = rpc.call('getblockcount')
    if not _is_txid(best) or type(height) is not int or (height, best) != tip:
        raise _TipMoved()
    return results


def _acquire(scanner, rpc, requests):
    for _attempt_number in (1, 2):
        try:
            return _attempt(scanner, rpc, requests)
        except _TipMoved:
            continue
    raise ObservationRefused('TIP_MOVED')


def observe_generic(scanner, rpc, txid):
    """Contract G: generic txid presence for exact-txid inspection."""
    return _acquire(scanner, rpc, {txid: None})[txid]


def observe_intents(scanner, rpc, intents):
    """Contract I: per-txid intent observation in one acquisition.

    ``intents`` maps each exact txid to the reservation outpoints its
    evidence already decoded to. Per-item UNKNOWN results stay per item;
    whole-acquisition failures raise :class:`ObservationRefused`.
    """
    requests = {txid: tuple(sorted(inputs)) for txid, inputs in intents.items()}
    if not requests:
        return {}
    return _acquire(scanner, rpc, requests)
