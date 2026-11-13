"""Complete WSP history paging under one SQLite snapshot.

Pinned Wallet.history allows limit 1..1000 and offset 0..1_000_000, and each
public history() call starts its own BEGIN IMMEDIATE. Callers must hold one
store.transaction() and read via _history or equivalent SQL, never separate
public history() pages.
"""
from hashlib import sha256
import json
import re

HISTORY_PAGE_LIMIT=1000
HISTORY_OFFSET_MAX=1_000_000
HISTORY_COMPLETE_MAX=HISTORY_OFFSET_MAX+HISTORY_PAGE_LIMIT
# GUI/session display window. Full fingerprint still visits every row.
GUI_HISTORY_LIMIT=250
_TXID=re.compile('[0-9a-f]{64}\\Z')


class HistoryPageError(ValueError):
    pass


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def complete_history(read_page,declared,height,*,collect=False,keep_tail=0,
                    skip_newest=0,error=HistoryPageError):
    """Hash every canonical WSP history row; optionally retain a bounded window.

    read_page(limit, offset) must observe the same snapshot as declared.
    Order is WSP canonical: height,txid ascending.
    skip_newest drops newest rows from the display window only after hashing.
    """
    if type(declared) is not int or declared<0:
        raise error('HISTORY_INCONSISTENT')
    if declared>HISTORY_COMPLETE_MAX:
        raise error('HISTORY_INCOMPLETE')
    if (type(keep_tail) is not int or keep_tail<0
            or type(skip_newest) is not int or skip_newest<0
            or (collect and (keep_tail or skip_newest))
            or (skip_newest and not keep_tail)):
        raise error('HISTORY_INCONSISTENT')
    digest=sha256(b'[');seen=0;offset=0;previous=None
    window_start=max(0,declared-skip_newest-keep_tail) if keep_tail else 0
    window_end=max(0,declared-skip_newest) if keep_tail else 0
    rows=[] if collect or keep_tail else None
    while True:
        if offset>HISTORY_OFFSET_MAX:
            raise error('HISTORY_INCOMPLETE')
        page=read_page(HISTORY_PAGE_LIMIT,offset)
        if type(page) is not list or len(page)>HISTORY_PAGE_LIMIT:
            raise error('HISTORY_INCONSISTENT')
        if not page:
            break
        for row in page:
            if type(row) is not dict:
                raise error('HISTORY_INCONSISTENT')
            txid,row_height=row.get('txid'),row.get('height')
            if (type(txid) is not str or not _TXID.fullmatch(txid)
                    or type(row_height) is not int or not 1<=row_height<=height):
                raise error('HISTORY_INCONSISTENT')
            order=(row_height,txid)
            if previous is not None and order<=previous:
                raise error('HISTORY_INCONSISTENT')
            confirmations=row.get('confirmations')
            if (type(confirmations) is not int or confirmations<1
                    or confirmations!=height-row_height+1):
                raise error('HISTORY_INCONSISTENT')
            if seen:
                digest.update(b',')
            digest.update(_canonical(row));seen+=1;previous=order
            if collect or (keep_tail and window_start<=seen-1<window_end):
                rows.append(row)
            if seen>declared:
                raise error('HISTORY_INCONSISTENT')
        if len(page)<HISTORY_PAGE_LIMIT or seen==declared:
            break
        offset+=len(page)
    digest.update(b']')
    if seen!=declared:
        raise error('HISTORY_INCONSISTENT')
    return seen,digest.hexdigest(),rows


def sql_history_pages(db,tip_height,sql,error=HistoryPageError,code='HISTORY_DENIED',
                     window=None,skip=0):
    """Page a stable ORDER BY query; refuse truncation and count mismatch.

    window keeps only N already-ordered rows (newest-first SQL) after skip.
    Every row is still validated so the GUI cannot silently drop a tail.
    """
    declared=db.execute('SELECT count(*) FROM history').fetchone()[0]
    if type(declared) is not int or declared<0:
        raise error(code)
    if declared>HISTORY_COMPLETE_MAX:
        raise error(code)
    if window is not None and (type(window) is not int or window<1):
        raise error(code)
    if type(skip) is not int or skip<0 or (skip and window is None):
        raise error(code)
    seen=0;offset=0;out=[]
    while True:
        if offset>HISTORY_OFFSET_MAX:
            raise error(code)
        page=list(db.execute(sql,(HISTORY_PAGE_LIMIT,offset)))
        if len(page)>HISTORY_PAGE_LIMIT:
            raise error(code)
        if not page:
            break
        for txid,block,credit,debit in page:
            if (type(txid) is not str or not _TXID.fullmatch(txid)
                    or type(block) is not int or not 1<=block<=tip_height
                    or type(credit) is not int or type(debit) is not int
                    or not 0<=credit<=22_000_000*100_000_000
                    or not 0<=debit<=22_000_000*100_000_000):
                raise error(code)
            if window is None or (seen>=skip and len(out)<window):
                out.append((txid,block,credit,debit,tip_height-block+1))
            seen+=1
            if seen>declared:
                raise error(code)
        if len(page)<HISTORY_PAGE_LIMIT or seen==declared:
            break
        offset+=len(page)
    if seen!=declared:
        raise error(code)
    return declared,out


def pending_activity(scanner, balance, read_evidence=None):
    """Bounded display only, inside the caller's existing SQLite transaction.

    Reservation tokens select authenticated, persisted broadcast evidence. It is
    never authority to spend/release/replay. A current WSP mempool must match
    every input before a broadcast is called observed; stale tables are ignored.
    Confirmed IDs are checked against ALL history, independent of GUI paging.
    """
    from .wallet_read import PendingHistoryRow
    from wam_sp.psbt import PSBT

    db = scanner.store.db
    ready = scanner.mempool_ready
    pending = balance.get('unconfirmed_atoms') if ready else None
    spent = balance.get('pending_spent_atoms') if ready else None
    rows = []
    owned_ids = set()
    if read_evidence is not None:
        tokens = db.execute(
            "SELECT DISTINCT token FROM reservations WHERE state='broadcast' "
            "ORDER BY token LIMIT ?", (GUI_HISTORY_LIMIT,)).fetchall()
        for (token,) in tokens:
            try:
                body = read_evidence(token, 'broadcast')
                if body is None:
                    continue
                psbt = PSBT.decode(bytes.fromhex(body['signed_psbt']))
                txid, atoms, fee = body['txid'], body['atoms'], body['fee']
                members = {tuple(row) for row in db.execute(
                    "SELECT txid,vout FROM reservations WHERE token=? AND state='broadcast'",
                    (token,))}
                if (txid != psbt.txid() or set(psbt.tx.inputs) != members
                        or type(atoms) is not int or atoms <= 0
                        or type(fee) is not int or fee <= 0
                        or sum(v for v, _ in psbt.utxos) - sum(v for v, _ in psbt.tx.outputs) != fee
                        or not any(v == atoms for v, _ in psbt.tx.outputs)):
                    continue
                if db.execute('SELECT 1 FROM history WHERE txid=? AND height>0', (txid,)).fetchone():
                    owned_ids.add(txid)
                    continue
                if ready:
                    observations = [db.execute(
                        'SELECT spending FROM mempool_spends WHERE txid=? AND vout=?',
                        coin).fetchone() for coin in members]
                    if any(row is None or row[0] != txid for row in observations):
                        continue
                change = sum(v for v, _ in psbt.utxos) - atoms - fee
                if change < 0 or txid in owned_ids:
                    continue
                owned_ids.add(txid)
                rows.append(PendingHistoryRow(txid, 0, 0, 0, atoms + fee,
                            fee_atoms=fee, pending_change_atoms=change if ready else None))
            except (ValueError, TypeError, KeyError, OSError, RuntimeError):
                # Supplemental evidence may be absent/invalid. Never fabricate
                # an amount or alter the native reservation on a display read.
                continue
    if ready:
        for txid, credit in db.execute(
                'SELECT c.txid,sum(c.atoms) FROM mempool_coins c '
                'WHERE NOT EXISTS(SELECT 1 FROM mempool_spends s '
                'WHERE s.txid=c.txid AND s.vout=c.vout) '
                'AND NOT EXISTS(SELECT 1 FROM history h WHERE h.txid=c.txid AND h.height>0) '
                'GROUP BY c.txid ORDER BY c.txid LIMIT ?', (GUI_HISTORY_LIMIT,)):
            if txid in owned_ids:
                continue
            if (type(txid) is not str or not _TXID.fullmatch(txid)
                    or type(credit) is not int or not 0 < credit <= 22_000_000*100_000_000):
                raise HistoryPageError('PENDING_HISTORY_INCONSISTENT')
            rows.append(PendingHistoryRow(txid, 0, 0, credit, 0))
    return pending, spent, tuple(rows[:GUI_HISTORY_LIMIT])
