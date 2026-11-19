"""PM-082 UX-01/UX-02: truthful broadcast-lock classification and display.

Synthetic scanner and Core doubles only. No genuine Core, no wallet profile,
and no reservation write.
"""
import os
import threading
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from test_obs01a_observation import IN_1, IN_2, TX, make_env
from wam_regtest.bip39_locale import t
from wam_regtest.domain.payment_state import (
    BROADCAST_BLOCK_CONFLICTED, BROADCAST_CONFIRMED, BROADCAST_EVICTED_LOCAL,
    BROADCAST_INPUT_UNAVAILABLE, BROADCAST_PENDING_MEMPOOL, BROADCAST_UNKNOWN,
    classify_broadcast_reservations, read_only_reservation_lock_summary,
    summarize_reservation_locks)
from wam_regtest.presentation.strings import CATALOG

NEW_KEYS = (
    'fusion.broadcast_mempool_locked', 'fusion.broadcast_evicted_locked',
    'fusion.broadcast_conflicted_locked', 'fusion.broadcast_unknown_locked',
    'fusion.locks_count_unknown', 'fusion.health_pending', 'fusion.health_pending_details',
    'fusion.health_attention', 'fusion.health_attention_details', 'fusion.health_unknown',
    'fusion.health_unknown_details', 'owner.locks_mempool_warning',
    'owner.locks_evicted_warning', 'owner.locks_conflicted_warning',
    'owner.locks_unknown_warning',
)
# 802 catalog keys on 5e4e15b (after PM-077 and PM-075) plus these 15,
# minus the five welcome.legacy_* keys retired by PM-086, plus the D4' refusal,
# plus the nine PM-090 REC-1 / deferred re-submission lines.
CATALOG_KEYS = 822
TXID = TX(0x3000)
TXID_B = TX(0x3001)
TXID_C = TX(0x3002)


def _token(name, rows, txid, evidence='ok', reason=None):
    return {'token': name, 'rows': rows, 'txid': txid, 'evidence': evidence, 'reason': reason}


def _summary(state, rows=1, txid=TXID, non_broadcast=()):
    classified = classify_broadcast_reservations(
        [_token('t0', rows, txid)], {txid: {'state': state}})
    return summarize_reservation_locks(classified, list(non_broadcast))


class PureClassification(unittest.TestCase):
    def test_each_obs_state_maps_to_one_attention_level(self):
        cases = (
            ('CONFIRMED', 'NONE', 0, False),
            ('IN_MEMPOOL', 'PENDING', 1, True),
            ('NOT_SEEN_LOCALLY', 'ATTENTION_REQUIRED', 1, True),
            ('BLOCK_CONFLICTED', 'ATTENTION_REQUIRED', 1, True),
            ('INPUT_UNAVAILABLE', 'ATTENTION_REQUIRED', 1, True),
            ('UNKNOWN', 'UNKNOWN_UNVERIFIED', 1, True),
        )
        classes = {
            'CONFIRMED': BROADCAST_CONFIRMED,
            'IN_MEMPOOL': BROADCAST_PENDING_MEMPOOL,
            'NOT_SEEN_LOCALLY': BROADCAST_EVICTED_LOCAL,
            'BLOCK_CONFLICTED': BROADCAST_BLOCK_CONFLICTED,
            'INPUT_UNAVAILABLE': BROADCAST_INPUT_UNAVAILABLE,
            'UNKNOWN': BROADCAST_UNKNOWN,
        }
        for state, level, locked, attention in cases:
            with self.subTest(state=state):
                classified = classify_broadcast_reservations(
                    [_token('t', 2, TXID)], {TXID: {'state': state, 'reason': 'INPUTS_UNVERIFIED'}})
                self.assertEqual(classified[0]['classification'], classes[state])
                summary = summarize_reservation_locks(classified, [])
                self.assertEqual(summary['attention_level'], level)
                self.assertEqual(summary['locked_inputs_total'], 0 if state == 'CONFIRMED' else 2)
                self.assertEqual(summary['confirmed_leftover_inputs'], 2 if state == 'CONFIRMED' else 0)
                self.assertIs(summary['read_only'], False)
                self.assertEqual(summary['tokens_needing_attention'] > 0, attention)
                if state == 'CONFIRMED':
                    self.assertTrue(summary['verified'])
                    self.assertEqual(summary['locked_inputs_total'], locked)

    def test_read_only_summary_never_claims_zero_or_verified(self):
        summary = read_only_reservation_lock_summary()
        self.assertEqual(summary['attention_level'], 'READ_ONLY')
        self.assertIs(summary['read_only'], True)
        self.assertIs(summary['verified'], False)
        self.assertIsNone(summary['locked_inputs_total'])
        self.assertIsNone(summary['observation_refused_reason'])

    def test_mixed_confirmed_evicted_and_mempool_counts_only_open_locks(self):
        classified = classify_broadcast_reservations([
            _token('t0', 1, TXID),
            _token('t1', 2, TXID_B),
            _token('t2', 1, TXID_C),
        ], {
            TXID: {'state': 'CONFIRMED'},
            TXID_B: {'state': 'NOT_SEEN_LOCALLY'},
            TXID_C: {'state': 'IN_MEMPOOL'},
        })
        signed = [{'token': 't3', 'state': 'signed', 'rows': 1}]
        summary = summarize_reservation_locks(classified, signed)
        self.assertEqual(summary['confirmed_leftover_inputs'], 1)
        self.assertEqual(summary['counts']['evicted'], 2)
        self.assertEqual(summary['counts']['mempool'], 1)
        self.assertEqual(summary['counts']['non_broadcast'], 1)
        self.assertEqual(summary['locked_inputs_total'], 4)
        self.assertEqual(summary['attention_level'], 'ATTENTION_REQUIRED')
        self.assertEqual(summary['state_breakdown']['signed'], 1)
        self.assertEqual(summary['tokens_needing_attention'], 3)

    def test_fingerprint_mismatch_is_unknown_with_no_total(self):
        classified = classify_broadcast_reservations(
            [_token('t', 2, None, evidence='unavailable', reason='FINGERPRINT_MISMATCH')])
        summary = summarize_reservation_locks(classified, [], verified_fingerprint=False)
        self.assertEqual(summary['attention_level'], 'UNKNOWN_UNVERIFIED')
        self.assertIsNone(summary['locked_inputs_total'])
        self.assertFalse(summary['verified'])
        self.assertEqual(summary['counts']['unknown'], 2)


def _decode(raw):
    spec = _PSBT[raw]
    return SimpleNamespace(tx=SimpleNamespace(inputs=list(spec['inputs'])), txid=lambda: spec['txid'])


_PSBT = {}


def _body(txid, key, inputs):
    _PSBT[key] = {'txid': txid, 'inputs': inputs}
    return {'txid': txid, 'signed_psbt': key.hex(), 'recipient': 'wamrtsp1public',
            'atoms': 50_000, 'fee': 1000}


def _fingerprint(rows):
    counts = {}
    for row in rows:
        counts[row[3]] = counts.get(row[3], 0) + 1
    ordered = tuple(sorted(counts.items()))
    return len(rows), tuple(state for state, _rows in ordered), ordered


class SessionClassification(unittest.TestCase):
    def setUp(self):
        _PSBT.clear()
        patcher = patch('wam_sp.psbt.PSBT.decode', side_effect=_decode)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _open(self, rows, evidence, prepare=None):
        store, scanner, rpc = make_env()
        if prepare is not None:
            prepare(store, rpc)
        if rows:
            store.db.executemany(
                'INSERT INTO reservations VALUES (?,?,?,?)', rows)
            store.db.commit()
        from wam_regtest.bip39_spend_session import Q06OwnedSpendSession
        session = object.__new__(Q06OwnedSpendSession)
        session._lock = threading.RLock()
        session._q06_pending_confirm = None
        session.scanner = scanner
        session._rpc = lambda: rpc

        def read(token, stage):
            value = evidence.get(token)
            if isinstance(value, BaseException):
                raise value
            return value

        session._read_payment_evidence = read
        session.rpc = rpc
        session.store = store
        return session

    def _summarize(self, session, rows):
        count, states, state_counts = _fingerprint(rows)
        return session.reservation_lock_summary(
            reservation_count=count, reservation_states=states,
            reservation_state_counts=state_counts)

    def test_live_observation_classifies_each_broadcast_state(self):
        def confirmed(store, rpc):
            store.db.execute('UPDATE coins SET spent=4 WHERE txid=? AND vout=?', IN_1)
            store.add_history(TXID, 4)
            store.db.commit()

        def mempool(store, rpc):
            rpc.mempool = [TXID]

        def evicted(store, rpc):
            return None

        def block_conflict(store, rpc):
            store.db.execute('UPDATE coins SET spent=4 WHERE txid=? AND vout=?', IN_1)
            store.db.commit()

        def unavailable(store, rpc):
            rpc.txouts[IN_1] = None

        def unknown(store, rpc):
            store.db.execute('DELETE FROM coins WHERE txid=? AND vout=?', IN_1)
            store.db.commit()

        expected = (
            (confirmed, 'NONE', 'mempool', 0),
            (mempool, 'PENDING', 'mempool', 1),
            (evicted, 'ATTENTION_REQUIRED', 'evicted', 1),
            (block_conflict, 'ATTENTION_REQUIRED', 'conflicted', 1),
            (unavailable, 'ATTENTION_REQUIRED', 'conflicted', 1),
            (unknown, 'UNKNOWN_UNVERIFIED', 'unknown', 1),
        )
        rows = [(IN_1[0], IN_1[1], 't1', 'broadcast')]
        evidence = {'t1': _body(TXID, b'\x11', [IN_1])}
        for prepare, level, bucket, count in expected:
            with self.subTest(level=level):
                session = self._open(rows, evidence, prepare)
                summary = self._summarize(session, rows)
                self.assertEqual(summary['attention_level'], level)
                self.assertEqual(summary['counts'][bucket], count)
                self.assertIsNone(session._q06_pending_confirm)

    def test_two_mempool_broadcasts_stay_pending_without_a_single_txid(self):
        rows = [
            (IN_1[0], IN_1[1], 't1', 'broadcast'),
            (IN_2[0], IN_2[1], 't2', 'broadcast'),
        ]
        evidence = {
            't1': _body(TXID, b'\x11', [IN_1]),
            't2': _body(TXID_B, b'\x22', [IN_2]),
        }
        session = self._open(rows, evidence, lambda store, rpc: rpc.__setattr__('mempool', [TXID, TXID_B]))
        summary = self._summarize(session, rows)
        self.assertIsNone(session._q06_pending_confirm)
        self.assertEqual(summary['counts']['mempool'], 2)
        self.assertEqual(summary['attention_level'], 'PENDING')
        self.assertEqual(summary['tokens_needing_attention'], 2)

    def test_confirmed_plus_signed_counts_both(self):
        def prepare(store, rpc):
            store.db.execute('UPDATE coins SET spent=4 WHERE txid=? AND vout=?', IN_1)
            store.add_history(TXID, 4)
            store.db.commit()

        rows = [
            (IN_1[0], IN_1[1], 't1', 'broadcast'),
            (IN_2[0], IN_2[1], 't2', 'signed'),
        ]
        session = self._open(rows, {'t1': _body(TXID, b'\x11', [IN_1])}, prepare)
        summary = self._summarize(session, rows)
        self.assertEqual(summary['confirmed_leftover_inputs'], 1)
        self.assertEqual(summary['counts']['non_broadcast'], 1)
        self.assertEqual(summary['attention_level'], 'ATTENTION_REQUIRED')
        self.assertEqual(summary['state_breakdown']['signed'], 1)

    def test_bad_evidence_duplicate_and_mixed_token_are_unknown(self):
        cases = []
        rows = [(IN_1[0], IN_1[1], 't1', 'broadcast')]
        cases.append(('missing', rows, {}))
        cases.append(('raises', rows, {'t1': ValueError('unreadable')}))
        bad = _body(TXID, b'\x31', [IN_1])
        bad['signed_psbt'] = 'zz'
        cases.append(('decode', rows, {'t1': bad}))
        mismatched = _body(TXID_B, b'\x32', [IN_1])
        mismatched['txid'] = TXID
        cases.append(('txid', rows, {'t1': mismatched}))
        cases.append(('inputs', rows, {'t1': _body(TXID, b'\x33', [IN_2])}))
        duplicate_rows = [
            (IN_1[0], IN_1[1], 't1', 'broadcast'),
            (IN_2[0], IN_2[1], 't2', 'broadcast'),
        ]
        cases.append(('duplicate', duplicate_rows, {
            't1': _body(TXID, b'\x34', [IN_1]),
            't2': _body(TXID, b'\x35', [IN_2]),
        }))
        mixed_rows = [
            (IN_1[0], IN_1[1], 't1', 'broadcast'),
            (IN_2[0], IN_2[1], 't1', 'signed'),
        ]
        cases.append(('mixed', mixed_rows, {'t1': _body(TXID, b'\x36', [IN_1])}))
        for name, case_rows, evidence in cases:
            with self.subTest(name=name):
                session = self._open(case_rows, evidence)
                summary = self._summarize(session, case_rows)
                self.assertEqual(summary['attention_level'], 'UNKNOWN_UNVERIFIED')
                self.assertGreater(summary['counts']['unknown'], 0)
                self.assertFalse(summary['verified'])
                self.assertEqual(session.rpc.calls, [])

    def test_observation_refused_degrades_without_hiding_the_lock(self):
        from wam_regtest.tx_observation import ObservationRefused
        rows = [(IN_1[0], IN_1[1], 't1', 'broadcast')]
        evidence = {'t1': _body(TXID, b'\x11', [IN_1])}
        for reason in ('SYNCING', 'SCANNER_BEHIND', 'TIP_MOVED', 'INVALID_REPLY', 'STORE_WRITE_DENIED'):
            with self.subTest(reason=reason):
                session = self._open(rows, evidence)
                with patch('wam_regtest.tx_observation.observe_intents',
                           side_effect=ObservationRefused(reason)):
                    summary = self._summarize(session, rows)
                self.assertEqual(summary['observation_refused_reason'], reason)
                self.assertEqual(summary['attention_level'], 'UNKNOWN_UNVERIFIED')
                self.assertEqual(summary['counts']['unknown'], 1)
                self.assertFalse(summary['verified'])

    def test_transport_errors_propagate(self):
        rows = [(IN_1[0], IN_1[1], 't1', 'broadcast')]
        evidence = {'t1': _body(TXID, b'\x11', [IN_1])}
        for failure in (ConnectionError('down'), OSError('down')):
            with self.subTest(failure=type(failure).__name__):
                session = self._open(rows, evidence)
                session.rpc.failure = failure
                with self.assertRaises(type(failure)):
                    self._summarize(session, rows)

    def test_classification_does_not_write_reservations_or_history(self):
        rows = [(IN_1[0], IN_1[1], 't1', 'broadcast')]
        session = self._open(rows, {'t1': _body(TXID, b'\x11', [IN_1])})
        writes = []
        real = session.store.db.execute
        before = real(
            'SELECT txid, vout, token, state FROM reservations ORDER BY token, txid, vout').fetchall()
        history = real('SELECT txid, height FROM history').fetchall()
        session.store.db.set_trace_callback(writes.append)
        try:
            summary = self._summarize(session, rows)
        finally:
            session.store.db.set_trace_callback(None)
        after = real(
            'SELECT txid, vout, token, state FROM reservations ORDER BY token, txid, vout').fetchall()
        self.assertEqual(summary['attention_level'], 'ATTENTION_REQUIRED')
        self.assertEqual([tuple(row) for row in before], [tuple(row) for row in after])
        self.assertEqual([tuple(row) for row in history],
                         [tuple(row) for row in real('SELECT txid, height FROM history')])
        self.assertFalse(any(text.lstrip().upper().startswith(('INSERT', 'UPDATE', 'DELETE', 'REPLACE'))
                             for text in writes))
        self.assertIsNone(session._q06_pending_confirm)


def _app():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def _fusion(summary, **overrides):
    from wam_regtest.qualification.ui_gallery import _fixture_snapshot
    _snap, result = _fixture_snapshot()
    result = dict(result)
    snap = result['fusion_snapshot']
    result.update(height=snap.height, tip=snap.tip, history=(), payment_review=None,
                  payment_signed=False, pending_confirm_txid=None)
    result['reservation_lock_summary'] = summary
    result.update(overrides)
    if 'signer_allowed' in overrides or 'broadcast_allowed' in overrides:
        result['fusion_snapshot'] = replace(
            snap,
            signer_allowed=result['signer_allowed'],
            broadcast_allowed=result['broadcast_allowed'])
    return result


class OverviewAndSend(unittest.TestCase):
    def setUp(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.wallet_executor import ExecutorState
        self.app = _app()
        owner = SimpleNamespace(
            state=ExecutorState(locked=False, faulted=False, core_alive=True),
            busy=False, closed=False)
        self.window = Bip39FusionWindow(owner)
        self.window._poll.stop()
        self.window._ready = True
        self.window._spend_enabled = True

    def tearDown(self):
        self.window._poll.stop()
        self.window.deleteLater()
        self.app.processEvents()

    def _render(self, summary, **overrides):
        self.window._render_verified(_fusion(summary, **overrides))

    def test_unknown_missing_and_empty_count_never_look_normal(self):
        unknown = _summary('UNKNOWN')
        for summary, count in ((unknown, 1), (None, None), (None, 0)):
            with self.subTest(summary=getattr(summary, 'get', lambda *_a: None)('attention_level') if isinstance(summary, dict) else None, count=count):
                self.window.overview.render_snapshot(
                    _fusion(None)['fusion_snapshot'], operational=True,
                    reservation_lock_summary=summary, reservation_count=count)
                details = self.window.overview.fund_details.text()
                self.assertNotIn('0' + t('fusion.reserved_input_s_stay_unavailable'), details)
                self.assertNotEqual(self.window.overview.health_value.text(), t('fusion.operating_normally'))
                if summary is None or summary['locked_inputs_total'] is None or summary['counts']['unknown']:
                    self.assertTrue(
                        t('fusion.locks_count_unknown') in details
                        or t('fusion.broadcast_unknown_locked').split('{count}')[0].strip() in details
                        or '{count}' not in t('fusion.broadcast_unknown_locked') and 'unverified' in details.lower()
                        or t('fusion.broadcast_unknown_locked').format(count=summary['counts']['unknown'] if summary else 0) in details)

    def test_each_classification_renders_truthful_overview_copy(self):
        evicted = _summary('NOT_SEEN_LOCALLY', rows=2)
        conflicted = _summary('BLOCK_CONFLICTED')
        unavailable = _summary('INPUT_UNAVAILABLE', rows=3)
        pending = _summary('IN_MEMPOOL', rows=4)
        confirmed = _summary('CONFIRMED', rows=5)
        self._render(evicted)
        self.assertIn(t('fusion.broadcast_evicted_locked').format(count=2), self.window.overview.fund_details.text())
        self.assertEqual(self.window.overview.health_value.text(), t('fusion.health_attention'))
        self._render(conflicted)
        self.assertIn(t('fusion.broadcast_conflicted_locked').format(count=1), self.window.overview.fund_details.text())
        self.assertEqual(self.window.overview.health_value.text(), t('fusion.health_attention'))
        self._render(unavailable)
        self.assertIn(t('fusion.broadcast_conflicted_locked').format(count=3), self.window.overview.fund_details.text())
        self._render(pending)
        self.assertIn(t('fusion.broadcast_mempool_locked').format(count=4), self.window.overview.fund_details.text())
        self.assertEqual(self.window.overview.health_value.text(), t('fusion.health_pending'))
        self.assertIn(t('fusion.health_pending_details'), self.window.overview.health_details.text())
        self._render(confirmed)
        self.assertNotIn(t('fusion.reserved_input_s_stay_unavailable'), self.window.overview.fund_details.text())
        self.assertNotIn('broadcast input', self.window.overview.fund_details.text())
        self.assertEqual(self.window.overview.health_value.text(), t('fusion.operating_normally'))

    def test_composite_segments_keep_every_lock_visible(self):
        classified = classify_broadcast_reservations([
            _token('t1', 2, TXID), _token('t2', 1, TXID_B),
        ], {TXID: {'state': 'NOT_SEEN_LOCALLY'}, TXID_B: {'state': 'IN_MEMPOOL'}})
        summary = summarize_reservation_locks(
            classified, [{'token': 't3', 'state': 'signed', 'rows': 1}])
        self._render(summary)
        text = self.window.overview.fund_details.text()
        evicted = text.index(t('fusion.broadcast_evicted_locked').format(count=2))
        mempool = text.index(t('fusion.broadcast_mempool_locked').format(count=1))
        signed = text.index('1' + t('fusion.reserved_input_s_stay_unavailable'))
        self.assertLess(evicted, mempool)
        self.assertLess(mempool, signed)

    def test_read_only_scan_is_neither_zero_locks_nor_operating_normally(self):
        from wam_regtest.bip39_owner_gui import Bip39TrialWindow
        from wam_regtest.domain.payment_state import read_only_reservation_lock_summary as read_only
        from wam_regtest.wallet_executor import ExecutorState
        summary = read_only()
        result = _fusion(summary, signer_allowed=False, broadcast_allowed=False,
                         reservation_count=None, status='Q06_REGTEST_REAL_CORE_READ_ONLY_VERIFIED')
        self.window._render_verified(result)
        overview = self.window.overview
        self.assertEqual(overview.health_value.text(), t('fusion.read_only_regtest_wallet'))
        self.assertNotEqual(overview.health_value.text(), t('fusion.operating_normally'))
        self.assertEqual(overview.health_details.text(), t('fusion.send_disabled'))
        self.assertIn(t('fusion.locks_count_unknown'), overview.fund_details.text())
        self.assertNotIn('0' + t('fusion.reserved_input_s_stay_unavailable'), overview.fund_details.text())
        self.assertFalse(overview.custody_switch.isChecked())
        self.assertEqual(overview.custody_switch.text(), t('fusion.locked'))
        owner = SimpleNamespace(state=ExecutorState(locked=False, faulted=False, core_alive=True),
                                busy=False, closed=False)
        trial = Bip39TrialWindow(owner)
        trial._poll.stop()
        trial._spend_enabled = False
        try:
            trial._on_ready('snapshot', result)
            self.assertEqual(trial.status.text(), t('owner.scan_verified'))
        finally:
            trial._poll.stop()
            trial.deleteLater()

    def test_broadcast_and_snapshot_do_not_keep_until_confirmed(self):
        self.window._on_ready('broadcast', TXID)
        text = self.window.send_result.text()
        self.assertNotIn('until confirmed', text)
        self.assertIn(t('pages.no_retry_until_confirmed').strip(), text.replace('\u200b', ''))
        pending = _summary('IN_MEMPOOL')
        self.window._on_ready('snapshot', _fusion(
            pending, pending_confirm_txid=TXID, payment_review=None))
        refreshed = self.window.send_result.text().replace('\u200b', '')
        self.assertIn(t('pages.mempool_pending').strip(), refreshed)
        self.assertNotIn('until confirmed', refreshed)
        self.assertNotIn(t('pages.submitted_pending').strip(), refreshed)

    def test_stale_send_result_is_replaced_for_every_bad_broadcast(self):
        stale = t('pages.submitted_pending') + TXID + t('pages.no_retry_until_confirmed')
        states = (
            ('NOT_SEEN_LOCALLY',),
            ('BLOCK_CONFLICTED',),
            ('INPUT_UNAVAILABLE',),
            ('UNKNOWN',),
        )
        for state, in states:
            for keep_pending in (True, False):
                with self.subTest(state=state, keep_pending=keep_pending):
                    self.window._broadcast_complete = False
                    self.window._last_review = None
                    self.window._pending_confirm_txid = TXID if keep_pending else None
                    self.window.last_txid.setText(TXID)
                    self.window.send_result.setText(stale)
                    summary = _summary(state)
                    pending = TXID if keep_pending else None
                    self.window._on_ready('snapshot', _fusion(
                        summary, pending_confirm_txid=pending, payment_review=None))
                    text = self.window.send_result.text().replace('\u200b', '')
                    self.assertNotIn(t('pages.submitted_pending').strip(), text)
                    self.assertNotIn('Confirmation is pending.', text)
                    self.assertTrue(
                        t('pages.txid_uncertain').strip() in text
                        or t('pages.broadcast_uncertain') in text)
                    self.assertIn(t('pages.no_retry_or_release').strip(), text)

    def test_lock_and_quit_reset_the_send_result(self):
        self.window.send_result.setText(t('pages.submitted_pending') + TXID)
        self.window._on_ready('lock', {})
        self.assertEqual(self.window.send_result.text(), t('wallet.no_broadcast_result'))
        self.window.send_result.setText(t('pages.mempool_pending') + TXID)
        self.window._on_ready('quit', {})
        self.assertEqual(self.window.send_result.text(), t('wallet.no_broadcast_result'))


class OwnerStatus(unittest.TestCase):
    def setUp(self):
        from wam_regtest.bip39_owner_gui import Bip39TrialWindow
        from wam_regtest.wallet_executor import ExecutorState
        self.app = _app()
        owner = SimpleNamespace(state=ExecutorState(locked=False, faulted=False, core_alive=True),
                                busy=False, closed=False)
        self.window = Bip39TrialWindow(owner)
        self.window._poll.stop()
        self.window._spend_enabled = True
        self.window._recovered_unsigned_cancel = False
        self.window._pending_confirm_txid = None

    def tearDown(self):
        self.window._poll.stop()
        self.window.deleteLater()
        self.app.processEvents()

    def _status(self, summary, **overrides):
        result = {
            'signer_allowed': True, 'receive_code': 'wamrtsp1example', 'confirmed_atoms': 0,
            'available_atoms': 0, 'height': 3, 'tip': 'ab' * 32, 'history': (),
            'reservation_count': 1, 'reservation_states': ('broadcast',),
            'payment_review': None, 'pending_confirm_txid': None,
            'reservation_lock_summary': summary,
        }
        result.update(overrides)
        self.window._on_ready('snapshot', result)
        return self.window.status.text()

    def test_precedence_never_uses_the_calm_line_while_locks_remain(self):
        signed = summarize_reservation_locks([], [{'token': 'd', 'state': 'draft', 'rows': 1}])
        cases = (
            (_summary('CONFIRMED'), None, t('owner.send_verified')),
            (_summary('IN_MEMPOOL'), None, t('owner.locks_mempool_warning')),
            (_summary('IN_MEMPOOL'), TXID, t('owner.awaiting_confirmation').format(txid=TXID)),
            (_summary('NOT_SEEN_LOCALLY'), TXID, t('owner.locks_evicted_warning')),
            (_summary('BLOCK_CONFLICTED'), None, t('owner.locks_conflicted_warning')),
            (_summary('INPUT_UNAVAILABLE'), None, t('owner.locks_conflicted_warning')),
            (_summary('UNKNOWN'), None, t('owner.locks_unknown_warning')),
            (signed, None, t('owner.reservations_warning')),
        )
        for summary, pending, expected in cases:
            with self.subTest(expected=expected[:24]):
                self.window._pending_confirm_txid = pending
                self.window._recovered_unsigned_cancel = False
                text = self._status(summary, pending_confirm_txid=pending)
                self.assertEqual(text, expected)
                if summary.get('attention_level') != 'NONE':
                    self.assertNotEqual(text, t('owner.send_verified'))
        self.window._pending_confirm_txid = TXID
        self.assertEqual(self._status(
            _summary('UNKNOWN'), pending_confirm_txid=TXID,
            recovered_unsigned_cancel_available=True), t('owner.draft_retained'))


class Catalog(unittest.TestCase):
    def test_new_keys_and_revised_retry_copy_match_across_locales(self):
        self.assertEqual(len(CATALOG['en']), CATALOG_KEYS)
        for language, entries in CATALOG.items():
            self.assertEqual(len(entries), CATALOG_KEYS, language)
            self.assertNotIn('until confirmed', entries['pages.no_retry_until_confirmed'])
            self.assertIn(entries['pages.no_retry_until_confirmed'], entries.values())
            for key in NEW_KEYS:
                self.assertIn(key, entries)
        self.assertIn('automatically', CATALOG['en']['pages.no_retry_until_confirmed'])


if __name__ == '__main__':
    unittest.main()
