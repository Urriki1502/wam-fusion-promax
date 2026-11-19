"""PM-013: W-TX-03b — the overview does not show a confirmed payment's leftover rows
as reserved inputs that "stay unavailable". Intentional, isolated display change."""
import unittest
from types import SimpleNamespace

from wam_regtest.domain.payment_state import reserved_rows_needing_attention


class ReservedRows(unittest.TestCase):
    def test_only_non_broadcast_rows_lock_coins(self):
        self.assertEqual(reserved_rows_needing_attention(()), 0)
        self.assertEqual(reserved_rows_needing_attention((('broadcast', 3),)), 0)
        self.assertEqual(reserved_rows_needing_attention((('broadcast', 3), ('signed', 2))), 2)
        self.assertEqual(reserved_rows_needing_attention(
            (('draft', 1), ('manual', 4), ('uncertain', 2))), 7)  # unknown states still count

    def test_overview_display_rule_and_fallback(self):
        import os
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        from wam_regtest.bip39_fusion_gui import displayed_reserved_inputs
        from wam_regtest.domain.payment_state import (
            classify_broadcast_reservations, summarize_reservation_locks)
        txid = 'ab' * 32
        confirmed = summarize_reservation_locks(classify_broadcast_reservations(
            [{'token': 't', 'rows': 2, 'txid': txid, 'evidence': 'ok'}],
            {txid: {'state': 'CONFIRMED'}}), [])
        self.assertEqual(displayed_reserved_inputs({
            'reservation_count': 2, 'reservation_state_counts': (('broadcast', 2),),
            'reservation_lock_summary': confirmed}), 0)
        # Broadcast rows without a verified summary are unknown, never a partial or zero count.
        self.assertIsNone(displayed_reserved_inputs(
            {'reservation_count': 2, 'reservation_state_counts': (('broadcast', 2),)}))
        self.assertIsNone(displayed_reserved_inputs(
            {'reservation_count': 3, 'reservation_state_counts': (('broadcast', 1), ('uncertain', 2))}))
        # Older result shapes keep the previous raw count.
        self.assertEqual(displayed_reserved_inputs({'reservation_count': 2}), 2)
        self.assertIsNone(displayed_reserved_inputs({}))

    def test_projection_carries_counts_or_none(self):
        from wam_regtest.application.snapshot_projection import project_owned_spend_snapshot
        session = SimpleNamespace(payment_review=None, payment_signed=False, pending_confirm_txid=None,
                                  recovered_unsigned_cancel_available=lambda: False)
        item = SimpleNamespace(receive_code='r', height=1, tip='t', confirmed_atoms=0, history=(),
                               reservation_count=2, reservation_states=('broadcast',),
                               reservation_state_counts=(('broadcast', 2),))
        self.assertEqual(project_owned_spend_snapshot(item, session, profile='p', account_id='a',
                                                      available_atoms=0)['reservation_state_counts'],
                         (('broadcast', 2),))
        legacy = SimpleNamespace(**{k: v for k, v in vars(item).items() if k != 'reservation_state_counts'})
        self.assertIsNone(project_owned_spend_snapshot(legacy, session, profile='p', account_id='a',
                                                       available_atoms=0)['reservation_state_counts'])


class SessionCountsAreVerified(unittest.TestCase):
    """Codex PEER-053 nit 1: execute the cross-check, not just read its source."""

    def test_counts_must_agree_with_the_fingerprint(self):
        from wam_regtest.domain.payment_state import state_counts_match as ok
        self.assertTrue(ok((), 0, []))
        self.assertTrue(ok((('broadcast', 2), ('signed', 1)), 3, ['broadcast', 'signed']))
        self.assertFalse(ok((('broadcast', 2),), 3, ['broadcast']))              # total mismatch
        self.assertFalse(ok((('broadcast', 2),), 2, ['broadcast', 'signed']))   # states mismatch
        self.assertFalse(ok((('signed', 1), ('broadcast', 2)), 3, ['broadcast', 'signed']))  # order
        self.assertFalse(ok((('broadcast', 0),), 0, ['broadcast']))             # non-positive
        self.assertFalse(ok((('broadcast', True),), 1, ['broadcast']))          # bool is not int
        self.assertFalse(ok(((b'broadcast', 1),), 1, ['broadcast']))           # bytes state
        self.assertFalse(ok([('broadcast', 1)], 1, ['broadcast']))              # not a tuple
        self.assertFalse(ok((('broadcast', 1, 'x'),), 1, ['broadcast']))        # malformed entry
        self.assertFalse(ok((('broadcast', 1),), None, ['broadcast']))          # bad count type

    def test_snapshot_refuses_inconsistent_counts_through_the_real_query(self):
        """The real SQL on an in-memory reservations table, then the same check."""
        import sqlite3
        from wam_regtest.domain.payment_state import state_counts_match
        db = sqlite3.connect(':memory:')
        db.execute('CREATE TABLE reservations(txid TEXT, vout INT, token TEXT, state TEXT, created INT)')
        db.executemany('INSERT INTO reservations VALUES (?,?,?,?,?)',
                       [('a', 0, 't1', 'broadcast', 1), ('b', 1, 't1', 'broadcast', 1),
                        ('c', 0, 't2', 'signed', 2)])
        counts = tuple(sorted((r[0], r[1]) for r in db.execute(
            'SELECT state,count(*) FROM reservations GROUP BY state')))
        self.assertEqual(counts, (('broadcast', 2), ('signed', 1)))
        self.assertTrue(state_counts_match(counts, 3, ['broadcast', 'signed']))
        self.assertFalse(state_counts_match(counts, 2, ['broadcast', 'signed']))

    def test_wallet_session_uses_the_domain_check_and_the_same_query(self):
        from pathlib import Path
        text = (Path(__file__).resolve().parents[1] / 'src/wam_regtest/wallet_session.py').read_text()
        self.assertIn("SELECT state,count(*) FROM reservations GROUP BY state", text)
        self.assertIn("state_counts_match(state_counts,reservation_count,reservation_states)", text)


if __name__ == '__main__':
    unittest.main()
