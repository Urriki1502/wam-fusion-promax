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
        self.assertEqual(displayed_reserved_inputs(
            {'reservation_count': 2, 'reservation_state_counts': (('broadcast', 2),)}), 0)
        self.assertEqual(displayed_reserved_inputs(
            {'reservation_count': 3, 'reservation_state_counts': (('broadcast', 1), ('uncertain', 2))}), 2)
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
    def test_snapshot_query_cross_checks_counts_against_the_fingerprint(self):
        from pathlib import Path
        text = (Path(__file__).resolve().parents[1] / 'src/wam_regtest/wallet_session.py').read_text()
        self.assertIn("SELECT state,count(*) FROM reservations GROUP BY state", text)
        self.assertIn("sum(n for _,n in state_counts)!=reservation_count", text)
        self.assertIn("tuple(s for s,_ in state_counts)!=tuple(reservation_states)", text)


if __name__ == '__main__':
    unittest.main()
