"""PM-011: W-TX-03 — no 'reservations exist' warning for a confirmed payment's leftover rows.

Intentional, isolated behaviour change (owner P1-A defect). Only the status
warning changes; reservations, WSP rows and every authority check are untouched.
"""
import os
import unittest
from types import SimpleNamespace

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

WARNING = ('Anchored transaction reservations exist; check previous TXID '
           'against verified history. Never auto-rebroadcast or release locks.')


def _result(**overrides):
    from test_characterization_r0 import _snapshot_result
    return _snapshot_result(**overrides)


class ReservationWarning(unittest.TestCase):
    def setUp(self):
        from PySide6.QtWidgets import QApplication
        from wam_regtest.bip39_owner_gui import Bip39TrialWindow
        from wam_regtest.wallet_executor import ExecutorState
        self.app = QApplication.instance() or QApplication([])
        owner = SimpleNamespace(state=ExecutorState(locked=False, faulted=False, core_alive=True),
                                busy=False, closed=False)
        self.window = Bip39TrialWindow(owner)
        self.window._poll.stop()
        self.window._pending_confirm_txid = None
        self.window._recovered_unsigned_cancel = False

    def tearDown(self):
        self.window._poll.stop()
        self.window.deleteLater()
        self.app.processEvents()

    def _status(self, **overrides):
        self.window._on_ready('snapshot', _result(**overrides))
        return self.window.status.text()

    def test_confirmed_payment_leftover_broadcast_rows_do_not_warn(self):
        self.assertNotEqual(self._status(reservation_count=2, reservation_states=('broadcast',)), WARNING)

    def test_rows_needing_attention_still_warn(self):
        for states in (('draft',), ('signed',), ('uncertain',), ('broadcast', 'signed'),
                       ('broadcast', 'uncertain'), ('manual',)):
            with self.subTest(states=states):
                self.assertEqual(self._status(reservation_count=3, reservation_states=states), WARNING)

    def test_result_without_states_keeps_the_previous_count_rule(self):
        self.assertEqual(self._status(reservation_count=1), WARNING)

    def test_pending_txid_and_unsigned_cancel_messages_keep_priority(self):
        txid = 'ab' * 32
        self.window._pending_confirm_txid = txid
        text = self._status(reservation_count=1, reservation_states=('signed',),
                            pending_confirm_txid=txid)
        self.assertIn('awaiting its first REGTEST confirmation', text)


class ProjectionCarriesStates(unittest.TestCase):
    def test_public_snapshot_has_the_verified_state_set(self):
        from wam_regtest.application.snapshot_projection import project_owned_spend_snapshot
        item = SimpleNamespace(receive_code='r', height=1, tip='t', confirmed_atoms=0, history=(),
                               reservation_count=2, reservation_states=['broadcast', 'signed'])
        session = SimpleNamespace(payment_review=None, payment_signed=False, pending_confirm_txid=None,
                                  recovered_unsigned_cancel_available=lambda: False)
        result = project_owned_spend_snapshot(item, session, profile='p', account_id='a', available_atoms=0)
        self.assertEqual(result['reservation_states'], ('broadcast', 'signed'))
        self.assertIsInstance(result['reservation_states'], tuple)
        item.reservation_states = None
        unverified = project_owned_spend_snapshot(item, session, profile='p', account_id='a',
                                                  available_atoms=0)
        self.assertIsNone(unverified['reservation_states'])


if __name__ == '__main__':
    unittest.main()
