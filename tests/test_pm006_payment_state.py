"""PM-006 domain payment-state model. Pure names, the two historical writes, no WSP."""
import ast
import sqlite3
import unittest
from pathlib import Path

from wam_regtest.domain.payment_state import (
    BROADCAST, DRAFT, EVIDENCE_STAGES, LEGAL_TRANSITIONS, RESERVATION_STATES,
    SIGNED, UNCERTAIN, ATTENTION_STATES, mark_reservations_uncertain_before_submission,
    reservations_need_attention,
)

ROOT = Path(__file__).resolve().parents[1]


def _table():
    db = sqlite3.connect(':memory:', isolation_level=None)
    db.execute(
        'CREATE TABLE reservations(txid TEXT, vout INT, token TEXT, state TEXT, created INT)')
    db.executemany(
        'INSERT INTO reservations VALUES (?,?,?,?,?)',
        (('aa', 0, 'tok', 'signed', 1), ('bb', 1, 'tok', 'draft', 1),
         ('cc', 0, 'other', 'signed', 1)))
    return db


def _states(db, token):
    return tuple(row[0] for row in db.execute(
        'SELECT state FROM reservations WHERE token=? ORDER BY txid', (token,)))


class PaymentStateModel(unittest.TestCase):
    def test_names_are_the_wsp_strings_and_there_is_no_confirmed_reservation(self):
        self.assertEqual(
            (DRAFT, SIGNED, UNCERTAIN, BROADCAST),
            ('draft', 'signed', 'uncertain', 'broadcast'))
        self.assertEqual(RESERVATION_STATES, frozenset(('draft', 'signed', 'uncertain', 'broadcast')))
        self.assertEqual(EVIDENCE_STAGES, frozenset(('signed', 'uncertain', 'broadcast')))
        self.assertNotIn('confirmed', RESERVATION_STATES)
        self.assertNotIn('draft', EVIDENCE_STAGES)
        self.assertEqual(LEGAL_TRANSITIONS, frozenset((
            ('draft', 'signed'),
            ('draft', None),
            ('signed', 'uncertain'),
            ('uncertain', 'broadcast'),
        )))
        self.assertNotIn(('broadcast', 'confirmed'), LEGAL_TRANSITIONS)

    def test_fresh_broadcast_marks_every_row_of_the_token_and_opens_no_transaction(self):
        db = _table()
        self.assertFalse(db.in_transaction)
        mark_reservations_uncertain_before_submission(db, 'tok', signed_rows_only=False)
        self.assertFalse(db.in_transaction)
        self.assertEqual(_states(db, 'tok'), ('uncertain', 'uncertain'))
        self.assertEqual(_states(db, 'other'), ('signed',))

    def test_resume_marks_only_rows_still_signed(self):
        db = _table()
        db.execute('BEGIN')
        mark_reservations_uncertain_before_submission(db, 'tok', signed_rows_only=True)
        self.assertTrue(db.in_transaction)
        self.assertEqual(_states(db, 'tok'), ('uncertain', 'draft'))
        db.execute('ROLLBACK')
        self.assertEqual(_states(db, 'tok'), ('signed', 'draft'))

    def test_sqlite_errors_propagate(self):
        db = sqlite3.connect(':memory:', isolation_level=None)
        with self.assertRaises(sqlite3.OperationalError):
            mark_reservations_uncertain_before_submission(db, 'tok', signed_rows_only=False)

    def test_attention_states_exclude_only_broadcast(self):
        """PM-011 / W-TX-03 (replaces PM-006's unused classify_payment, D-PM006-1)."""
        self.assertEqual(ATTENTION_STATES, {DRAFT, SIGNED, UNCERTAIN})
        self.assertFalse(reservations_need_attention(()))
        self.assertFalse(reservations_need_attention((BROADCAST,)))
        for state in (DRAFT, SIGNED, UNCERTAIN):
            self.assertTrue(reservations_need_attention((state,)))
            self.assertTrue(reservations_need_attention((BROADCAST, state)))
        # Fail safe: a state this wallet does not know about still warns.
        self.assertTrue(reservations_need_attention(('manual',)))
        self.assertTrue(reservations_need_attention(('unexpected',)))

    def test_call_sites_keep_their_historical_predicates(self):
        wallet = ast.parse((ROOT / 'src/wam_regtest/wallet_session.py').read_text())
        spend = ast.parse((ROOT / 'src/wam_regtest/bip39_spend_session.py').read_text())

        def flags(tree, function):
            found = []
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == function:
                    for child in ast.walk(node):
                        if not isinstance(child, ast.Call):
                            continue
                        func = child.func
                        name = func.id if isinstance(func, ast.Name) else None
                        if name != 'mark_reservations_uncertain_before_submission':
                            continue
                        for keyword in child.keywords:
                            if keyword.arg == 'signed_rows_only':
                                found.append(keyword.value.value)
            return found

        self.assertEqual(flags(wallet, 'broadcast'), [False])
        self.assertEqual(flags(spend, 'resume_signed_intent'), [True])


if __name__ == '__main__':
    unittest.main()
