"""PM-006 domain payment-state model. Pure names, the two historical writes, no WSP."""
import ast
import sqlite3
import unittest
from pathlib import Path

from wam_regtest.domain.payment_state import (
    BROADCAST, DRAFT, EVIDENCE_STAGES, LEGAL_TRANSITIONS, RESERVATION_STATES,
    SIGNED, UNCERTAIN, classify_payment, mark_reservations_uncertain_before_submission,
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

    def test_classify_follows_the_reservation_and_the_latch_only(self):
        evidence = ('signed', 'uncertain', 'broadcast')
        pending = 'ab' * 32
        self.assertEqual(classify_payment(('draft',), (), None, False), 'draft')
        self.assertEqual(classify_payment(('signed',), ('signed',), None, False), 'signed')
        self.assertEqual(classify_payment(('uncertain',), evidence, None, False), 'uncertain')
        self.assertEqual(classify_payment(('broadcast',), evidence, pending, False), 'broadcast')
        # Confirm clears the pending txid and leaves the row broadcast. Not 'confirmed'.
        self.assertEqual(classify_payment(('broadcast',), evidence, None, False), 'broadcast')
        # Confirm ambiguity sets the latch and does not rename the row in the store,
        # but the session is uncertain. The latch outranks the row.
        self.assertEqual(classify_payment(('broadcast',), evidence, pending, True), 'uncertain')
        self.assertEqual(classify_payment(('signed', 'uncertain'), ('signed',), None, False), 'mixed')
        self.assertIsNone(classify_payment((), (), None, False))
        # Evidence and a pending txid do not override a signed reservation.
        self.assertEqual(classify_payment(('signed',), evidence, pending, False), 'signed')
        self.assertEqual(classify_payment(('signed',), (), None, False), 'signed')

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
