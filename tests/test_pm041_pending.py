"""W-TX-04: read-only pending activity from existing WSP tables/evidence."""
from dataclasses import replace
import sqlite3
from types import SimpleNamespace
import unittest

from wam_regtest.wallet_read import HistoryRow, WalletReadSnapshot
from wam_regtest.history_pages import pending_activity
from wam_sp.psbt import PSBT, Tx

TXID = 'a' * 64
INPUT = ('b' * 64, 0)


class PendingActivity(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.executescript('''
            CREATE TABLE history(txid TEXT,height INTEGER,credit INTEGER,debit INTEGER);
            CREATE TABLE reservations(txid TEXT,vout INTEGER,token TEXT,state TEXT);
            CREATE TABLE mempool_coins(txid TEXT,vout INTEGER,atoms INTEGER);
            CREATE TABLE mempool_spends(txid TEXT,vout INTEGER,spending TEXT);
        ''')
        self.scanner = SimpleNamespace(store=SimpleNamespace(db=self.db), mempool_ready=True)
        self.balance = dict(unconfirmed_atoms=6900, pending_spent_atoms=10000)
        self.psbt = PSBT(Tx((INPUT,), ((3000, b'\x51'), (6900, b'\x52'))), ((10000, b'\x51'),))
        self.txid = self.psbt.txid()
        self.body = dict(txid=self.txid, atoms=3000, fee=100, signed_psbt=self.psbt.encode().hex())
        self.db.execute('INSERT INTO reservations VALUES(?,?,?,?)', (*INPUT, 'c'*32, 'broadcast'))
        self.db.execute('INSERT INTO mempool_spends VALUES(?,?,?)', (*INPUT, self.txid))
        self.db.execute('INSERT INTO mempool_coins VALUES(?,?,?)', (self.txid, 1, 6900))

    def read(self):
        return pending_activity(self.scanner, self.balance, lambda token, stage: self.body)

    def test_outgoing_exact_amount_fee_and_change(self):
        pending, spent, rows = self.read()
        self.assertEqual((pending, spent), (6900, 10000))
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row.txid, row.debit_atoms, row.credit_atoms, row.fee_atoms,
                          row.pending_change_atoms, row.state),
                         (self.txid, 3100, 0, 100, 6900, 'pending'))

    def test_incoming_unspent_only_and_no_duplicate_change(self):
        self.db.execute('INSERT INTO mempool_coins VALUES(?,?,?)', (TXID, 0, 200))
        self.db.execute('INSERT INTO mempool_coins VALUES(?,?,?)', (TXID, 1, 400))
        self.db.execute('INSERT INTO mempool_spends VALUES(?,?,?)', (TXID, 1, 'd'*64))
        rows = self.read()[2]
        self.assertEqual([(r.txid, r.credit_atoms) for r in rows], [(self.txid, 0), (TXID, 200)])

    def test_confirmation_removes_pending_even_outside_history_window(self):
        self.db.execute('INSERT INTO history VALUES(?,?,?,?)', (self.txid, 12, 6900, 10000))
        self.assertEqual(self.read()[2], ())

    def test_not_ready_is_unknown_ignores_stale_tables(self):
        self.scanner.mempool_ready = False
        pending, spent, rows = self.read()
        self.assertIsNone(pending)
        self.assertIsNone(spent)
        self.assertEqual(rows[0].state, 'pending')
        self.assertIsNone(rows[0].pending_change_atoms)

    def test_dropped_or_conflicted_never_becomes_confirmed(self):
        self.db.execute('DELETE FROM mempool_coins')
        self.db.execute('DELETE FROM mempool_spends')
        self.assertEqual(self.read()[2], ())
        self.db.execute('INSERT INTO mempool_spends VALUES(?,?,?)', (*INPUT, 'd'*64))
        self.assertEqual(self.read()[2], ())

    def test_restart_uses_persisted_evidence_without_session_review(self):
        before = self.read()
        self.scanner = SimpleNamespace(store=SimpleNamespace(db=self.db), mempool_ready=True)
        self.assertEqual(before, self.read())

    def test_pending_window_bounded(self):
        for n in range(300):
            self.db.execute('INSERT INTO mempool_coins VALUES(?,?,?)', (f'{n:064x}', 0, 1))
        self.assertLessEqual(len(self.read()[2]), 250)

    def test_invalid_evidence_cannot_fabricate_debit(self):
        self.body['fee'] = 999
        self.assertTrue(all(r.debit_atoms == 0 for r in self.read()[2]))

class PendingWidgets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def snapshot(self):
        from wam_regtest.wallet_read import PendingHistoryRow
        return WalletReadSnapshot('regtest', 12, 'e'*64, '', 10000, 1,
            (HistoryRow('f'*64, 12, 1, 10000, 0),), '0'*64,
            history_count=251, history_complete=False,
            pending_atoms=6900, pending_spent_atoms=10000, available_atoms=0,
            pending_history=(PendingHistoryRow(TXID, 0, 0, 0, 3100,
                fee_atoms=100, pending_change_atoms=6900),))

    def test_history_pending_first_exact_details_confirm_transition_and_paging(self):
        from wam_regtest.fusion_pages import HistoryPage
        page = HistoryPage()
        self.addCleanup(page.deleteLater)
        snap = self.snapshot()
        page.render_snapshot(snap)
        self.assertEqual(page.rows[0].txid, TXID)
        self.assertIn('Pending', page.table.item(0, 0).text())
        page.table.selectRow(0)
        self.assertIn('0.00000100', page.detail_values.text())
        self.assertIn('0.00006900', page.detail_values.text())
        self.assertIn('1–1', page.scope.text())
        page.render_snapshot(replace(snap, history_count=None))
        self.assertFalse(page.older.isEnabled())
        rows = (HistoryRow(TXID, 12, 1, 6900, 10000),) + snap.history
        page.render_snapshot(replace(snap, pending_history=(), history=rows))
        self.assertEqual(sum(r.txid == TXID for r in page.rows), 1)
        self.assertNotIn('Pending', page.table.item(0, 0).text())

    def test_overview_pending_first_balances_distinct_and_unknown(self):
        from wam_regtest.fusion_ui import FusionOverview
        page = FusionOverview()
        self.addCleanup(page.deleteLater)
        page.render_snapshot(self.snapshot(), operational=True)
        self.assertEqual(page._txids[0], TXID)
        self.assertIn('Pending', page.activity_table.item(0, 2).text())
        text = page.fund_details.text()
        self.assertIn('0.00006900', text)
        self.assertIn('Spendable (confirmed): 0.00000000', text)
        page.render_snapshot(replace(self.snapshot(), pending_atoms=None, pending_spent_atoms=None), operational=True)
        self.assertIn('unknown', page.fund_details.text())

    def test_six_locale_keys_and_review_queue(self):
        import json
        from pathlib import Path
        from wam_regtest.presentation.strings import CATALOG
        english = {k for k in CATALOG['en'] if k.startswith('pending.')}
        self.assertTrue(english)
        for catalog in CATALOG.values():
            self.assertEqual(english, {k for k in catalog if k.startswith('pending.')})
        queue = json.loads((Path(__file__).parent/'l10n_security_review_keys.json').read_text())
        self.assertTrue(english <= {r['key'] for r in queue['keys']})

class NativeRowShape(PendingActivity):
    def setUp(self):
        super().setUp()
        self.db.row_factory = sqlite3.Row

class PersistedPending(unittest.TestCase):
    setUp = PendingActivity.setUp
    read = PendingActivity.read

    def test_actual_evidence_and_sqlite_reopen(self):
        import tempfile
        from pathlib import Path
        from wam_regtest.domain.payment_evidence import PaymentEvidenceStore
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            store = PaymentEvidenceStore(root)
            password = b'public disposable PM041 test password'
            binding = lambda: 'public-test-owner-binding'
            account = lambda: 'public-test-account'
            store.write('broadcast', signed=self.psbt.encode(),
                        review=SimpleNamespace(commitment='e'*64, code='public-test-recipient',
                                               atoms=3000, fee=100),
                        token='c'*32, txid=self.txid, owner_binding=binding,
                        account_id=account, password=password)
            path = root/'test.sqlite'
            disk = sqlite3.connect(path)
            self.db.commit()
            self.db.backup(disk)
            disk.close()
            reopened = sqlite3.connect(path)
            self.addCleanup(reopened.close)
            reopened.row_factory = sqlite3.Row
            scanner = SimpleNamespace(store=SimpleNamespace(db=reopened), mempool_ready=True)
            reader = lambda token, stage: store.read(token, stage, owner_binding=binding,
                                                      account_id=account, password=password)
            result = pending_activity(scanner, self.balance, reader)
            self.assertEqual(result, self.read())

    def test_backend_enriches_same_fusion_snapshot(self):
        from contextlib import nullcontext
        from threading import RLock
        from pathlib import Path
        from unittest.mock import patch
        from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend
        snapshot = WalletReadSnapshot('regtest', 12, 'e'*64, '', 10000, 1, (), 'f'*64)
        self.scanner.store.transaction = nullcontext
        session = SimpleNamespace(_lock=RLock(), scanner=self.scanner,
            snapshot=lambda: snapshot, _read_payment_evidence=lambda token, stage: self.body,
            payment_review=None, payment_signed=False, pending_confirm_txid=None,
            recovered_unsigned_cancel_available=lambda: False)
        backend = Bip39ReadOnlyBackend(Path('/unused'), Path('/unused'), Path('/unused'))
        backend._spend_session = session
        backend._public = dict(profile='test', account_id='test')
        with patch('wam_sp.wallet.Wallet') as wallet:
            wallet.return_value._balance.return_value = dict(self.balance, available_atoms=0)
            result = backend._session_snapshot()
        self.assertEqual(result['fusion_snapshot'].pending_history, self.read()[2])
        self.assertEqual(result['pending_atoms'], 6900)
        self.assertEqual(result['fusion_snapshot'].available_atoms, 0)


if __name__ == '__main__':
    unittest.main()
