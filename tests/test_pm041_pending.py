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

    def test_pending_row_fits_wrapped_details_in_six_languages_and_widths(self):
        from itertools import product
        from unittest.mock import patch
        from PySide6.QtCore import QRect, Qt
        from PySide6.QtGui import QFontMetrics
        from PySide6.QtWidgets import QStyleOptionViewItem
        from wam_regtest import bip39_locale
        from wam_regtest.fusion_ui import FusionOverview, fusion_stylesheet
        from wam_regtest.presentation.strings import SUPPORTED_LANGUAGES
        for language, font_size in product(SUPPORTED_LANGUAGES, (14, 18)):
            with patch.object(bip39_locale, '_lang', return_value=language):
                page = FusionOverview()
                page.setStyleSheet(fusion_stylesheet('dark') +
                                  f'QTableWidget {{font-size:{font_size}px;}}')
                try:
                    snap = self.snapshot()
                    snap = replace(snap, pending_history=(replace(
                        snap.pending_history[0], fee_atoms=1234567890123,
                        pending_change_atoms=987654321098765),))
                    page.render_snapshot(snap, operational=True)
                    page.show()
                    # Resize the same page to exercise reflow in both directions.
                    for width in (900, 1100, 1440, 900):
                        with self.subTest(language=language, width=width, font_size=font_size):
                            page.resize(width, 900)
                            for _ in range(3):
                                self.app.processEvents()
                            table = page.activity_table
                            index = table.model().index(0, 2)
                            item = table.item(0, 2)
                            self.assertIn('\n', item.text())
                            option = QStyleOptionViewItem()
                            option.initFrom(table)
                            option.font = table.font()
                            table.itemDelegate().initStyleOption(option, index)
                            # Fusion item padding is 10px per edge; include the grid edge.
                            rect = table.visualRect(index)
                            required = QFontMetrics(option.font).boundingRect(
                                QRect(0, 0, rect.width() - 21, 10000),
                                Qt.TextFlag.TextWordWrap, item.text()).height() + 21
                            self.assertGreaterEqual(table.rowHeight(0), required)
                finally:
                    page.close()
                    page.deleteLater()

    def test_pending_row_wraps_instead_of_eliding_in_narrowest_locale_and_size(self):
        from unittest.mock import patch
        from PySide6.QtCore import QRect, Qt
        from PySide6.QtGui import QFontMetrics
        from PySide6.QtWidgets import QStyleOptionViewItem
        from wam_regtest import bip39_locale
        from wam_regtest.fusion_ui import FusionOverview, fusion_stylesheet
        with patch.object(bip39_locale, '_lang', return_value='id'):
            page = FusionOverview()
            page.setStyleSheet(fusion_stylesheet('dark') +
                              'QTableWidget {font-size:18px;}')
            try:
                snap = self.snapshot()
                snap = replace(snap, pending_history=(replace(
                    snap.pending_history[0], fee_atoms=1234567890123,
                    pending_change_atoms=987654321098765),))
                page.render_snapshot(snap, operational=True)
                page.resize(900, 900)
                page.show()
                for _ in range(3):
                    self.app.processEvents()
                table = page.activity_table
                index = table.model().index(0, 2)
                item = table.item(0, 2)
                lines = item.text().split('\n')
                self.assertEqual(len(lines), 2)
                option = QStyleOptionViewItem()
                option.initFrom(table)
                option.font = table.font()
                table.itemDelegate().initStyleOption(option, index)
                # The delegate must ask the style to wrap: without the WrapText
                # feature the long pending fee/change line is elided, not
                # wrapped (PM-041 review nit).
                self.assertTrue(option.features & QStyleOptionViewItem.ViewItemFeature.WrapText)
                rect = table.visualRect(index)
                metrics = QFontMetrics(option.font)
                # The second line is wider than the cell, so a non-wrapping
                # delegate would elide it instead of showing it in full.
                self.assertGreater(metrics.horizontalAdvance(lines[1]), rect.width() - 21)
                # Wrapped, the same text fits the cell horizontally and the
                # row is tall enough to show every wrapped line.
                wrapped = metrics.boundingRect(QRect(0, 0, rect.width() - 21, 10000),
                                               Qt.TextFlag.TextWordWrap, item.text())
                self.assertLessEqual(wrapped.width(), rect.width() - 21)
                self.assertGreaterEqual(table.rowHeight(0), wrapped.height() + 21)
            finally:
                page.close()
                page.deleteLater()

    def test_unverified_fields_have_no_amount_unit_in_each_language(self):
        from unittest.mock import patch
        from wam_regtest import bip39_locale
        from wam_regtest.fusion_ui import FusionOverview
        from wam_regtest.fusion_pages import HistoryPage
        from wam_regtest.presentation.strings import CATALOG
        for language, catalog in CATALOG.items():
            with self.subTest(language=language), patch.object(bip39_locale, '_lang', return_value=language):
                overview, history = FusionOverview(), HistoryPage()
                try:
                    snap = self.snapshot()
                    snap = replace(snap, available_atoms=None, pending_atoms=None,
                                   pending_spent_atoms=None, pending_history=(replace(
                                       snap.pending_history[0], fee_atoms=None,
                                       pending_change_atoms=None),))
                    overview.render_snapshot(snap, operational=True)
                    funds = overview.fund_details.text()
                    # SPEC-UX0102 §3.1.4 / §4.2.5: no lock summary appends
                    # fusion.locks_count_unknown as its own segment. The three
                    # amount segments stay one unitless pending.unknown.
                    unknown = catalog['pending.unknown']
                    parts = [part.strip() for part in funds.split('  ·  ')]
                    self.assertEqual(len(parts), 4)
                    self.assertEqual(parts[-1], catalog['fusion.locks_count_unknown'])
                    for part in parts[:3]:
                        self.assertEqual(part.count(unknown), 1)
                        self.assertNotIn('WAM', part)
                    self.assertNotIn('WAM', funds)
                    self.assertNotIn(unknown + ' WAM', funds)
                    status = overview.activity_table.item(0, 2).text()
                    history.render_snapshot(snap)
                    history.table.selectRow(0)
                    details = history.detail_values.text().split('\n')[1]
                    for text in (status, details):
                        self.assertEqual(text.count(catalog['pending.unknown']), 2)
                        self.assertNotIn('WAM', text)
                    # Verify mixed known/unknown fee and change independently.
                    for fee, change in ((None, 6900), (100, None)):
                        mixed = replace(snap, pending_history=(replace(
                            snap.pending_history[0], fee_atoms=fee,
                            pending_change_atoms=change),))
                        overview.render_snapshot(mixed, operational=True)
                        history.render_snapshot(mixed)
                        history.table.selectRow(0)
                        for text in (overview.activity_table.item(0, 2).text(),
                                     history.detail_values.text().split('\n')[1]):
                            self.assertNotIn(catalog['pending.unknown'] + ' WAM', text)
                            self.assertEqual(text.count('WAM'), 1)
                            self.assertIn('0.00006900' if fee is None else '0.00000100', text)
                finally:
                    overview.deleteLater()
                    history.deleteLater()

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
