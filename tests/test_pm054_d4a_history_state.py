"""D4-A: synthetic display/accounting characterization, no Core or custody.

PM-062 fixes the three D4A presentation defects and preserves valid selection
across ordinary refreshes; historical PM-054 failure evidence remains retained.
"""
from dataclasses import replace
import unittest
from unittest.mock import patch

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from wam_regtest import bip39_locale
from wam_regtest.fusion_pages import HistoryPage
from wam_regtest.fusion_ui import FusionOverview, pending_amount_text, ui_text
from wam_regtest.presentation.strings import SUPPORTED_LANGUAGES
from wam_regtest.wallet_read import HistoryRow, PendingHistoryRow, WalletReadSnapshot

INCOMING = HistoryRow('ab' * 32, 112, 1, 5000, 0)
OUTGOING = HistoryRow('cd' * 32, 108, 5, 6900, 10000)
ZERO = HistoryRow('ef' * 32, 107, 6, 10000, 10000)
PENDING = PendingHistoryRow('12' * 32, 0, 0, 0, 3100,
                            fee_atoms=100, pending_change_atoms=None)


def snapshot(**changes):
    base = WalletReadSnapshot('regtest', 112, '34' * 32, '', 5000, 1,
                              (INCOMING, OUTGOING, ZERO), '56' * 32,
                              pending_history=(PENDING,))
    return replace(base, **changes)


class HistoryState(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def page(self, snap=None):
        page = HistoryPage()
        self.addCleanup(page.deleteLater)
        page.resize(900, 630)
        page.show()
        page.render_snapshot(snap)
        self.settle()
        return page

    def settle(self):
        for _ in range(5):
            self.app.processEvents()

    def test_four_compulsory_columns_visible_at_900_in_all_six_locales(self):
        self.assertEqual(set(SUPPORTED_LANGUAGES), {'en', 'zh-Hans', 'vi', 'ko', 'id', 'ja'})
        for language in SUPPORTED_LANGUAGES:
            with self.subTest(language=language), patch.object(bip39_locale, '_lang', return_value=language):
                page = self.page(snapshot())
                self.assertEqual(page.width(), 900)
                for column in (0, 1, 4, 5):
                    self.assertFalse(page.table.isColumnHidden(column), (language, column))
                page.hide()

    def test_row_mapping_raw_columns_and_integer_net_no_double_fee(self):
        page = self.page(snapshot())
        overview = FusionOverview()
        self.addCleanup(overview.deleteLater)
        overview.render_snapshot(snapshot())
        cases = ((PENDING, -3100, 'pages.sent', '-0.00003100 WAM'),
                 (INCOMING, 5000, 'pages.received', '+0.00005000 WAM'),
                 (OUTGOING, -3100, 'pages.sent', '-0.00003100 WAM'),
                 (ZERO, 0, 'pages.activity', '0.00000000 WAM'))
        self.assertEqual(page.rows, (PENDING, INCOMING, OUTGOING, ZERO))
        for index, (row, net, direction, amount) in enumerate(cases):
            with self.subTest(txid=row.txid):
                self.assertIs(type(net), int)
                self.assertEqual(row.credit_atoms - row.debit_atoms, net)
                self.assertTrue(page.table.item(index, 0).text().startswith(ui_text(direction)))
                self.assertEqual(overview.activity_table.item(index, 0).data(Qt.ItemDataRole.UserRole), net)
                self.assertEqual(overview.activity_table.item(index, 1).text(), amount)
                self.assertEqual(page.table.item(index, 1).data(Qt.ItemDataRole.UserRole), row.txid)
        self.assertEqual(page.table.item(0, 4).text(), '0.00000000')
        self.assertEqual(page.table.item(0, 5).text(), '0.00003100')
        self.assertEqual(page.table.item(2, 4).text(), '0.00006900')
        self.assertEqual(page.table.item(2, 5).text(), '0.00010000')
        self.assertEqual(page.table.item(0, 2).text(), '—')
        self.assertEqual(page.table.item(0, 3).text(), ui_text('pending.state'))
        self.assertEqual(page.table.item(2, 3).text(), '5')
        # Fee already belongs to the 3100 debit; subtracting it again yields 3200.
        self.assertNotEqual(overview.activity_table.item(0, 1).text(), '-0.00003200 WAM')
        page.select_txid(PENDING.txid)
        self.assertIn('0.00000100 WAM', page.detail_values.text())
        self.assertIn(ui_text('pending.unknown'), page.detail_values.text())
        page.select_txid(OUTGOING.txid)
        self.assertEqual(page.detail_values.text(), ui_text('pages.block_amounts').format(
            height=108, confirmations=5, credit='0.00006900', debit='0.00010000'))

    def test_unknown_is_unitless_and_known_zero_numeric_in_six_locales(self):
        for language in SUPPORTED_LANGUAGES:
            with self.subTest(language=language), patch.object(bip39_locale, '_lang', return_value=language):
                for unknown in (None, -1, True, '0', 0.0):
                    self.assertEqual(pending_amount_text(unknown), ui_text('pending.unknown'))
                    self.assertNotIn('WAM', pending_amount_text(unknown))
                self.assertEqual(pending_amount_text(0), '0.00000000 WAM')
                page = self.page(snapshot(pending_history=(replace(PENDING, fee_atoms=None),)))
                page.select_txid(PENDING.txid)
                text = page.detail_values.text()
                self.assertEqual(text.count(ui_text('pending.unknown')), 2)
                self.assertNotIn(ui_text('pending.unknown') + ' WAM', text)
                page.hide()

    def test_copy_is_exact_full_txid_for_pending_and_confirmed(self):
        page = self.page(snapshot())
        for row in page.rows:
            with self.subTest(txid=row.txid):
                self.app.clipboard().setText('sentinel')
                page.select_txid(row.txid)
                page.copy_button.click()
                self.assertEqual(self.app.clipboard().text(), row.txid)
                self.assertEqual(len(self.app.clipboard().text().encode('ascii')), 64)
                self.assertEqual(page.detail_id.text(), row.txid)

    def test_search_filters_only_loaded_rows_and_credit_includes_change(self):
        page = self.page(snapshot(history_count=800, history_complete=False))
        requests = []
        page.page_requested.connect(requests.append)
        page.filter.setCurrentIndex(1)
        self.assertFalse(page.table.isRowHidden(2))  # outgoing change is credit
        page.filter.setCurrentIndex(2)
        self.assertFalse(page.table.isRowHidden(2))  # same row also has debit
        page.filter.setCurrentIndex(0)
        page.search.setText('108')
        self.assertEqual([r.txid for i, r in enumerate(page.rows)
                          if not page.table.isRowHidden(i)], [OUTGOING.txid])
        page.search.setText(PENDING.txid.upper())
        self.assertFalse(page.table.isRowHidden(0))
        page.search.setText('99' * 32)  # not loaded, no lookup/page scan
        self.assertTrue(all(page.table.isRowHidden(i) for i in range(4)))
        self.assertEqual(requests, [])

    def test_pending_rows_do_not_change_confirmed_offsets_or_scope(self):
        for offset in (0, 250, 500):
            scopes = []
            for pending in ((), (PENDING,)):
                with self.subTest(offset=offset, pending=len(pending)):
                    page = self.page(snapshot(history_offset=offset, history_count=503,
                                              history_complete=False, pending_history=pending))
                    requests = []
                    page.page_requested.connect(requests.append)
                    page.newer.click()
                    page.older.click()
                    self.assertEqual(requests, ([max(0, offset - 250)] if offset else [])
                                     + ([offset + 250] if offset < 500 else []))
                    self.assertEqual(page._total, 503)
                    scopes.append(page.scope.text())
                    page.hide()
            self.assertEqual(scopes[0], scopes[1])

    def test_hidden_selection_disables_copy_and_arrows_update_detail(self):
        page = self.page(snapshot())
        page.select_txid(INCOMING.txid)
        page.table.setFocus()
        QTest.keyClick(page.table, Qt.Key.Key_Down)
        self.settle()
        self.assertEqual(page.detail_id.text(), OUTGOING.txid)
        page.search.setText(INCOMING.txid)
        self.assertFalse(page.copy_button.isEnabled())
        self.assertEqual(page.detail_values.text(), '')
        self.app.clipboard().setText('sentinel')
        page.copy_txid()
        self.assertEqual(self.app.clipboard().text(), 'sentinel')

    def test_verified_empty_and_unavailable_clear_selection(self):
        page = self.page(snapshot())
        for snap, key in ((None, 'history.unavailable'),
                          (snapshot(history=(), pending_history=()), 'history.empty_verified')):
            page.render_snapshot(snap)
            self.assertEqual(page.rows, ())
            self.assertEqual(page.empty.text(), ui_text(key))
            self.assertFalse(page.copy_button.isEnabled())
            self.assertEqual(page.detail_values.text(), '')
            self.assertFalse(page.older.isEnabled())
            self.assertFalse(page.newer.isEnabled())
        self.assertIn(ui_text('pending.unverified'), page.scope.text())
        page.render_snapshot(snapshot(history=(), pending_history=(), pending_atoms=0))
        self.assertNotIn(ui_text('pending.unverified'), page.scope.text())

    def test_same_snapshot_refresh_3x_preserves_selection_detail_and_copy(self):
        page = self.page(snapshot())
        page.select_txid(INCOMING.txid)
        expected_detail = page.detail_values.text()
        self.assertEqual(page.table.currentRow(), 1)
        self.assertTrue(page.copy_button.isEnabled())
        for _ in range(3):
            page.render_snapshot(snapshot())
            self.settle()
            self.assertEqual(page.table.currentRow(), 1)
            self.assertTrue(page.table.selectionModel().hasSelection())
            self.assertEqual(page.detail_id.text(), INCOMING.txid)
            self.assertEqual(page.detail_values.text(), expected_detail)
            self.assertTrue(page.copy_button.isEnabled())
        self.app.clipboard().setText('sentinel')
        page.copy_button.click()
        self.assertEqual(self.app.clipboard().text(), INCOMING.txid)

    def test_reordered_or_confirmed_refresh_preserves_selection_by_exact_txid(self):
        page = self.page(snapshot())
        page.select_txid(INCOMING.txid)
        self.assertEqual(page.table.currentRow(), 1)
        # Pending row disappears -> INCOMING shifts from row 1 to row 0.
        page.render_snapshot(snapshot(pending_history=()))
        self.settle()
        self.assertEqual(page.table.currentRow(), 0)
        self.assertEqual(page.detail_id.text(), INCOMING.txid)
        self.assertTrue(page.copy_button.isEnabled())
        # Pending TXID confirms with same TXID -> stays selected and updates detail.
        page.render_snapshot(snapshot())
        page.select_txid(PENDING.txid)
        self.assertEqual(page.table.currentRow(), 0)
        confirmed = HistoryRow(PENDING.txid, 113, 1, 0, 3100)
        page.render_snapshot(snapshot(history=(confirmed, INCOMING, OUTGOING, ZERO), pending_history=()))
        self.settle()
        self.assertEqual(page.table.currentRow(), 0)
        self.assertEqual(page.detail_id.text(), PENDING.txid)
        self.assertIn('113', page.detail_values.text())
        self.assertTrue(page.copy_button.isEnabled())

    def test_disappearing_selected_txid_clears_selection_detail_and_copy(self):
        page = self.page(snapshot())
        page.select_txid(INCOMING.txid)
        self.assertTrue(page.copy_button.isEnabled())
        page.render_snapshot(snapshot(history=(OUTGOING, ZERO), pending_history=()))
        self.settle()
        self.assertEqual(page.table.currentRow(), -1)
        self.assertFalse(page.table.selectedItems())
        self.assertEqual(page.detail_id.text(), ui_text('pages.no_transaction_selected'))
        self.assertEqual(page.detail_values.text(), '')
        self.assertFalse(page.copy_button.isEnabled())
        self.app.clipboard().setText('sentinel')
        page.copy_txid()
        self.assertEqual(self.app.clipboard().text(), 'sentinel')

    def test_lock_clear_clears_selection_detail_and_copy(self):
        page = self.page(snapshot())
        page.select_txid(INCOMING.txid)
        self.assertTrue(page.copy_button.isEnabled())
        page.render_snapshot(None)
        self.settle()
        self.assertEqual(page.rows, ())
        self.assertEqual(page.table.currentRow(), -1)
        self.assertFalse(page.table.selectedItems())
        self.assertEqual(page.detail_id.text(), ui_text('pages.no_transaction_selected'))
        self.assertEqual(page.detail_values.text(), '')
        self.assertFalse(page.copy_button.isEnabled())
        self.assertEqual(page.empty.text(), ui_text('history.unavailable'))
        self.app.clipboard().setText('sentinel')
        page.copy_txid()
        self.assertEqual(self.app.clipboard().text(), 'sentinel')

    def test_empty_refresh_3x_stays_empty_not_unavailable(self):
        page = self.page(snapshot(history=(), pending_history=()))
        for _ in range(3):
            page.render_snapshot(snapshot(history=(), pending_history=()))
            self.settle()
            self.assertEqual(page.empty.text(), ui_text('history.empty_verified'))
            self.assertNotEqual(page.empty.text(), ui_text('history.unavailable'))
            self.assertTrue(page.empty.isVisible())
            self.assertFalse(page.copy_button.isEnabled())

    def test_filter_hiding_clears_detail_and_does_not_restore_stale_selection(self):
        page = self.page(snapshot())
        page.select_txid(INCOMING.txid)
        page.filter.setCurrentIndex(2)  # Has debits: hides INCOMING
        self.assertFalse(page.copy_button.isEnabled())
        self.assertEqual(page.detail_values.text(), '')
        self.assertEqual(page.detail_id.text(), ui_text('pages.no_transaction_selected'))
        self.assertEqual(page.table.currentRow(), -1)
        page.filter.setCurrentIndex(0)  # All activity: stays cleared
        self.assertFalse(page.copy_button.isEnabled())
        self.assertEqual(page.detail_values.text(), '')
        self.assertEqual(page.table.currentRow(), -1)
        self.app.clipboard().setText('sentinel')
        page.copy_txid()
        self.assertEqual(self.app.clipboard().text(), 'sentinel')

    def test_scoped_state_copy_in_all_six_locales(self):
        for language in SUPPORTED_LANGUAGES:
            with self.subTest(language=language), patch.object(bip39_locale, '_lang', return_value=language):
                page = self.page(snapshot())
                page.select_txid(INCOMING.txid)
                page.select_txid('99' * 32)
                self.assertEqual(page.detail_id.text(), ui_text('history.txid_not_displayed'))
                self.assertFalse(page.copy_button.isEnabled())
                page.search.setText('no-match')
                self.assertEqual(page.empty.text(), ui_text('history.no_matching_activity'))
                page.render_snapshot(snapshot(history=(), pending_history=()))
                self.assertEqual(page.empty.text(), ui_text('history.empty_verified'))
                self.assertIn(ui_text('pending.unverified'), page.scope.text())
                page.render_snapshot(None)
                self.assertEqual(page.empty.text(), ui_text('history.unavailable'))
                self.assertEqual(page.scope.text(), '')
                page.hide()

    def test_D4A_1_absent_txid_clears_previous_detail_and_copy(self):
        """DEFECT D4A-1: select_txid misses leave stale verified selection."""
        page = self.page(snapshot())
        page.select_txid(INCOMING.txid)
        page.select_txid('99' * 32)
        self.assertFalse(page.copy_button.isEnabled(), 'D4A-1')
        self.assertEqual(page.detail_values.text(), '')
        self.assertEqual(page.detail_id.text(), ui_text('history.txid_not_displayed'))
        self.assertEqual(page.table.currentRow(), -1)
        self.assertFalse(page.table.selectedItems())
        self.app.clipboard().setText('sentinel')
        page.copy_txid()
        page.apply_filter()
        self.assertFalse(page.copy_button.isEnabled())
        self.assertEqual(self.app.clipboard().text(), 'sentinel')
        page.select_txid(PENDING.txid)
        self.assertTrue(page.copy_button.isEnabled())

    def test_D4A_2_no_match_copy_does_not_claim_confirmed_only(self):
        """DEFECT D4A-2: pending-inclusive display has confirmed-only no-match copy."""
        with patch.object(bip39_locale, '_lang', return_value='en'):
            page = self.page(snapshot(history=()))
            page.search.setText('99' * 32)
            self.assertEqual(page.empty.text(), 'No matching activity in this display.')

    def test_D4A_3_verified_empty_distinguished_from_unavailable(self):
        """DEFECT D4A-3: verified empty and unavailable use the same message."""
        page = self.page(None)
        unavailable = page.empty.text()
        page.render_snapshot(snapshot(history=(), pending_history=()))
        self.assertNotEqual(page.empty.text(), unavailable, 'D4A-3')
        self.assertEqual(unavailable, ui_text('history.unavailable'))
        self.assertEqual(page.empty.text(), ui_text('history.empty_verified'))


if __name__ == '__main__':
    unittest.main()
