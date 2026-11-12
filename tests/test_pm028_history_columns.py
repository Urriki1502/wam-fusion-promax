"""PM-028 (V0 R-5): History never hides amounts behind a horizontal scroll."""
import unittest

from wam_regtest.wallet_read import HistoryRow, WalletReadSnapshot

TXID = 'ab' * 32


def _snapshot():
    rows = (HistoryRow(TXID, 112, 1, 0, 25_010_000), HistoryRow('cd' * 32, 108, 5, 50_000_000, 0))
    return WalletReadSnapshot(chain='regtest', height=112, tip='ef' * 32, receive_code='',
                              confirmed_atoms=24_990_000, confirmed_utxos=1, history=rows,
                              core_sha256='01' * 32, history_complete=True)


class HistoryColumns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def _page(self, width):
        from wam_regtest.fusion_pages import HistoryPage
        page = HistoryPage()
        self.addCleanup(page.deleteLater)
        page.resize(width, 700)
        page.show()
        page.render_snapshot(_snapshot())
        for _ in range(10):
            self.app.processEvents()
        return page

    def test_narrow_hides_block_and_confirmed_first_and_never_amounts(self):
        table = self._page(560).table
        self.assertTrue(table.isColumnHidden(2))
        self.assertTrue(table.isColumnHidden(3))
        for column in (0, 1, 4, 5):
            self.assertFalse(table.isColumnHidden(column), column)
        self.assertEqual(table.horizontalScrollBar().maximum(), 0)

    def test_wide_shows_every_column(self):
        table = self._page(1300).table
        for column in range(6):
            self.assertFalse(table.isColumnHidden(column), column)

    def test_detail_panel_still_shows_block_and_confirmations(self):
        page = self._page(560)
        page.table.selectRow(0)
        page.show_details()
        self.assertIn('112', page.detail_values.text())
        self.assertEqual(page.detail_id.text(), TXID)


class AdaptiveButtonRowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def test_minimum_is_the_widest_button_and_it_stacks_when_narrow(self):
        from PySide6.QtWidgets import QBoxLayout, QPushButton
        from wam_regtest.fusion_ui import AdaptiveButtonRow
        first, second = QPushButton('A fairly long first label'), QPushButton('A fairly long second label')
        row = AdaptiveButtonRow(first, second)
        self.addCleanup(row.deleteLater)
        widest = max(first.minimumSizeHint().width(), second.minimumSizeHint().width())
        self.assertEqual(row.minimumSizeHint().width(), widest)
        row.resize(widest + 4, 200)
        row.show()
        self.app.processEvents()
        self.assertEqual(row._box.direction(), QBoxLayout.Direction.TopToBottom)
        row.resize(2000, 200)
        self.app.processEvents()
        self.assertEqual(row._box.direction(), QBoxLayout.Direction.LeftToRight)


if __name__ == '__main__':
    unittest.main()
