"""D4-A route counts: real window/WalletExecutor, synthetic recording backend.

No Core, profile, persistence or cryptographic authority. Count GUI dispatch and
backend execution separately, as in PM-051; cleanup quit is outside the event.
"""
from collections import Counter
from dataclasses import replace
import unittest
from unittest.mock import patch

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
from wam_regtest.wallet_executor import WalletExecutor
from test_pm054_d4a_history_state import snapshot, INCOMING, PENDING

COMMANDS = ('prepare_auto', 'prepare', 'mark_signed', 'sign', 'broadcast',
            'sendrawtransaction', 'cancel', 'release_draft', 'resume_intent',
            'activate', 'fund', 'confirm', 'lock', 'unlock', 'quit', 'snapshot')


class HistoryCommands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def setUp(self):
        self.calls = []
        calls = self.calls

        class Backend:
            core_alive = True

            def public_state(self):
                return dict(locked=False, faulted=False, core_alive=self.core_alive)

            def execute(self, action, args, kwargs):
                calls.append((action, args))
                if action == 'quit':
                    self.core_alive = False
                return None

        self.owner = WalletExecutor(Backend)
        self.window = Bip39FusionWindow(self.owner)
        self.window._poll.stop()
        self.owner.request('core_status')
        self.calls.clear()
        self.window._ready = True
        self.window.overview.render_snapshot(snapshot())
        self.window.history_page.render_snapshot(snapshot())
        self.window.show()
        self.app.processEvents()

    def tearDown(self):
        self.window._poll.stop()
        if not self.owner.closed:
            self.owner.request('quit')
        self.assertTrue(self.owner.join())
        self.window.hide()
        self.window.deleteLater()
        self.app.processEvents()

    def test_overview_exact_route_selection_and_copy_emit_zero_commands(self):
        page = self.window.history_page
        for index, txid in ((0, PENDING.txid), (1, INCOMING.txid)):
            with self.subTest(txid=txid):
                self.window.navigation.setCurrentRow(0)
                page.search.setText('no-match')
                page.filter.setCurrentIndex(2)
                self.app.processEvents()
                with patch.object(self.window, '_command', wraps=self.window._command) as dispatch:
                    table = self.window.overview.activity_table
                    item = table.item(index, 0)
                    QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton,
                                     pos=table.visualItemRect(item).center())
                    self.app.processEvents()
                    self.assertEqual(self.window.navigation.currentRow(), 2)
                    self.assertEqual(page.detail_id.text(), txid)
                    self.assertEqual(page.search.text(), '')
                    self.assertEqual(page.filter.currentIndex(), 0)
                    page.copy_button.click()
                    self.assertEqual(self.app.clipboard().text(), txid)
                    gui_counts = Counter(call.args[0] for call in dispatch.call_args_list)
                    backend_counts = Counter(action for action, _ in self.calls)
                    self.assertEqual({c: gui_counts[c] for c in COMMANDS}, dict.fromkeys(COMMANDS, 0))
                    self.assertEqual({c: backend_counts[c] for c in COMMANDS}, dict.fromkeys(COMMANDS, 0))
                    self.assertEqual(dispatch.call_count, 0)  # includes unknown command names
                    self.assertEqual(self.calls, [])

    def test_absent_overview_route_and_copy_emit_zero_commands(self):
        page = self.window.history_page
        page.select_txid(INCOMING.txid)
        requests = []
        page.page_requested.connect(requests.append)
        with patch.object(self.window, '_command', wraps=self.window._command) as dispatch:
            self.window._select_transaction('99' * 32)
            page.copy_txid()
            self.assertFalse(page.copy_button.isEnabled())
            self.assertEqual(page.detail_values.text(), '')
            self.assertEqual(requests, [])
            self.assertEqual(dispatch.call_count, 0)
            self.assertEqual(self.calls, [])

    def test_refresh_and_lock_through_window_boundaries(self):
        from wam_regtest.fusion_ui import ui_text
        page = self.window.history_page
        page.select_txid(INCOMING.txid)
        expected_detail = page.detail_values.text()
        snap = snapshot()
        verified_result = {
            'fusion_snapshot': snap,
            'receive_code': snap.receive_code,
            'confirmed_atoms': snap.confirmed_atoms,
            'available_atoms': snap.confirmed_atoms,
            'signer_allowed': snap.signer_allowed,
            'broadcast_allowed': snap.broadcast_allowed,
        }
        with patch.object(self.window, '_command', wraps=self.window._command) as dispatch:
            for _ in range(3):
                self.window._render_verified(verified_result)
                self.app.processEvents()
                self.assertEqual(page.table.currentRow(), 1)
                self.assertEqual(page.detail_id.text(), INCOMING.txid)
                self.assertEqual(page.detail_values.text(), expected_detail)
                self.assertTrue(page.copy_button.isEnabled())
            self.app.clipboard().setText('sentinel')
            page.copy_button.click()
            self.assertEqual(self.app.clipboard().text(), INCOMING.txid)
            for locked in (True, False):
                with self.subTest(locked=locked):
                    with patch.object(self.owner, '_state', replace(self.owner.state, locked=locked)):
                        self.window._clear_visuals()
                    self.assertEqual(page.empty.text(), ui_text('history.unavailable'))
                    self.assertFalse(page.copy_button.isEnabled())
                    self.assertEqual(page.rows, ())
                    self.assertEqual(page.scope.text(), '')
                    self.assertEqual(page.detail_values.text(), '')
            self.assertEqual(dispatch.call_count, 0)
        self.assertEqual(self.calls, [])

    def test_clear_visuals_lock_boundary_clears_history_selection(self):
        page = self.window.history_page
        page.select_txid(INCOMING.txid)
        self.window._clear_visuals()
        self.assertEqual(page.rows, ())
        self.assertFalse(page.copy_button.isEnabled())
        self.assertEqual(page.detail_values.text(), '')
        self.assertEqual(self.window.overview._txids, [])
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
