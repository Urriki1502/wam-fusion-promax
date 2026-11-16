"""Permanent PM-057 regression probe, originally supplied by Kimi review.

Verify item 1: a periodic snapshot poll delivering the SAME live review while
a Sign sheet is open must not close or neuter the sheet, must add zero
commands, and a later explicit Approve must still emit exactly ONE sign.
Same for the Broadcast sheet: exactly ONE broadcast afterwards.
"""
import unittest
from dataclasses import replace

import test_pm051_d3a_send_commands as send_commands
from wam_regtest.wallet_executor import immutable
from wam_regtest.wallet_read import WalletReadSnapshot

REVIEW, TXID = send_commands.REVIEW, send_commands.TXID


class SnapshotWhileSheetOpen(send_commands.SendCommands):

    def _verified_poll_then_approve(self, kind):
        from wam_regtest.qualification.ui_gallery import _fixture_snapshot
        receive_code = _fixture_snapshot()[0].receive_code
        dialog = self.prepare()
        if kind == 'broadcast':
            dialog.approve.click()
            self.wait_for(lambda: self.window._signed_ready and self.window._worker is None)
            self.window._confirm_broadcast()
            dialog = self.dialog()
        before = list(self.calls)
        for _ in range(3):
            # Executor delivery reconstructs frozen dataclasses. Equal review
            # commitments must survive even when their objects are different.
            review = replace(REVIEW, commitment=''.join(['a'] * 64))
            self.assertIsNot(review.commitment, self.window._approved_commitment)
            result = dict(self.snapshot(review=review, signed=kind == 'broadcast'))
            result['receive_code'] = receive_code
            result['fusion_snapshot'] = WalletReadSnapshot(
                chain='regtest', height=1, tip='c'*64, receive_code=receive_code,
                confirmed_atoms=100000, confirmed_utxos=1, history=(),
                core_sha256='e'*64, signer_allowed=True, broadcast_allowed=True)
            self.window._on_ready('snapshot', immutable(result))
            self.app.processEvents()
            self.assertIsNotNone(self.window._last_verified)
            self.assertTrue(dialog.isVisible())
            self.assertTrue(dialog.approve.isEnabled())
            self.assertEqual(self.calls, before)
            self.assertIsNone(self.window._pending_action)
        dialog.approve.click()
        self.wait_for(lambda: kind in self.actions() and self.window._worker is None)
        self.assertEqual(self.actions().count('prepare_auto'), 1)
        self.assertEqual(self.actions().count('sign'), 1)
        self.assertEqual(self.actions().count('broadcast'), int(kind == 'broadcast'))
        self.assertEqual(self.actions().count('cancel'), 0)

    def test_verified_snapshot_equal_review_then_one_sign(self):
        self._verified_poll_then_approve('sign')

    def test_verified_snapshot_equal_review_then_one_broadcast(self):
        self._verified_poll_then_approve('broadcast')

    def test_snapshot_poll_keeps_sign_sheet_then_one_sign(self):
        dialog = self.prepare()
        self.assertEqual(self.actions(), ['prepare_auto'])
        for _ in range(3):
            self.window._on_ready('snapshot', self.snapshot(review=REVIEW))
            self.app.processEvents()
            self.assertTrue(dialog.isVisible())
            self.assertTrue(dialog.isEnabled())
            self.assertTrue(dialog.approve.isEnabled())
            self.assertEqual(self.actions(), ['prepare_auto'])
            self.command.reset_mock()
        dialog.approve.click()
        self.wait_for(lambda: self.window._signed_ready and self.window._worker is None)
        self.assertEqual(self.actions(), ['prepare_auto', 'sign'])
        self.assertEqual(self.actions().count('sign'), 1)

    def test_snapshot_poll_keeps_broadcast_sheet_then_one_broadcast(self):
        self.signed()
        self.assertEqual(self.actions(), ['prepare_auto', 'sign'])
        self.window._confirm_broadcast()
        dialog = self.dialog()
        for _ in range(3):
            self.window._on_ready('snapshot', self.snapshot(review=REVIEW, signed=True))
            self.app.processEvents()
            self.assertTrue(dialog.isVisible())
            self.assertTrue(dialog.isEnabled())
            self.assertTrue(dialog.approve.isEnabled())
            self.assertEqual(self.actions(), ['prepare_auto', 'sign'])
        dialog.approve.click()
        self.wait_for(lambda: 'broadcast' in self.actions() and self.window._worker is None)
        self.assertEqual(self.actions().count('broadcast'), 1)
        self.assertEqual(self.actions().count('sign'), 1)
        self.assertEqual(self.window._pending_confirm_txid, TXID)

    def test_snapshot_poll_does_not_queue_cancel_or_close_after_repeated_polls(self):
        dialog = self.prepare()
        for _ in range(5):
            self.window._on_ready('snapshot', self.snapshot(review=REVIEW))
        self.app.processEvents()
        self.assertTrue(dialog.isVisible())
        self.assertEqual(self.actions(), ['prepare_auto'])
        # Cancel path still works exactly as before: exactly one cancel.
        dialog.cancel.click()
        self.wait_for(lambda: self.window._worker is None and 'cancel' in self.actions())
        self.assertEqual(self.actions(), ['prepare_auto', 'cancel'])
        self.assertEqual(self.actions().count('cancel'), 1)


if __name__ == '__main__':
    unittest.main()
