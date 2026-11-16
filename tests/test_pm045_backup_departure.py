"""D5-D presentation contracts; public fixtures, no custody acceptance."""
import unittest
from unittest.mock import patch
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QDialogButtonBox, QLabel
from wam_regtest.bip39_backup_page import BackupLeaveConfirm
from wam_regtest.bip39_locale import t
from test_q06_bip39_backup_safety import (
    _BackupSafetyCase, _DialogDriver, _DeferFailsStub, _VerifyFailsStub)


class DeparturePresentation(_BackupSafetyCase):
    def test_dialog_stay_focus_and_return_even_after_leave_focus(self):
        dialog = BackupLeaveConfirm(self.window)
        self.addCleanup(dialog.deleteLater)
        dialog.show()
        self.app.processEvents()
        self.assertIs(self.app.focusWidget(), dialog.stay_button)
        box = dialog.findChild(QDialogButtonBox)
        self.assertEqual(box.buttonRole(dialog.leave_button), QDialogButtonBox.ButtonRole.DestructiveRole)
        dialog.leave_button.setFocus()
        QTest.keyClick(dialog.leave_button, Qt.Key.Key_Return)
        self.assertEqual(dialog.result(), dialog.DialogCode.Rejected)
        self.assertFalse(dialog.isVisible())

    def test_success_clears_and_has_compact_continue_block(self):
        self._show_required()
        self._to_success_page()
        self.assertTrue(all(not edit.text() for _, _, edit in self.page._verify_cards))
        self.assertEqual(self.page._continue_button.text(), t('backup.done'))
        self.assertLessEqual(self.page._success_title.parentWidget().maximumWidth(), 560)
        self.assertEqual(self._word_count(), 0)

    def test_deferred_locked_reopen_uses_existing_password_flow_only(self):
        self._show_required()
        with _DialogDriver(self.app, 'leave'):
            self.page._back_up_later.click()
        self.assertIs(self.window.stack.currentWidget(), self.window.backup_deferred_page)
        self.assertEqual(self.window.backup_locked_description.text(), t('locked_subtitle'))
        self.window.executor.requests.clear()
        # Cancel the existing password prompt: no backend operation/auto-unlock.
        with patch.object(self.window, '_passphrase', return_value=None) as prompt:
            self.window.backup_reopen.click()
        prompt.assert_called_once()
        self.assertEqual(self.window.executor.requests, [])
        self.assertFalse(self.window._ready)
        self.assertEqual(self._word_count(), 0)
        self._show_deferred()
        self.assertEqual(self._word_count(), 0)
        self.assertFalse(self.page._verify_back.isVisible())

    def test_each_route_safe_default_keeps_phrase(self):
        self._show_required()
        self.window.show()
        for route in (self.page._back_up_later.click,
                      lambda: QTest.keyClick(self.page, Qt.Key.Key_Escape),
                      lambda: self.window._navigate(1), self.window.close,
                      self.window.request_quit):
            with _DialogDriver(self.app, 'enter') as driver:
                route()
            self.assertEqual(len(driver.seen), 1)
            self._assert_phrase_preserved()

    def test_challenge_and_cancel_errors_keep_codes_out_of_visible_text(self):
        self._show_required()
        with patch.object(self.window.executor, 'request', side_effect=ValueError('PUBLIC_UNAVAILABLE')):
            for callback in (self.window._on_backup_challenge, self.window._on_backup_challenge_cancel):
                callback()
                self.assertEqual(self.window.status.text(), t('wallet.backup_verify_unavailable'))
                self.assertEqual(self.window.status.toolTip(), t('wallet.backup_verify_unavailable'))
                self.assertEqual(self.window._last_error_code, 'WALLET_OPERATION_DENIED_STATE_RETAINED')
        self.assertEqual(self._word_count(), 12)

    def test_dialog_escape_and_close_are_stay_and_space_explicitly_leaves(self):
        for operation in ('escape', 'close', 'space'):
            dialog = BackupLeaveConfirm(self.window)
            self.addCleanup(dialog.deleteLater)
            dialog.show()
            self.app.processEvents()
            if operation == 'close':
                dialog.close()
            else:
                QTest.keyClick(dialog.leave_button, Qt.Key.Key_Space if operation == 'space' else Qt.Key.Key_Escape)
            self.assertEqual(dialog.result(), dialog.DialogCode.Accepted if operation == 'space' else dialog.DialogCode.Rejected)
            self.assertFalse(dialog.isVisible())



class VerifyUnavailablePresentation(_BackupSafetyCase):
    stub = _VerifyFailsStub

    def test_unavailable_has_no_appended_code(self):
        self._show_required()
        self._to_verify_page()
        for edit in self.page._verify_inputs:
            edit.setText('wrong')
        self.page._verify_button.click()
        self.assertEqual(self.window.status.text(), t('wallet.backup_verify_unavailable'))
        self.assertEqual(self.window._last_error_code, 'WALLET_OPERATION_DENIED_STATE_RETAINED')


class DeferralUnavailablePresentation(_BackupSafetyCase):
    stub = _DeferFailsStub

    def test_failure_does_not_claim_locked_deferral_or_append_code(self):
        self._show_required()
        self.assertNotIn(t('wallet.backup_defer_unavailable'), self.window.status.text())
        with _DialogDriver(self.app, 'leave'):
            self.page._back_up_later.click()
        self.assertEqual(self.window.status.text(), t('wallet.backup_defer_unavailable'))
        self.assertEqual(self.window._last_error_code, 'WALLET_OPERATION_DENIED_STATE_RETAINED')
        self.assertNotIn(t('locked_subtitle'), [w.text() for w in self.window.findChildren(QLabel) if w.isVisible()])
        self.assertEqual(self._word_count(), 0)


class DeferredCopyContracts(unittest.TestCase):
    def test_all_six_locales_have_reviewed_key_shapes_and_explicit_pending_review(self):
        import json
        from pathlib import Path
        from test_pm043_backup_copy import fields
        from wam_regtest.presentation.strings import CATALOG
        ledger = json.loads(Path(__file__).with_name('pm045_copy_ledger.json').read_text())
        for key, expected in ledger['english'].items():
            self.assertEqual(CATALOG['en'][key], expected)
            for locale, catalog in CATALOG.items():
                self.assertEqual(fields(catalog[key]), fields(expected))
                self.assertTrue(catalog[key].strip())
                self.assertEqual(ledger['native_review'][locale], 'PENDING')
