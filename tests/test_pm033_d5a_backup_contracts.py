"""PM-033 D5-A: source/widget characterization; no Core or acceptance claims.

Only public disposable fixtures and recording executors are used. Known gaps
are expected failures with finding IDs; D5-A must not repair product code.
"""
from collections import Counter
import sys
import unittest
from unittest.mock import patch

from PySide6.QtCore import Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel, QWidget

from test_q06_bip39_backup_ack import _DISPLAY_PHRASE_WORDS
from test_q06_bip39_backup_safety import (
    _BackupSafetyCase, _DeferFailsStub, _DialogDriver, _VerifyFailsStub,
)
from wam_regtest.bip39_locale import t
from wam_regtest.bip39_owner_gui import Bip39RecoveryVerifyDialog


class BackupCommandInventory(_BackupSafetyCase):
    def test_confirm_checkbox_challenge_verify_and_back_counts(self):
        self._show_required()
        self.assertEqual(self.window.executor.requests, ['acknowledge_create_pending'])
        self.window.executor.requests.clear()
        self.page._back_up_now.click()
        self.page._on_back_up_now()  # slot must enforce the gate too
        self.assertEqual(self.window.executor.requests, [])
        self._to_verify_page()
        self.assertEqual(self.window.executor.requests, ['backup_challenge'])
        self.page._verify_button.click()  # empty answers stay local
        self.assertEqual(self.window.executor.requests, ['backup_challenge'])
        self.page._verify_back.click()
        self.assertEqual(self.window.executor.requests,
                         ['backup_challenge', 'backup_challenge_cancel'])
        self.assertTrue(all(not edit.text() for _, _, edit in self.page._verify_cards))
        self._to_success_page()
        self.assertEqual(Counter(self.window.executor.requests), Counter(
            backup_challenge=2, backup_challenge_cancel=1, backup_verify=1))

    def test_wrong_word_refreshes_challenge_clears_answers_without_retry(self):
        self._show_required()
        self._to_verify_page()
        previous = self.page._challenge_id
        self.window.executor.requests.clear()
        for edit in self.page._verify_inputs:
            edit.setText('wrong')
        self.page._verify_button.click()
        self.assertEqual(self.window.executor.requests, ['backup_verify', 'backup_challenge'])
        self.assertNotEqual(self.page._challenge_id, previous)
        self.assertTrue(all(not edit.text() for _, _, edit in self.page._verify_cards))
        self.assertEqual(self.page._verify_error.text(), t('verify_error'))
        self.assertFalse(self.window._backup_verified)

    def test_challenge_unavailable_does_not_verify_or_judge_words(self):
        self._show_required()
        self.window.executor.requests.clear()
        original = self.window.executor.request

        def unavailable(action, *args, **kwargs):
            if action == 'backup_challenge':
                self.window.executor.requests.append(action)
                raise ValueError('PUBLIC_TEST_UNAVAILABLE')
            return original(action, *args, **kwargs)

        with patch.object(self.window.executor, 'request', side_effect=unavailable):
            self.page._written_check.setChecked(True)
            self.page._back_up_now.click()
        self.assertEqual(self.window.executor.requests, ['backup_challenge'])
        self.assertIsNone(self.page._challenge_id)
        self.assertEqual(self.page._verify_error.text(), t('verify_unavailable'))
        self.assertTrue(self.page.holds_unverified_phrase())

    def test_departure_stay_and_leave_dialog_and_command_counts(self):
        self._show_required()
        self.window.show()
        # Observe live labels at executor invocation, before Qt deferred deletion.
        original = self.window.executor.request
        counts_at_defer = []

        def observe(action, *args, **kwargs):
            if action == 'backup_defer':
                self.assertEqual(kwargs.get('timeout'), 30)
                counts_at_defer.append(self._word_count())
            return original(action, *args, **kwargs)

        with patch.object(self.window.executor, 'request', side_effect=observe):
            for route in (self.page._back_up_later.click,
                          lambda: QTest.keyClick(self.page, Qt.Key.Key_Escape),
                          self.window.close, self.window.request_quit):
                with _DialogDriver(self.app, 'stay') as driver:
                    route()
                self.assertEqual(len(driver.seen), 1)
                self._assert_phrase_preserved()
            self.window.executor.requests.clear()
            with _DialogDriver(self.app, 'leave') as driver:
                self.page._back_up_later.click()
            self.assertEqual(len(driver.seen), 1)
        self.assertEqual(counts_at_defer, [0])
        self.assertEqual(self.window.executor.requests, ['backup_defer'])
        self.page.deferred_requested.emit()
        self.window._defer_active_backup()
        self.assertEqual(self.window.executor.requests, ['backup_defer'])

    def test_disabled_navigation_cannot_depart_by_mouse_or_keyboard(self):
        self._show_required()
        self.window.show()
        before = self.window.navigation.currentRow()
        self.window.executor.requests.clear()
        with _DialogDriver(self.app, 'leave') as driver:
            nav = self.window.navigation
            QTest.mouseClick(nav.viewport(), Qt.MouseButton.LeftButton,
                             pos=nav.visualItemRect(nav.item(1)).center())
            QTest.keyClick(nav, Qt.Key.Key_Down)
        self.assertEqual(driver.seen, [])  # disabled is no departure route
        self.assertEqual(nav.currentRow(), before)
        self.assertEqual(self.window.executor.requests, [])
        self._assert_phrase_preserved()

    def test_navigation_callback_requires_departure_guard(self):
        """D5A-01: direct navigation callback must enforce backup departure guard."""
        self._show_required()
        with _DialogDriver(self.app, 'stay') as driver:
            self.window._navigate(1)
        self.assertEqual(len(driver.seen), 1, 'D5A-01: callback has no departure dialog')
        self._assert_phrase_preserved()

    def test_navigation_callback_leave_clears_before_defer_and_deferred_stays_locked(self):
        self._show_required()
        counts = []
        original = self.window.executor.request

        def observe(action, *args, **kwargs):
            if action == 'backup_defer':
                self.assertEqual(kwargs.get('timeout'), 30)
                counts.append(self._word_count())
            return original(action, *args, **kwargs)

        with patch.object(self.window.executor, 'request', side_effect=observe):
            with _DialogDriver(self.app, 'leave') as driver:
                self.window._navigate(1)
        self.assertEqual(len(driver.seen), 1)
        self.assertEqual(counts, [0])
        self._assert_left_fail_closed()

        # Deferred reopen holds no words, so _navigate must stay on backup_page without prompting.
        self.window.executor.requests.clear()
        self._show_deferred()
        with _DialogDriver(self.app, 'stay') as driver:
            self.window._navigate(1)
        self.assertEqual(driver.seen, [])
        self.assertEqual(self._defers(), 0)
        self.assertIs(self.window.stack.currentWidget(), self.page)
        self.assertIs(self.page._stack.currentWidget(), self.page._verify_page)

    def _leave_via_owner(self, route):
        self._show_required()
        self.window.show()
        counts = []
        original = self.window.executor.request

        def observe(action, *args, **kwargs):
            if action == 'backup_defer':
                self.assertEqual(kwargs.get('timeout'), 30)
                counts.append(self._word_count())
            return original(action, *args, **kwargs)

        with patch.object(self.window.executor, 'request', side_effect=observe):
            with _DialogDriver(self.app, 'leave') as driver:
                route()
        self.assertEqual(len(driver.seen), 1)
        self.assertEqual(self._defers(), 1)
        self.assertEqual(self._word_count(), 0)
        self.assertEqual(counts, [0], 'D5A-02: owner quit sends defer before clearing labels')

    def test_window_close_clears_labels_before_defer(self):
        """D5A-02: close clears words before backup_defer is dispatched."""
        self._leave_via_owner(self.window.close)

    def test_request_quit_clears_labels_before_defer(self):
        """D5A-02: request_quit clears words before backup_defer is dispatched."""
        self._leave_via_owner(self.window.request_quit)

    def test_native_cmd_q_departure(self):
        if sys.platform != 'darwin' or QApplication.platformName() != 'cocoa':
            self.skipTest('Native Cmd+Q/menu delivery requires macOS Cocoa platform')
        from PySide6.QtCore import QCoreApplication
        from test_jeeves_onboarding_regression import _macos_send_command_q

        self._show_required()
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()
        self.app.processEvents()

        # First Cmd+Q with Stay retains all 12 words and sends zero defers/quits.
        stay_dog = QTimer(self.window)
        stay_dog.setSingleShot(True)
        stay_dog.timeout.connect(lambda: QCoreApplication.exit(0))
        try:
            with _DialogDriver(self.app, 'stay') as driver:
                QTimer.singleShot(50, self.window, _macos_send_command_q)
                stay_dog.start(400)
                self.app.exec()
        finally:
            stay_dog.stop()
        self.assertEqual(len(driver.seen), 1)
        self._assert_phrase_preserved()
        self.assertNotIn('quit', self.window.executor.requests)

        # Second Cmd+Q with Leave clears words BEFORE backup_defer and quits.
        counts = []
        original = self.window.executor.request

        def observe(action, *args, **kwargs):
            if action == 'backup_defer':
                self.assertEqual(kwargs.get('timeout'), 30)
                counts.append(self._word_count())
            return original(action, *args, **kwargs)

        leave_dog = QTimer(self.window)
        leave_dog.setSingleShot(True)
        leave_dog.timeout.connect(lambda: QCoreApplication.exit(0))
        try:
            with patch.object(self.window.executor, 'request', side_effect=observe):
                with _DialogDriver(self.app, 'leave') as driver:
                    QTimer.singleShot(50, self.window, _macos_send_command_q)
                    leave_dog.start(500)
                    self.app.exec()
        finally:
            leave_dog.stop()
            # Reset Qt's quit-now flag left by Quit before later tests run exec().
            QTimer.singleShot(0, self.app.quit)
            self.app.exec()
        self.assertEqual(len(driver.seen), 1)
        self.assertEqual(counts, [0])
        self._assert_left_fail_closed()
        self.assertTrue(self.window._quit_requested)

    def test_deferred_reopen_never_redisplays_and_verified_cannot_defer(self):
        self._show_required()
        self.window.executor.requests.clear()
        self._show_deferred()
        self.assertEqual(self.window.executor.requests, ['backup_challenge'])
        self.assertEqual(self._word_count(), 0)
        self.window.executor.requests.clear()
        self.page._verify_back.click()
        self.assertEqual(self.window.executor.requests, ['backup_challenge_cancel'])
        self.assertIs(self.page._stack.currentWidget(), self.page._verify_page)
        self.assertEqual(self._word_count(), 0)
        self.page._verify_button.click()  # no challenge => request only
        self.assertEqual(self.window.executor.requests,
                         ['backup_challenge_cancel', 'backup_challenge'])
        words = _DISPLAY_PHRASE_WORDS.split()
        for edit, position in zip(self.page._verify_inputs, self.page._challenge_positions):
            edit.setText(words[position - 1])
        self.page._verify_button.click()
        self.assertTrue(self.window._backup_verified)
        self.window.executor.requests.clear()
        self.page.deferred_requested.emit()
        self.page.deferred_requested.emit()
        self.window._defer_active_backup()
        self.window.request_quit()
        self.assertNotIn('backup_defer', self.window.executor.requests)
        self.assertEqual(self._word_count(), 0)

    def test_clearing_removes_words_from_widget_metadata_and_status(self):
        self._show_required()
        self._to_success_page()
        surfaces = []
        for widget in [self.window, *self.window.findChildren(QWidget)]:
            surfaces.extend((widget.toolTip(), widget.accessibleName(),
                             widget.accessibleDescription(), widget.windowTitle(),
                             widget.statusTip(), widget.whatsThis()))
            if isinstance(widget, QLabel):
                surfaces.append(widget.text())
        # Whole tokens: common fixture words must not match substrings of UI copy.
        import re
        tokens = set(re.findall(r'[a-z]+', ' '.join(surfaces).lower()))
        self.assertFalse(set(_DISPLAY_PHRASE_WORDS.split()) & tokens,
                         'cleared word remains in visible text or metadata')


class UnavailableCommandInventory(_BackupSafetyCase):
    stub = _VerifyFailsStub

    def test_verify_unavailable_refreshes_without_reporting_wrong_answer(self):
        self._show_required()
        self._to_verify_page()
        previous = self.page._challenge_id
        self.window.executor.requests.clear()
        for edit in self.page._verify_inputs:
            edit.setText('wrong')
        self.page._verify_button.click()
        self.assertEqual(self.window.executor.requests, ['backup_verify', 'backup_challenge'])
        self.assertNotEqual(self.page._challenge_id, previous)
        self.assertEqual(self.page._verify_error.text(), t('verify_unavailable'))
        self.assertTrue(all(not edit.text() for _, _, edit in self.page._verify_cards))


class DeferralFailureContracts(_BackupSafetyCase):
    stub = _DeferFailsStub

    def _assert_owner_deferral_failure(self, route):
        self._show_required()
        self.window.show()
        self.window.executor.requests.clear()
        counts = []
        original = self.window.executor.request

        def observe(action, *args, **kwargs):
            if action == 'backup_defer':
                self.assertEqual(kwargs.get('timeout'), 30)
                counts.append(self._word_count())
            return original(action, *args, **kwargs)

        with patch.object(self.window.executor, 'request', side_effect=observe):
            with _DialogDriver(self.app, 'leave') as driver:
                route()
        self.assertEqual(len(driver.seen), 1)
        self.assertEqual(counts, [0])
        self.assertEqual(self._word_count(), 0)
        self.assertFalse(self.page.holds_unverified_phrase())
        self.assertTrue(self.window._backup_unacked)
        self.assertFalse(self.window._ready)
        self.assertFalse(self.window._unlock_allowed)

    def test_close_deferral_failure_keeps_words_cleared_and_unavailable(self):
        self._assert_owner_deferral_failure(self.window.close)

    def test_request_quit_deferral_failure_keeps_words_cleared_and_unavailable(self):
        self._assert_owner_deferral_failure(self.window.request_quit)

    def test_back_up_later_deferral_failure_shows_unavailable_without_restoring_words(self):
        self._show_required()
        with _DialogDriver(self.app, 'leave') as driver:
            self.page._back_up_later.click()
        self.app.processEvents()
        self.assertEqual(len(driver.seen), 1)
        self.assertEqual(self._word_count(), 0)
        self.assertFalse(self.page.holds_unverified_phrase())
        self.assertTrue(self.window._backup_unacked)
        self.assertFalse(self.window._ready)
        self.assertIn(t('wallet.backup_defer_unavailable'), self.window.status.text())
        self.assertNotIn('PUBLIC_TEST_ACK_WRITE_FAILURE', self.window.status.text())


class RecoveryCommandInventory(_BackupSafetyCase):
    def test_fusion_backup_consent_and_recovery_cancel_send_no_command(self):
        from wam_regtest.bip39_fusion_gui import WalletConsent
        self.window._spend_enabled = True
        self.window.recovery.setEnabled(True)
        self.window.executor.requests.clear()
        for accept in (False, True):
            seen = []
            ticks = []

            def respond():
                ticks.append(1)
                dialog = self.app.activeModalWidget()
                if isinstance(dialog, WalletConsent):
                    seen.append('consent')
                    dialog.accept() if accept else dialog.reject()
                elif isinstance(dialog, Bip39RecoveryVerifyDialog):
                    seen.append('entry')
                    dialog._on_cancel()
                elif len(ticks) > 100 and dialog is not None:
                    dialog.reject()

            timer = QTimer()
            timer.setInterval(10)
            timer.timeout.connect(respond)
            timer.start()
            try:
                self.window._quick_backup()
            finally:
                timer.stop()
            self.assertEqual(seen, ['consent', 'entry'] if accept else ['consent'])
            self.assertEqual(self.window.executor.requests, [])
            self.assertIsNone(getattr(self.window, '_recovery_dialog', None))

    def test_recovery_invalid_cancel_and_valid_submit_command_counts(self):
        dialog = Bip39RecoveryVerifyDialog(self.window)
        self.addCleanup(dialog.deleteLater)
        dialog.verify_requested.connect(self.window._on_recovery_verify_requested)
        dialog.cancelled.connect(self.window._on_recovery_verify_cancelled)
        # Keep the real ControlWorker and recording executor boundary.
        original = self.window.executor.request

        def recovery(action, *args, **kwargs):
            if action == 'recovery_verify':
                self.window.executor.requests.append(action)
                return {'history_count': 0, 'confirmed_atoms': 0}
            return original(action, *args, **kwargs)

        with patch.object(self.window.executor, 'request', side_effect=recovery):
            self.window.executor.requests.clear()
            dialog._on_verify_phrase()
            self.assertEqual(self.window.executor.requests, [])
            dialog._on_cancel()
            self.assertEqual(self.window.executor.requests, [])
            for field, word in zip(dialog._fields, _DISPLAY_PHRASE_WORDS.split()):
                field.setText(word)
            dialog._verify_button.click()
            worker = self.window._worker
            self.assertIsNotNone(worker)
            self.assertTrue(worker.wait(2000))
            self.app.processEvents()
            self.assertEqual(self.window.executor.requests, ['recovery_verify'])
            self.assertTrue(all(not field.text() for field in dialog._fields))
