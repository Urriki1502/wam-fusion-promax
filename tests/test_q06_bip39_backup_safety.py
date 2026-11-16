"""UI-FIX-01 backup safety regression (audit findings D1 and D2).

D1: the only display of the 12 words must not be dismissed by Escape, Back up
later, window close or quit without an explicit confirmation whose safe
default is Stay.
D2: a verified backup acknowledgement must never regress to deferred because
of Escape, close, quit or a repeated signal.

Real production Qt widgets and the real confirmation dialog are driven; only
the wallet executor is a recording stub. This is a source/widget contract. It
is not real-Core, frozen-binary or physical acceptance, and it changes no
acceptance status.
"""
import contextlib
import importlib.util
import io
import unittest

from test_q06_bip39_backup_ack import (
    _DISPLAY_PHRASE_WORDS, _StubExecutor, _make_window, _open_result)

_QT = importlib.util.find_spec("PySide6") is not None
if _QT:
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QCheckBox, QLabel, QPushButton

    from wam_regtest.bip39_backup_page import BackupLeaveConfirm

_WORDS = _DISPLAY_PHRASE_WORDS.split()


class _DialogDriver:
    """Answers the REAL modal confirmation once it is visible. Never hangs."""

    def __init__(self, app, how):
        self.app = app
        self.how = how
        self.seen = []
        self.ticks = 0
        self.timer = QTimer()
        self.timer.setInterval(20)
        self.timer.timeout.connect(self._tick)

    def _dialogs(self):
        return [w for w in self.app.topLevelWidgets()
                if isinstance(w, BackupLeaveConfirm) and w.isVisible()]

    def _tick(self):
        self.ticks += 1
        dialogs = self._dialogs()
        if not dialogs:
            if self.ticks > 150:
                self.timer.stop()
            return
        dialog = dialogs[0]
        if len(self.seen) > 3 or self.ticks > 400:
            # Watchdog: the safe answer, so a defect fails instead of hanging.
            self.timer.stop()
            dialog.reject()
            return
        self.seen.append({
            "stay_default": dialog.stay_button.isDefault(),
            "leave_default": dialog.leave_button.isDefault(),
            "leave_auto_default": dialog.leave_button.autoDefault(),
            "texts": [w.text() for w in dialog.findChildren(QLabel)],
        })
        if self.how == "leave":
            dialog.leave_button.click()
        elif self.how == "stay":
            dialog.stay_button.click()
        elif self.how == "enter":
            QTest.keyClick(dialog, Qt.Key.Key_Return)
        elif self.how == "escape":
            QTest.keyClick(dialog, Qt.Key.Key_Escape)
        else:
            dialog.reject()

    def __enter__(self):
        self.timer.start()
        return self

    def __exit__(self, *exc):
        self.timer.stop()
        for dialog in self._dialogs():
            dialog.reject()
        return False


class _QuitStub(_StubExecutor):
    """Recording stub that also completes the owner quit the GUI requests."""

    def request(self, action, *args, timeout=90, **kwargs):
        if action == "quit":
            self.requests.append(action)
            self.closed = True
            return None
        return super().request(action, *args, timeout=timeout, **kwargs)

    def join(self, timeout=None):
        return True


class _DeferFailsStub(_QuitStub):
    def request(self, action, *args, timeout=90, **kwargs):
        if action == "backup_defer":
            self.requests.append(action)
            raise ValueError("PUBLIC_TEST_ACK_WRITE_FAILURE")
        return super().request(action, *args, timeout=timeout, **kwargs)


class _VerifyFailsStub(_QuitStub):
    def request(self, action, *args, timeout=90, **kwargs):
        if action == "backup_verify":
            self.requests.append(action)
            self.challenge = None
            raise ValueError("PUBLIC_TEST_ACK_WRITE_FAILURE")
        return super().request(action, *args, timeout=timeout, **kwargs)


@unittest.skipUnless(_QT, "Native Qt widgets verified on Qt-capable runners")
class _BackupSafetyCase(unittest.TestCase):
    stub = _QuitStub

    def setUp(self):
        self.app, self.window = _make_window()
        executor = self.stub(self.window.executor.seed_folder, _DISPLAY_PHRASE_WORDS)
        self.window.executor = executor
        # Deterministic: the test drives quit completion itself.
        self.window._poll.stop()
        self.page = self.window.backup_page

    def tearDown(self):
        self.window._poll.stop()
        worker = self.window._worker
        if worker is not None:
            self.assertTrue(worker.wait(2000))
        self.app.processEvents()
        self.window.hide()
        self.window.deleteLater()
        self.app.processEvents()

    # -- helpers ---------------------------------------------------------
    def _show_required(self):
        self.window._on_ready("open", _open_result(
            "required", _DISPLAY_PHRASE_WORDS, self.window.executor.seed_folder))
        self.app.processEvents()

    def _show_deferred(self):
        self.window._on_ready("open", _open_result(
            "deferred", "", self.window.executor.seed_folder))
        self.app.processEvents()

    def _to_verify_page(self):
        self.page.findChildren(QCheckBox)[0].setChecked(True)
        self.page._back_up_now.click()
        self.app.processEvents()
        self.assertIs(self.page._stack.currentWidget(), self.page._verify_page)

    def _to_success_page(self):
        self._to_verify_page()
        for edit, position in zip(self.page._verify_inputs, self.page._challenge_positions):
            edit.setText(_WORDS[position - 1])
        self.page._verify_button.click()
        self.app.processEvents()
        self.assertIs(self.page._stack.currentWidget(), self.page._success_page)
        self.assertEqual(self.window.executor.marker, (True, False))
        self.assertEqual(self._word_count(), 0)

    def _displayed_words(self):
        # Words held by ANY label under the backup page, including cards that
        # are only scheduled for deletion. Assertions use counts/booleans so a
        # failure never prints fixture words into a log.
        return [w.text() for w in self.page.findChildren(QLabel)
                if w.text() in _WORDS]

    def _words_shown(self):
        return sorted(self._displayed_words()) == sorted(_WORDS)

    def _word_count(self):
        return len(self._displayed_words())

    def _defers(self):
        return self.window.executor.requests.count("backup_defer")

    def _assert_phrase_preserved(self, page=None):
        self.assertEqual(self._defers(), 0)
        self.assertTrue(self._words_shown(), "all 12 words must still be displayed")
        self.assertTrue(self.page.holds_unverified_phrase())
        self.assertIs(self.window.stack.currentWidget(), self.page)
        self.assertIs(self.page._stack.currentWidget(), page or self.page._phrase_page)
        self.assertTrue(self.window._backup_flow_active)
        self.assertFalse(self.window.navigation.isEnabled())
        self.assertFalse(self.window._quit_requested)
        self.assertFalse(self.window.executor.locked)
        self.assertFalse(self.window._ready)

    def _assert_left_fail_closed(self):
        self.assertEqual(self._defers(), 1)
        self.assertTrue(self.window.executor.locked)
        self.assertEqual(self.window.executor.marker, (False, True))
        self.assertEqual(self._word_count(), 0)
        self.assertFalse(self.page.holds_unverified_phrase())
        self.assertFalse(self.window._backup_flow_active)
        self.assertTrue(self.window._backup_unacked)
        self.assertFalse(self.window._ready)
        self.assertFalse(self.window._unlock_allowed)
        self.assertFalse(self.window.send.isEnabled())
        self.assertFalse(self.window.broadcast.isEnabled())
        self.assertFalse(self.window.activate.isEnabled())


class SeedDisplayDepartureContract(_BackupSafetyCase):
    """D1: every route off the initial seed display needs explicit consent."""

    def test_confirmation_dialog_defaults_to_stay(self):
        self._show_required()
        with _DialogDriver(self.app, "stay") as driver:
            self.page._back_up_later.click()
        self.assertEqual(len(driver.seen), 1)
        seen = driver.seen[0]
        self.assertTrue(seen["stay_default"])
        self.assertFalse(seen["leave_default"])
        self.assertFalse(seen["leave_auto_default"])
        # The prompt explains the consequence and never carries seed words.
        self.assertTrue(any("not be displayed again" in text for text in seen["texts"]))
        for text in seen["texts"]:
            self.assertNotIn(_DISPLAY_PHRASE_WORDS, text)
        self._assert_phrase_preserved()

    def test_escape_then_stay_preserves_the_twelve_words(self):
        for answer in ("stay", "enter", "escape"):
            with self.subTest(answer=answer):
                self._show_required()
                with _DialogDriver(self.app, answer) as driver:
                    QTest.keyClick(self.page, Qt.Key.Key_Escape)
                self.assertEqual(len(driver.seen), 1, "confirmation must be shown once")
                self._assert_phrase_preserved()

    def test_back_up_later_then_stay_preserves_the_twelve_words(self):
        for answer in ("stay", "enter", "escape"):
            with self.subTest(answer=answer):
                self._show_required()
                with _DialogDriver(self.app, answer) as driver:
                    self.page._back_up_later.click()
                self.assertEqual(len(driver.seen), 1)
                self._assert_phrase_preserved()

    def test_escape_then_confirmed_departure_clears_and_locks(self):
        self._show_required()
        with _DialogDriver(self.app, "leave") as driver:
            QTest.keyClick(self.page, Qt.Key.Key_Escape)
        self.app.processEvents()
        self.assertEqual(len(driver.seen), 1)
        self._assert_left_fail_closed()
        self.assertTrue(self.window.navigation.isEnabled())

    def test_back_up_later_then_confirmed_departure_clears_and_locks(self):
        self._show_required()
        with _DialogDriver(self.app, "leave") as driver:
            self.page._back_up_later.click()
        self.app.processEvents()
        self.assertEqual(len(driver.seen), 1)
        self._assert_left_fail_closed()

    def test_window_close_then_stay_keeps_window_and_words(self):
        self._show_required()
        self.window.show()
        self.app.processEvents()
        with _DialogDriver(self.app, "stay") as driver:
            self.window.close()
        self.app.processEvents()
        self.assertEqual(len(driver.seen), 1)
        self.assertTrue(self.window.isVisible())
        self.assertNotIn("quit", self.window.executor.requests)
        self._assert_phrase_preserved()

    def test_window_close_then_confirmed_departure_defers_and_quits(self):
        self._show_required()
        self.window.show()
        self.app.processEvents()
        with _DialogDriver(self.app, "leave") as driver:
            self.window.close()
        self.app.processEvents()
        self.assertEqual(len(driver.seen), 1)
        self.assertTrue(self.window._quit_requested)
        self._assert_left_fail_closed()

    def test_quit_request_then_stay_and_then_confirmed_departure(self):
        self._show_required()
        with _DialogDriver(self.app, "stay") as driver:
            self.window.request_quit()
        self.assertEqual(len(driver.seen), 1)
        self._assert_phrase_preserved()
        with _DialogDriver(self.app, "leave") as driver:
            self.window.request_quit()
        self.app.processEvents()
        self.assertEqual(len(driver.seen), 1)
        self.assertTrue(self.window._quit_requested)
        self._assert_left_fail_closed()

    def test_verification_page_escape_returns_to_words_without_deferral(self):
        self._show_required()
        self._to_verify_page()
        with _DialogDriver(self.app, "leave") as driver:
            QTest.keyClick(self.page, Qt.Key.Key_Escape)
        self.assertEqual(driver.seen, [], "Escape here is Back, never a departure")
        self.assertIsNone(self.page._challenge_id)
        self.assertIsNone(self.window.executor.challenge)
        self._assert_phrase_preserved()

    def test_verification_page_close_needs_confirmation_while_words_are_held(self):
        self._show_required()
        self._to_verify_page()
        with _DialogDriver(self.app, "stay") as driver:
            self.window.request_quit()
        self.assertEqual(len(driver.seen), 1)
        self._assert_phrase_preserved(self.page._verify_page)
        with _DialogDriver(self.app, "leave") as driver:
            self.window.request_quit()
        self.app.processEvents()
        self.assertEqual(len(driver.seen), 1)
        self._assert_left_fail_closed()

    def test_repeated_escape_and_reentrant_prompt_never_leave(self):
        self._show_required()
        nested = []

        def prompt():
            # A second request while the confirmation is open must not leave.
            nested.append(self.page.confirm_departure())
            QTest.keyClick(self.page, Qt.Key.Key_Escape)
            return False

        self.page._departure_prompt = prompt
        QTest.keyClick(self.page, Qt.Key.Key_Escape)
        QTest.keyClick(self.page, Qt.Key.Key_Escape)
        self.assertEqual(nested, [False, False])
        self._assert_phrase_preserved()

    def test_prompt_failure_keeps_the_words(self):
        self._show_required()

        def broken():
            raise RuntimeError("PUBLIC_TEST_PROMPT_FAILURE")

        self.page._departure_prompt = broken
        QTest.keyClick(self.page, Qt.Key.Key_Escape)
        self.page._back_up_later.click()
        self.window.request_quit()
        self._assert_phrase_preserved()

    def test_repeated_deferral_signal_is_sent_to_backend_once(self):
        self._show_required()
        with _DialogDriver(self.app, "leave"):
            self.page._back_up_later.click()
        self.app.processEvents()
        self._assert_left_fail_closed()
        self.page.deferred_requested.emit()
        self.page.deferred_requested.emit()
        self.window._defer_active_backup()
        self.app.processEvents()
        self._assert_left_fail_closed()

    def test_no_words_in_output_status_or_prompt(self):
        captured_out, captured_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):
            self._show_required()
            with _DialogDriver(self.app, "stay") as stay:
                QTest.keyClick(self.page, Qt.Key.Key_Escape)
            with _DialogDriver(self.app, "leave") as leave:
                self.page._back_up_later.click()
            self.app.processEvents()
        self.assertEqual(captured_out.getvalue(), "")
        self.assertEqual(captured_err.getvalue(), "")
        surfaces = [self.window.status.text(), self.window.status.toolTip(),
                    self.window.windowTitle(), self.window.connection_pill.text()]
        for seen in stay.seen + leave.seen:
            surfaces.extend(seen["texts"])
        for surface in surfaces:
            self.assertNotIn(_DISPLAY_PHRASE_WORDS, surface)
        for word in _WORDS:
            self.assertNotIn(word, self.window.status.text())
        # No executor request ever carried the phrase.
        self.assertEqual(
            [r for r in self.window.executor.log if _DISPLAY_PHRASE_WORDS in repr(r)], [])


class VerifiedAcknowledgementContract(_BackupSafetyCase):
    """D2: a verified acknowledgement never regresses through navigation."""

    def _assert_still_verified(self):
        self.assertEqual(self._defers(), 0)
        self.assertEqual(self.window.executor.marker, (True, False))
        self.assertTrue(self.window.executor.verified)
        self.assertFalse(self.window.executor.locked)

    def test_escape_on_success_page_does_nothing(self):
        self._show_required()
        self._to_success_page()
        with _DialogDriver(self.app, "leave") as driver:
            for _ in range(3):
                QTest.keyClick(self.page, Qt.Key.Key_Escape)
                QTest.keyClick(self.page._continue_button, Qt.Key.Key_Escape)
        self.app.processEvents()
        self.assertEqual(driver.seen, [])
        self._assert_still_verified()
        self.assertIs(self.page._stack.currentWidget(), self.page._success_page)
        self.assertTrue(self.window._backup_flow_active)
        self.page._continue_button.click()
        self.app.processEvents()
        self.assertTrue(self.window._ready)
        self.assertFalse(self.window._backup_unacked)
        self._assert_still_verified()

    def test_window_close_on_success_page_keeps_verified(self):
        self._show_required()
        self._to_success_page()
        self.window.show()
        self.app.processEvents()
        with _DialogDriver(self.app, "leave") as driver:
            self.window.close()
        self.app.processEvents()
        self.assertEqual(driver.seen, [], "nothing left to protect: no prompt")
        self.assertTrue(self.window._quit_requested)
        self.assertFalse(self.window._backup_unacked)
        self._assert_still_verified()

    def test_quit_and_stray_deferral_signals_keep_verified(self):
        self._show_required()
        self._to_success_page()
        self.page.deferred_requested.emit()
        self.app.processEvents()
        self._assert_still_verified()
        self.assertTrue(self.window._ready)
        self.page.deferred_requested.emit()
        self.window._defer_active_backup()
        self.window.request_quit()
        self.app.processEvents()
        self._assert_still_verified()
        self.assertFalse(self.window._backup_unacked)

    def test_verified_flag_resets_for_the_next_flow(self):
        self._show_required()
        self._to_success_page()
        self.assertTrue(self.window._backup_verified)
        self.page._continue_button.click()
        self.app.processEvents()
        self.window._on_ready("lock", None)
        self.assertFalse(self.window._backup_verified)
        self.window.executor.requests.clear()
        self.window.executor.marker = (False, True)
        self._show_deferred()
        self.assertFalse(self.window._backup_verified)
        self.window.request_quit()
        self.app.processEvents()
        # An unverified deferred flow still defers and locks on quit.
        self.assertEqual(self._defers(), 1)
        self.assertTrue(self.window._backup_unacked)


class DeferredReopenContract(_BackupSafetyCase):
    """A deferred profile stays fail-closed; Escape gives no way around it."""

    def test_escape_in_deferred_verification_changes_nothing(self):
        self._show_deferred()
        self.assertEqual(self._word_count(), 0)
        with _DialogDriver(self.app, "leave") as driver:
            QTest.keyClick(self.page, Qt.Key.Key_Escape)
            QTest.keyClick(self.page._verify_inputs[0], Qt.Key.Key_Escape)
        self.app.processEvents()
        self.assertEqual(driver.seen, [])
        self.assertEqual(self._defers(), 0)
        self.assertIs(self.window.stack.currentWidget(), self.page)
        self.assertIs(self.page._stack.currentWidget(), self.page._verify_page)
        self.assertFalse(self.window._ready)
        self.assertFalse(self.window.navigation.isEnabled())
        self.assertFalse(self.window.send.isEnabled())

    def test_close_in_deferred_verification_defers_without_prompt(self):
        self._show_deferred()
        with _DialogDriver(self.app, "stay") as driver:
            self.window.request_quit()
        self.app.processEvents()
        self.assertEqual(driver.seen, [], "no words are on screen to protect")
        self.assertEqual(self._defers(), 1)
        self.assertTrue(self.window.executor.locked)
        self.assertTrue(self.window._backup_unacked)
        self.assertFalse(self.window._ready)

    def test_wrong_words_in_deferred_verification_stay_locked(self):
        self._show_deferred()
        for edit in self.page._verify_inputs:
            edit.setText("wrong")
        self.page._verify_button.click()
        self.app.processEvents()
        self.assertFalse(self.window._backup_verified)
        self.assertFalse(self.window._ready)
        self.assertIs(self.window.stack.currentWidget(), self.page)


class DeferralFailureContract(_BackupSafetyCase):
    stub = _DeferFailsStub

    def test_acknowledgement_write_failure_still_fails_closed(self):
        self._show_required()
        with _DialogDriver(self.app, "leave"):
            self.page._back_up_later.click()
        self.app.processEvents()
        self.assertEqual(self._defers(), 1)
        self.assertEqual(self._word_count(), 0)
        self.assertTrue(self.window._backup_unacked)
        self.assertFalse(self.window._ready)
        self.assertFalse(self.window._unlock_allowed)
        self.assertFalse(self.window.send.isEnabled())
        for word in _WORDS:
            self.assertNotIn(word, self.window.status.text())
        self.assertNotIn("PUBLIC_TEST_ACK_WRITE_FAILURE", self.window.status.text())


class VerificationFailureContract(_BackupSafetyCase):
    stub = _VerifyFailsStub

    def test_refused_verification_is_not_treated_as_verified(self):
        self._show_required()
        self._to_verify_page()
        for edit, position in zip(self.page._verify_inputs, self.page._challenge_positions):
            edit.setText(_WORDS[position - 1])
        self.page._verify_button.click()
        self.app.processEvents()
        self.assertFalse(self.window._backup_verified)
        self.assertIs(self.page._stack.currentWidget(), self.page._verify_page)
        self.assertTrue(self.page.holds_unverified_phrase())
        # Interrupted verification: leaving still needs the confirmation and
        # still defers, because nothing was acknowledged.
        with _DialogDriver(self.app, "stay") as driver:
            self.window.request_quit()
        self.assertEqual(len(driver.seen), 1)
        self.assertEqual(self._defers(), 0)
        with _DialogDriver(self.app, "leave"):
            self.window.request_quit()
        self.app.processEvents()
        self.assertEqual(self._defers(), 1)
        self.assertTrue(self.window._backup_unacked)
        self.assertFalse(self.window._ready)


if __name__ == "__main__":
    unittest.main()
