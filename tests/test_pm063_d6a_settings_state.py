"""PM-063 D6-A characterization tests for Settings, Security, preferences & error privacy."""

from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from PySide6.QtCore import QEventLoop, QSettings, QTimer
from PySide6.QtWidgets import QApplication, QWidget

from wam_regtest import bip39_locale, ui_settings
from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
from wam_regtest.bip39_locale import t
from wam_regtest.fusion_motion import motion_reduced
from wam_regtest.infrastructure import core_compat
from wam_regtest.managed_gui import ControlWorker
from wam_regtest.wallet_executor import WalletExecutor, WalletExecutorError


SECRET_SENTINEL = "WAM_SECRET_SENTINEL_x9k2m7"
PATH_SENTINEL = "/Users/owner_private/wallets/regtest-seed.sqlite"
COOKIE_SENTINEL = "Cookie: __Host-wam-rpc=auth_cookie_deadbeef99"


class _HostileError(RuntimeError):
    """Exception carrying secret, path, and cookie sentinels if str() is called."""

    def __str__(self) -> str:
        return f"{SECRET_SENTINEL} path={PATH_SENTINEL} {COOKIE_SENTINEL}"


class _PassiveBackend:
    """In-memory WalletExecutor backend without touching disk or Core."""

    core_alive = True
    locked = True
    faulted = False

    def public_state(self) -> dict[str, bool]:
        return {
            "locked": self.locked,
            "faulted": self.faulted,
            "core_alive": self.core_alive,
        }

    def execute(self, action: str, args: tuple, kwargs: dict):
        if action == "quit":
            self.core_alive = False
        elif action == "lock":
            self.locked = True
        return None


def _qt_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@contextmanager
def _isolated_ini(env_overrides: dict[str, str] | None = None):
    """Bind PM-016 isolated INI settings under a temporary path cleanly."""
    with tempfile.TemporaryDirectory(prefix="wam-pm063-ini-") as tmp:
        ini_path = Path(tmp) / "pm063-ui-settings.ini"
        patch_env = {
            ui_settings.ENV_PATH: str(ini_path),
            "GITHUB_ACTIONS": "false",
        }
        if env_overrides:
            patch_env.update(env_overrides)
        with patch.dict(os.environ, patch_env, clear=False):
            assert ui_settings.native_store_enabled() is False, (
                "PM-016 native preference store must be disabled in isolated tests"
            )
            yield ini_path


def _snapshot_ini(ini_path: Path) -> dict[str, object]:
    """Read all key/value pairs from the isolated INI store only."""
    store = QSettings(str(ini_path), QSettings.Format.IniFormat)
    return {key: store.value(key) for key in store.allKeys()}


def _make_window(backend: object | None = None) -> tuple[Bip39FusionWindow, WalletExecutor, object]:
    _qt_app()
    be = backend or _PassiveBackend()
    executor = WalletExecutor(lambda: be)
    window = Bip39FusionWindow(executor)
    window._poll.stop()
    return window, executor, be


def _close_window(window: Bip39FusionWindow, executor: WalletExecutor) -> None:
    window._poll.stop()
    window.close()
    window.deleteLater()
    try:
        WalletExecutor.request(executor, "quit", timeout=5)
    except Exception:
        pass
    executor.join(5)
    QApplication.processEvents()


def _set_executor_state(executor: WalletExecutor, **changes: object) -> None:
    with executor._guard:
        executor._state = replace(executor._state, **changes)


def _widget_surface_strings(root: QWidget) -> list[tuple[str, str, str]]:
    """Collect (widget_name, surface, value) across visible text, tooltip, and a11y."""
    entries: list[tuple[str, str, str]] = []
    widgets = [root, *root.findChildren(QWidget)]
    for widget in widgets:
        name = widget.objectName() or type(widget).__name__
        for surface, accessor in (
            ("text", getattr(widget, "text", None)),
            ("placeholderText", getattr(widget, "placeholderText", None)),
            ("plainText", getattr(widget, "toPlainText", None)),
            ("currentText", getattr(widget, "currentText", None)),
            ("toolTip", widget.toolTip),
            ("accessibleName", widget.accessibleName),
            ("accessibleDescription", widget.accessibleDescription),
        ):
            if callable(accessor):
                val = accessor()
                if isinstance(val, str) and val:
                    entries.append((name, surface, val))
    return entries


def _assert_no_sentinels(test_case: unittest.TestCase, window: Bip39FusionWindow) -> None:
    for sentinel in (SECRET_SENTINEL, PATH_SENTINEL, COOKIE_SENTINEL):
        for name, surface, val in _widget_surface_strings(window):
            test_case.assertNotIn(
                sentinel,
                val,
                f"Hostile sentinel leaked into {name}.{surface}: {val!r}",
            )
        if window._last_error_code is not None:
            test_case.assertNotIn(sentinel, str(window._last_error_code))


class SettingsIsolationAndKeysTests(unittest.TestCase):
    """Pin PM-016 isolation, preference keys, theme/language/motion behavior."""

    def test_pm016_isolation_active_in_tests(self):
        with _isolated_ini() as ini_path:
            self.assertFalse(ui_settings.native_store_enabled())
            self.assertEqual(Path(ui_settings.isolated_path()), ini_path)
            settings = ui_settings.ui_settings()
            self.assertEqual(settings.format(), QSettings.Format.IniFormat)
            self.assertEqual(Path(settings.fileName()), ini_path)

    def test_preference_defaults_and_invalid_values(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}) as ini_path:
            self.assertFalse(ui_settings.native_store_enabled())
            self.assertEqual(bip39_locale.stored_language(), "system")
            self.assertEqual(bip39_locale.effective_choice(), "en")
            # Corrupted appearance & unsupported language do not crash or overwrite store.
            store = ui_settings.ui_settings()
            store.setValue("fusion_appearance", 99)
            store.setValue("ui_language", "xx-Unsupported")
            store.sync()
            self.assertEqual(bip39_locale.effective_choice(), "system")

            window, executor, _ = _make_window()
            try:
                self.assertFalse(hasattr(window, 'header_theme'))
                self.assertEqual(window.settings_theme.currentIndex(), 0)
                self.assertEqual(window.language.currentData(), "system")
                self.assertFalse(window.reduce_motion.isChecked())
                after = _snapshot_ini(ini_path)
                self.assertEqual(int(after["fusion_appearance"]), 99)
                self.assertEqual(after["ui_language"], "xx-Unsupported")
            finally:
                _close_window(window, executor)

    def test_theme_choice_writes_only_fusion_appearance_and_syncs_sliders(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}) as ini_path:
            self.assertFalse(ui_settings.native_store_enabled())
            window, executor, _ = _make_window()
            try:
                baseline = _snapshot_ini(ini_path)
                # PM-103 defaults Dark; first choose Light so this is a real change.
                window.settings_theme.buttons[1].click()
                baseline = _snapshot_ini(ini_path)
                window.settings_theme.buttons[2].click()
                QApplication.processEvents()
                self.assertEqual(window.settings_theme.currentIndex(), 2)
                after_dark = _snapshot_ini(ini_path)
                self.assertEqual(int(after_dark["fusion_appearance"]), 2)
                changed = {
                    k for k in set(baseline) | set(after_dark)
                    if baseline.get(k) != after_dark.get(k)
                }
                self.assertEqual(changed, {"fusion_appearance"})

                # Settings is the only theme control: Light (1) then Automatic (0).
                window.settings_theme.buttons[1].click()
                QApplication.processEvents()
                self.assertEqual(window.settings_theme.currentIndex(), 1)
                self.assertEqual(int(_snapshot_ini(ini_path)["fusion_appearance"]), 1)

                window.settings_theme.buttons[0].click()
                QApplication.processEvents()
                self.assertEqual(window.settings_theme.currentIndex(), 0)
                self.assertEqual(int(_snapshot_ini(ini_path)["fusion_appearance"]), 0)
            finally:
                _close_window(window, executor)

    def test_language_choice_writes_only_ui_language_with_next_window_semantics(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}) as ini_path:
            self.assertFalse(ui_settings.native_store_enabled())
            window, executor, _ = _make_window()
            try:
                initial_toggle_text = window.advanced_toggle.text()
                initial_lang_label = window.language.accessibleName()
                baseline = _snapshot_ini(ini_path)

                vi_index = window.language.findData("vi")
                self.assertGreaterEqual(vi_index, 0)
                window.language.setCurrentIndex(vi_index)
                QApplication.processEvents()

                after = _snapshot_ini(ini_path)
                self.assertEqual(after.get("ui_language"), "vi")
                changed = {
                    k for k in set(baseline) | set(after)
                    if baseline.get(k) != after.get(k)
                }
                self.assertEqual(changed, {"ui_language"})

                # The same window re-renders immediately. Persistence stays ui_language only.
                from wam_regtest.presentation.strings import text
                self.assertEqual(window.advanced_toggle.text(), text('wallet.show_developer', 'vi'))
                self.assertEqual(window.language.accessibleName(), text('settings.language', 'vi'))
                self.assertNotEqual(window.advanced_toggle.text(), initial_toggle_text)
                self.assertNotEqual(window.language.accessibleName(), initial_lang_label)
                self.assertEqual(bip39_locale.effective_choice(), "vi")
            finally:
                _close_window(window, executor)

    def test_reduce_motion_toggle_writes_only_fusion_reduce_motion(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}) as ini_path:
            self.assertFalse(ui_settings.native_store_enabled())
            window, executor, _ = _make_window()
            try:
                self.assertFalse(window.reduce_motion.isChecked())
                self.assertFalse(motion_reduced(window))
                baseline = _snapshot_ini(ini_path)

                window.reduce_motion.setChecked(True)
                QApplication.processEvents()
                self.assertTrue(window.property("fusion_reduce_motion"))
                self.assertTrue(motion_reduced(window))
                after = _snapshot_ini(ini_path)
                self.assertIn(after.get("fusion_reduce_motion"), (True, "true", "True"))
                changed = {
                    k for k in set(baseline) | set(after)
                    if baseline.get(k) != after.get(k)
                }
                self.assertEqual(changed, {"fusion_reduce_motion"})

                # Check GITHUB_ACTIONS="true" also forces motion_reduced in memory.
                window.reduce_motion.setChecked(False)
                QApplication.processEvents()
                self.assertFalse(motion_reduced(window))
                with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=False):
                    self.assertTrue(motion_reduced(window))
            finally:
                _close_window(window, executor)

    def test_settings_security_advanced_static_widget_inventory(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            window, executor, _ = _make_window()
            try:
                self.assertFalse(window.advanced_toggle.isChecked())
                self.assertTrue(window.advanced_container.isHidden())
                self.assertTrue(window.last_txid.isReadOnly())
                self.assertTrue(window.lock.isHidden())
                self.assertTrue(window.unlock.isHidden())
                self.assertFalse(window.custody_switch.isChecked())
                self.assertFalse(window.custody_switch.isEnabled())
                self.assertTrue(window.quit.isEnabled())
                self.assertIsNot(window.backup_review, window.recovery)
                self.assertTrue(window.backup_review.isEnabled())  # PM-063 original contract: backup review enabled
                # The backup-review control is connected to the WalletConsent
                # flow: clicking it creates the consent dialog (proof the slot
                # is live, not an accessibleDescription side-effect).
                from wam_regtest import bip39_fusion_gui
                from PySide6.QtWidgets import QDialog

                class _Consent(QDialog):
                    created = False

                    def __init__(self, *args, **kwargs):
                        super().__init__()
                        _Consent.created = True

                    def exec(self):
                        return QDialog.DialogCode.Rejected

                with patch.object(bip39_fusion_gui, 'WalletConsent', _Consent):
                    window.backup_review.click()
                self.assertTrue(_Consent.created)
                self.assertFalse(window.recovery.isEnabled())
                self.assertEqual(window.security_state.text(), t("wallet.security_locked"))

                surfaces = [val for _, _, val in _widget_surface_strings(window)]
                self.assertTrue(
                    any(core_compat.DISPLAY_NAME in text for text in surfaces),
                    "Settings About panel should display core_compat.DISPLAY_NAME",
                )
            finally:
                _close_window(window, executor)


class SettingsReduceMotionEnvDefectTests(unittest.TestCase):
    """Pin D6A-1: QT_REDUCE_MOTION=1 writes fusion_reduce_motion during __init__."""

    def test_qt_reduce_motion_env_does_not_write_preference_on_open(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "1"}) as ini_path:
            self.assertFalse(ui_settings.native_store_enabled())
            store = ui_settings.ui_settings()
            store.setValue("fusion_reduce_motion", False)
            store.sync()

            window, executor, _ = _make_window()
            try:
                self.assertTrue(motion_reduced(window))
                after = _snapshot_ini(ini_path)
                # Spec D6 §5 & §8.4: environment-forced reduced motion must not mutate user's pref.
                self.assertIn(
                    after.get("fusion_reduce_motion"),
                    (False, "false", "False"),
                    f"QT_REDUCE_MOTION=1 overwrote fusion_reduce_motion: {after!r}",
                )
            finally:
                _close_window(window, executor)

    def test_user_toggle_still_persists_reduce_motion_preference(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}) as ini_path:
            self.assertFalse(ui_settings.native_store_enabled())
            window, executor, _ = _make_window()
            try:
                window.reduce_motion.setChecked(True)
                QApplication.processEvents()
                self.assertIn(
                    _snapshot_ini(ini_path).get("fusion_reduce_motion"),
                    (True, "true", "True"),
                )
                window.reduce_motion.setChecked(False)
                QApplication.processEvents()
                self.assertIn(
                    _snapshot_ini(ini_path).get("fusion_reduce_motion"),
                    (False, "false", "False"),
                )
            finally:
                _close_window(window, executor)


class HostileErrorPrivacyTests(unittest.TestCase):
    """Pin error/diagnostic privacy across visible text, tooltip, and accessible text."""

    def _hostile_message(self) -> str:
        return f"{SECRET_SENTINEL} path={PATH_SENTINEL} {COOKIE_SENTINEL}"

    def test_control_worker_and_on_denied_never_expose_hostile_exception(self):
        hostile_msg = self._hostile_message()

        class _FailingBackend(_PassiveBackend):
            def execute(self, action, args, kwargs):
                if action == "snapshot":
                    raise _HostileError(hostile_msg)
                return super().execute(action, args, kwargs)

        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            window, executor, _ = _make_window(_FailingBackend())
            try:
                denied_codes: list[str] = []
                loop = QEventLoop()
                worker = ControlWorker(executor, "snapshot", (), parent=window)
                worker.denied.connect(lambda c: (denied_codes.append(c), loop.quit()))
                QTimer.singleShot(3000, loop.quit)
                worker.start()
                loop.exec()
                worker.wait(2000)

                self.assertEqual(len(denied_codes), 1)
                self.assertEqual(denied_codes[0], "WALLET_OPERATION_DENIED_STATE_RETAINED")

                window._on_denied(denied_codes[0])
                QApplication.processEvents()
                _assert_no_sentinels(self, window)
                self.assertEqual(window._last_error_code, "WALLET_OPERATION_DENIED_STATE_RETAINED")
                self.assertEqual(window.status.toolTip(), window.status.text())

                # Direct hostile string / ValueError / WalletExecutorError never leak sentinels.
                from wam_regtest.gui_errors import operation_error
                for err in (
                    ValueError(hostile_msg),
                    WalletExecutorError(hostile_msg),
                ):
                    window._on_denied(operation_error("snapshot", err))
                    QApplication.processEvents()
                    _assert_no_sentinels(self, window)
                    self.assertEqual(window._last_error_code, "WALLET_OPERATION_DENIED_STATE_RETAINED")

                window._on_denied(hostile_msg)
                QApplication.processEvents()
                _assert_no_sentinels(self, window)
                self.assertEqual(window._last_error_code, "WALLET_OPERATION_DENIED_STATE_RETAINED")

                # Allowlisted public code passes cleanly.
                window._on_denied("WALLET_BROADCAST_REJECTED_LOCK_RETAINED")
                QApplication.processEvents()
                self.assertEqual(window._last_error_code, "WALLET_BROADCAST_REJECTED_LOCK_RETAINED")
            finally:
                _close_window(window, executor)

    def test_backup_error_handlers_never_expose_hostile_exception(self):
        hostile_msg = self._hostile_message()

        class _FailingExecutor(WalletExecutor):
            def request(self, action, *args, timeout=30):
                raise _HostileError(hostile_msg)

        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            _qt_app()
            executor = _FailingExecutor(lambda: _PassiveBackend())
            window = Bip39FusionWindow(executor)
            window._poll.stop()
            try:
                window._on_backup_challenge()
                _assert_no_sentinels(self, window)
                self.assertEqual(window._last_error_code, "WALLET_OPERATION_DENIED_STATE_RETAINED")
                self.assertEqual(window.status.text(), t("wallet.backup_verify_unavailable"))

                window._on_backup_challenge_cancel()
                _assert_no_sentinels(self, window)
                self.assertEqual(window._last_error_code, "WALLET_OPERATION_DENIED_STATE_RETAINED")

                window._on_backup_verify("id-1", {1: "abandon"})
                _assert_no_sentinels(self, window)
                self.assertEqual(window._last_error_code, "WALLET_OPERATION_DENIED_STATE_RETAINED")

                window._backup_flow_active = True
                window._backup_verified = False
                window._defer_active_backup()
                _assert_no_sentinels(self, window)
                self.assertEqual(window._last_error_code, "WALLET_OPERATION_DENIED_STATE_RETAINED")
                self.assertEqual(window.status.text(), t("wallet.backup_defer_unavailable"))
            finally:
                _close_window(window, executor)

    def test_acknowledge_create_pending_and_prepare_send_never_expose_hostile_message(self):
        hostile_msg = self._hostile_message()

        class _AckFailExecutor(WalletExecutor):
            def request(self, action, *args, timeout=30):
                if action == "acknowledge_create_pending":
                    raise _HostileError(hostile_msg)
                return super().request(action, *args, timeout=timeout)

        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            _qt_app()
            executor = _AckFailExecutor(lambda: _PassiveBackend())
            window = Bip39FusionWindow(executor)
            window._poll.stop()
            try:
                window._on_ready(
                    "open",
                    {"backup_status": "required", "seed_folder": "/tmp/fake-seed"},
                )
                QApplication.processEvents()
                _assert_no_sentinels(self, window)
                self.assertIn(
                    "WALLET_OPERATION_DENIED_STATE_RETAINED",
                    window.status.text().replace("\u200b", ""),
                )

                # Hostile strings in send inputs also never echo into status/tooltip/a11y.
                window._spend_enabled = True
                _set_executor_state(executor, faulted=False)
                window.recipient_input.setText(hostile_msg)
                window.amount_input.setText(f"not-amount-{COOKIE_SENTINEL}")
                window._prepare_send()
                QApplication.processEvents()
                _assert_no_sentinels(self, window)
            finally:
                _close_window(window, executor)


if __name__ == "__main__":
    unittest.main()
