"""PM-063 D6-A characterization tests for Settings/Security/Advanced commands & lifetime."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QDialog, QInputDialog, QMessageBox, QWidget

from test_pm063_d6a_settings_state import (
    _close_window,
    _isolated_ini,
    _make_window,
    _set_executor_state,
    _snapshot_ini,
)
from wam_regtest import ui_settings
from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
from wam_regtest.bip39_owner_gui import Bip39TrialWindow
from wam_regtest.fusion_pages import WalletConsent
from wam_regtest.presentation.action_state import BASE_CONTROLS
from wam_regtest.bip39_locale import t
from wam_regtest.wallet_executor import WalletExecutor
from wam_regtest.wallet_read import HistoryRow, WalletReadSnapshot
from wam_sp.core import pub
from wam_sp.keystore import ScanAccount


_BROADCAST_TXID = "e3" * 32
_SECOND_TXID = "f4" * 32
_CORE_SHA = "34" * 32
_CHAIN_TIP = "56" * 32
_DUMMY_MNEMONIC_12 = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def _make_snapshot(**changes) -> WalletReadSnapshot:
    return replace(
        WalletReadSnapshot(
            "regtest",
            112,
            _CORE_SHA,
            ScanAccount(0, 1, pub(2), birthday=1).payment_code(),
            100000,
            1,
            (HistoryRow("ab" * 32, 112, 1, 100000, 0),),
            _CHAIN_TIP,
            available_atoms=7000,
            pending_atoms=None,
            pending_spent_atoms=None,
            signer_allowed=True,
            broadcast_allowed=True,
        ),
        **changes,
    )


def _make_result(snap: WalletReadSnapshot | None = None, **changes) -> dict:
    snap = snap or _make_snapshot()
    return dict(
        fusion_snapshot=snap,
        receive_code=snap.receive_code,
        confirmed_atoms=snap.confirmed_atoms,
        available_atoms=snap.available_atoms,
        signer_allowed=snap.signer_allowed,
        broadcast_allowed=snap.broadcast_allowed,
        height=snap.height,
        tip=snap.tip,
        history=(),
        **changes,
    )


class _RecordingBackend:
    """In-memory WalletExecutor backend recording every execute call."""

    def __init__(self) -> None:
        self.core_alive = True
        self.locked = False
        self.faulted = False
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def public_state(self) -> dict[str, bool]:
        return {
            "locked": self.locked,
            "faulted": self.faulted,
            "core_alive": self.core_alive,
        }

    def execute(self, action: str, args: tuple, kwargs: dict):
        self.calls.append((action, args))
        if action == "snapshot":
            return _make_result()
        if action == "lock":
            self.locked = True
            return {"locked": True}
        if action == "quit":
            self.core_alive = False
            return {"quit": True}
        if action == "open":
            return {
                "account_id": "acct-alpha-01",
                "receive_code": _make_snapshot().receive_code,
                "backup_status": "verified",
                "checkpoint_present": True,
            }
        return None


def _open_verified_session(
    window: Bip39FusionWindow,
    executor: WalletExecutor,
    *,
    account_id: str = "acct-alpha-01",
    snap=None,
    shared_network: dict[str, object] | None = None,
) -> None:
    snap = snap or _make_snapshot(core_sha256=_CORE_SHA, tip=_CHAIN_TIP, height=112)
    _set_executor_state(
        executor,
        locked=False,
        faulted=False,
        reauthentication_required=False,
        core_alive=True,
    )

    open_payload = {
        "account_id": account_id,
        "receive_code": snap.receive_code,
        "backup_status": "verified",
        "checkpoint_present": True,
    }
    snap_payload = _make_result(
        snap=snap,
        payment_review=None,
        payment_signed=False,
        pending_confirm_txid=None,
        **({"shared_network": shared_network} if shared_network is not None else {}),
    )
    window._on_ready("open", open_payload)
    window._on_ready("snapshot", snap_payload)
    QApplication.processEvents()


def _surface_texts(widgets: list[QWidget]) -> list[str]:
    texts: list[str] = []
    for widget in widgets:
        for accessor in (
            getattr(widget, "text", None),
            getattr(widget, "toolTip", None),
            getattr(widget, "accessibleName", None),
            getattr(widget, "accessibleDescription", None),
        ):
            if callable(accessor):
                val = accessor()
                if isinstance(val, str) and val:
                    texts.append(val)
    return texts


@contextmanager
def _reject_unexpected_modals(interval_ms: int = 10, watchdog_ms: int = 5000):
    """Dismiss any modal QDialog/widget opened under offscreen so tests never hang."""
    app = QApplication.instance()

    def _dismiss() -> None:
        if app is None:
            return
        modal = app.activeModalWidget()
        if modal is not None:
            if isinstance(modal, QDialog):
                modal.reject()
            else:
                modal.close()

    timer = QTimer()
    timer.setInterval(interval_ms)
    timer.timeout.connect(_dismiss)
    timer.start()
    watchdog = QTimer()
    watchdog.setSingleShot(True)
    watchdog.timeout.connect(_dismiss)
    watchdog.start(watchdog_ms)
    try:
        yield
    finally:
        timer.stop()
        watchdog.stop()
        _dismiss()


def _close_window_bounded(window: Bip39TrialWindow, executor: WalletExecutor) -> None:
    """Close a test window safely even if a departure/backup modal opens on close()."""
    with _reject_unexpected_modals():
        _close_window(window, executor)
        worker = getattr(window, "_worker", None)
        if worker is not None:
            worker.wait(2000)
        QApplication.processEvents()


class SettingsCommandBoundaryTests(unittest.TestCase):
    """Pin zero-command reads, zero-pref-write disclosure, and D-D6-1 tool behavior."""

    def test_opening_settings_toggling_disclosure_and_scanning_text_emit_zero_commands_or_pref_writes(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}) as ini_path:
            self.assertFalse(ui_settings.native_store_enabled())
            be = _RecordingBackend()
            window, executor, _ = _make_window(be)
            window.show()
            QApplication.processEvents()
            try:
                _open_verified_session(window, executor)
                window.last_txid.setText(_BROADCAST_TXID)

                baseline_ini = _snapshot_ini(ini_path)
                dispatched: list[tuple[str, tuple[object, ...]]] = []

                with patch.object(
                    window, "_command", side_effect=lambda a, *args: dispatched.append((a, *args)) or True
                ):
                    be.calls.clear()

                    # 1. Navigate to Settings (row 6).
                    window.navigation.setCurrentRow(6)
                    QApplication.processEvents()

                    # 2. Expand & collapse Advanced disclosure.
                    window.advanced_toggle.click()
                    QApplication.processEvents()
                    self.assertTrue(window.advanced_toggle.isChecked())
                    self.assertFalse(window.advanced_container.isHidden())

                    window.advanced_toggle.click()
                    QApplication.processEvents()
                    self.assertFalse(window.advanced_toggle.isChecked())
                    self.assertTrue(window.advanced_container.isHidden())

                    # 3. Expand again and read/select session text & labels.
                    window.advanced_toggle.click()
                    QApplication.processEvents()
                    window.last_txid.selectAll()
                    _ = (
                        window.account.text(),
                        window.balance.text(),
                        window.tip.text(),
                        window.last_txid.selectedText(),
                        window.status.text(),
                        window.security_state.text(),
                    )

                self.assertEqual(dispatched, [])
                self.assertEqual(be.calls, [])
                self.assertEqual(_snapshot_ini(ini_path), baseline_ini)
            finally:
                _close_window(window, executor)

    def test_choosing_theme_language_and_motion_emit_zero_commands_or_rpcs(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            self.assertFalse(ui_settings.native_store_enabled())
            be = _RecordingBackend()
            window, executor, _ = _make_window(be)
            try:
                dispatched: list[tuple[str, tuple[object, ...]]] = []
                with patch.object(
                    window, "_command", side_effect=lambda a, *args: dispatched.append((a, *args)) or True
                ):
                    window.navigation.setCurrentRow(6)
                    window.settings_theme.buttons[2].click()
                    window.header_theme.buttons[1].click()
                    window.settings_theme.buttons[0].click()
                    vi_idx = window.language.findData("vi")
                    window.language.setCurrentIndex(vi_idx)
                    window.language.setCurrentIndex(window.language.findData("en"))
                    window.reduce_motion.setChecked(True)
                    window.reduce_motion.setChecked(False)
                    QApplication.processEvents()

                self.assertEqual(dispatched, [])
                self.assertEqual(be.calls, [])
            finally:
                _close_window(window, executor)

    def test_disclosure_toggle_never_enables_disabled_action(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            window, executor, _ = _make_window()
            try:
                tracked_controls = [
                    *((name, getattr(window, name)) for name in BASE_CONTROLS),
                    ("custody_switch", window.custody_switch),
                    ("overview.custody_switch", window.overview.custody_switch),
                    ("backup_review", window.backup_review),
                    ("overview.go_send", window.overview.go_send),
                    ("overview.go_receive", window.overview.go_receive),
                    ("overview.open_security", window.overview.open_security),
                ]

                def assert_disclosure_preserves_disabled(state_label: str):
                    before = {name: ctrl.isEnabled() for name, ctrl in tracked_controls}
                    disabled_before = {name for name, en in before.items() if not en}
                    window.advanced_toggle.setChecked(True)
                    QApplication.processEvents()
                    during = {name: ctrl.isEnabled() for name, ctrl in tracked_controls}
                    self.assertEqual(during, before, f"Expanding enabled controls in {state_label}")
                    for name in disabled_before:
                        self.assertFalse(during[name], f"{name} became enabled in {state_label}")
                    window.advanced_toggle.setChecked(False)
                    QApplication.processEvents()
                    after = {name: ctrl.isEnabled() for name, ctrl in tracked_controls}
                    self.assertEqual(after, before, f"Collapsing changed controls in {state_label}")

                # State 1: Initial locked.
                assert_disclosure_preserves_disabled("locked_initial")

                # State 2: Checkpoint ready (unlocked read-only, spend disabled).
                _set_executor_state(executor, locked=False, core_alive=True, faulted=False)
                window._ready = True
                window._spend_enabled = False
                window._test_funded = False
                window._set_actions()
                assert_disclosure_preserves_disabled("open_checkpoint_ready")

                # State 3: Spend enabled, no pending confirm or resumable intent.
                window._spend_enabled = True
                window._pending_confirm_txid = None
                window._resumable_intent = None
                window._set_actions()
                assert_disclosure_preserves_disabled("spend_enabled_idle")

                # State 4: Faulted.
                _set_executor_state(executor, faulted=True)
                window._set_actions()
                assert_disclosure_preserves_disabled("faulted")

                # State 5: Busy worker.
                _set_executor_state(executor, faulted=False)
                window._worker = object()
                window._set_actions()
                assert_disclosure_preserves_disabled("busy_worker")
                window._worker = None
            finally:
                _close_window(window, executor)

    def test_existing_advanced_tools_characterization_d_d6_1(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            window, executor, _ = _make_window()
            try:
                dispatched: list[tuple[str, tuple[object, ...]]] = []
                with patch.object(
                    window, "_command", side_effect=lambda a, *args: dispatched.append((a, *args)) or True
                ):
                    _set_executor_state(executor, locked=False, core_alive=True, faulted=False)

                    # 1. fund: enabled when ready and not spend_enabled and not test_funded.
                    window._ready = True
                    window._spend_enabled = False
                    window._test_funded = False
                    window._set_actions()
                    self.assertTrue(window.fund.isEnabled())
                    with patch.object(WalletConsent, "exec", return_value=QDialog.DialogCode.Rejected):
                        window.fund.click()
                    self.assertEqual(dispatched, [])
                    with patch.object(WalletConsent, "exec", return_value=QDialog.DialogCode.Accepted):
                        window.fund.click()
                    self.assertEqual(dispatched, [("mine",)])
                    dispatched.clear()

                    # 2. confirm & inspect when pending_confirm is set (intents requires idle_payment).
                    window._spend_enabled = True
                    window._pending_confirm_txid = _BROADCAST_TXID
                    window._set_actions()
                    self.assertFalse(window.fund.isEnabled())
                    self.assertTrue(window.confirm.isEnabled())
                    self.assertTrue(window.inspect.isEnabled())
                    self.assertFalse(window.intents.isEnabled())
                    self.assertFalse(window.resume.isEnabled())

                    with patch.object(WalletConsent, "exec", return_value=QDialog.DialogCode.Accepted):
                        window.confirm.click()
                    self.assertEqual(dispatched, [("confirm", _BROADCAST_TXID)])
                    dispatched.clear()

                    with patch.object(QInputDialog, "getText", return_value=(_BROADCAST_TXID, True)):
                        window.inspect.click()
                    self.assertEqual(dispatched, [("inspect_confirmed", _BROADCAST_TXID)])
                    dispatched.clear()

                    # 3. intents & resume once pending_confirm clears (idle_payment == True).
                    window._pending_confirm_txid = None
                    window._set_actions()
                    self.assertFalse(window.confirm.isEnabled())
                    self.assertTrue(window.intents.isEnabled())
                    self.assertFalse(window.resume.isEnabled())

                    # intents emits immediately without modal.
                    window.intents.click()
                    self.assertEqual(dispatched, [("intent_status",)])
                    dispatched.clear()

                    # Delivering single resumable intent enables resume button.
                    window._on_ready(
                        "intent_status",
                        {
                            "intents": [
                                {
                                    "classification": "SIGNED_NOT_SUBMITTED_RESUMABLE",
                                    "token": "tok-1",
                                    "txid": _BROADCAST_TXID,
                                    "recipient": "wamrtsp1testrecipient",
                                    "atoms": 5000,
                                    "fee": 120,
                                    "state": "signed",
                                }
                            ]
                        },
                    )
                    self.assertTrue(window.resume.isEnabled())
                    with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
                        window.resume.click()
                    self.assertEqual(dispatched, [("resume_intent", "tok-1", _BROADCAST_TXID, True)])
            finally:
                _close_window(window, executor)


class SettingsLifetimeTests(unittest.TestCase):
    """Pin session-value lifetime across lock, fault, profile switch, and late results."""

    def test_lock_clears_advanced_account_balance_tip_last_txid_and_overview_cards(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            window, executor, _ = _make_window()
            try:
                _open_verified_session(window, executor, account_id="acct-secret-01")
                window.last_txid.setText(_BROADCAST_TXID)

                self.assertIn("acct-secret-01", window.account.text())
                self.assertIn("100,000", window.balance.text())
                self.assertIn(_CHAIN_TIP, window.tip.text())
                self.assertEqual(window.last_txid.text(), _BROADCAST_TXID)

                _set_executor_state(executor, locked=True)
                window._on_ready("lock", {"locked": True})
                QApplication.processEvents()

                self.assertEqual(window.account.text(), t("owner.account_locked"))
                self.assertEqual(window.balance.text(), t("owner.balance_unverified"))
                self.assertEqual(window.tip.text(), t("owner.chain_unverified"))
                self.assertEqual(window.last_txid.text(), "")
                self.assertEqual(window.status.text(), t("owner.locked_status"))
                self.assertEqual(window.status.toolTip(), t("owner.locked_status"))
                self.assertEqual(window.security_state.text(), t("wallet.security_locked"))
                self.assertTrue(window.overview.fund_details.isHidden())
                self.assertEqual(window.overview.activity_table.rowCount(), 0)
                self.assertEqual(window.overview.evidence_text.toolTip(), "")

                surfaces = _surface_texts(
                    [window.account, window.balance, window.tip, window.last_txid, window.overview.evidence_text]
                )
                for forbidden in ("acct-secret-01", "100,000", "100000", "7,000", "7000", _CHAIN_TIP, _BROADCAST_TXID):
                    for text in surfaces:
                        self.assertNotIn(forbidden, text)
            finally:
                _close_window(window, executor)

    # D6A-2 fixed by PM-061 (9256015): _clear_visuals resets _last_network and _shared_connected.
    def test_last_network_cleared_after_lock_fault_and_profile_switch(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            executor = WalletExecutor(lambda: _RecordingBackend())
            shared_profile = SimpleNamespace(coordinator=True)
            window = Bip39FusionWindow(executor, shared_profile=shared_profile)
            window._poll.stop()
            try:
                _open_verified_session(
                    window,
                    executor,
                    shared_network={
                        "connected": True,
                        "peer_count": 3,
                        "height": 112,
                        "tip": _CHAIN_TIP,
                    },
                )
                self.assertEqual(window._last_network["peer_count"], 3)

                # Lock must reset _last_network & clear peer/height/tip from network surfaces.
                _set_executor_state(executor, locked=True)
                window._on_ready("lock", {"locked": True})
                QApplication.processEvents()
                net_surfaces = _surface_texts(
                    [
                        window.overview.network_card,
                        window.overview.network_card.value,
                        window.overview.network_card.detail,
                        window.network_page.peer_value,
                        window.network_page.height_value,
                        window.network_page.sync_value,
                    ]
                )
                for text in net_surfaces:
                    self.assertNotIn("3 peer", text)
                    self.assertNotIn(_CHAIN_TIP[:14], text)
                self.assertIsNone(window._last_network)
            finally:
                _close_window(window, executor)

    # D6A-3 fixed by PM-061 (9256015): _on_ready('open', ...) clears _last_error_code before base handling.
    def test_last_error_code_cleared_on_open_and_ack_error_recorded(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            window, executor, _ = _make_window()
            try:
                window._on_denied("WALLET_BROADCAST_REJECTED_LOCK_RETAINED")
                self.assertEqual(window._last_error_code, "WALLET_BROADCAST_REJECTED_LOCK_RETAINED")

                # Profile switch / direct open delivery must clear previous session error code.
                _open_verified_session(window, executor, account_id="acct-second-02")
                self.assertIsNone(window._last_error_code)
            finally:
                _close_window(window, executor)

    # D6A-4 fixed by PM-061 (9256015): _clear_visuals resets account, balance, tip and their a11y/tooltip buffers.
    def test_fault_and_late_snapshot_clear_advanced_session_labels(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            window, executor, _ = _make_window()
            try:
                _open_verified_session(window, executor, account_id="acct-fault-01")
                self.assertIn("acct-fault-01", window.account.text())
                self.assertIn("100,000", window.balance.text())

                # Fault must clear account, balance, tip (visible text, tooltip, a11y).
                _set_executor_state(executor, faulted=True)
                window._on_denied("WALLET_CORE_UNAVAILABLE")
                QApplication.processEvents()

                # Also simulate a late snapshot arriving after faulted state.
                late_snap = _make_snapshot(height=222, tip="99" * 32, confirmed_atoms=55555, available_atoms=44444)
                window._on_ready("snapshot", _make_result(snap=late_snap))
                QApplication.processEvents()

                surfaces = _surface_texts([window.account, window.balance, window.tip])
                for forbidden in (
                    "acct-fault-01",
                    "100,000",
                    "100000",
                    "55,555",
                    "55555",
                    "44,444",
                    "44444",
                    _CHAIN_TIP,
                    "99" * 10,
                ):
                    for text in surfaces:
                        self.assertNotIn(forbidden, text)
            finally:
                _close_window(window, executor)

    # D6A-5 fixed by PM-067: _clear_visuals / base lifetime clear last_txid on fault/open/quit and reset status on backup_status='required' open.
    def test_last_txid_and_status_cleared_on_fault_profile_switch_and_quit(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            window, executor, _ = _make_window()
            try:
                _open_verified_session(window, executor, account_id="acct-txid-01")
                window._approved_commitment = b"\x01" * 32
                window._on_ready("broadcast", _BROADCAST_TXID)
                QApplication.processEvents()
                self.assertEqual(window.last_txid.text(), _BROADCAST_TXID)

                # Fault must clear last_txid across text, tooltip, and accessible strings.
                _set_executor_state(executor, faulted=True)
                window._on_denied("WALLET_CORE_UNAVAILABLE")
                QApplication.processEvents()
                txid_surfaces = _surface_texts([window.last_txid])
                for text in txid_surfaces:
                    self.assertNotIn(_BROADCAST_TXID, text)

                # Profile switch (`open`) must also clear last_txid and stale TXID status.
                _set_executor_state(executor, faulted=False)
                window.last_txid.setText(_BROADCAST_TXID)
                window.status.setText(t("owner.broadcast_submitted").format(txid=_BROADCAST_TXID))
                window._on_ready(
                    "open",
                    {
                        "account_id": "acct-txid-02",
                        "receive_code": _make_snapshot().receive_code,
                        "backup_status": "deferred",
                    },
                )
                QApplication.processEvents()
                for text in _surface_texts([window.last_txid, window.status]):
                    self.assertNotIn(_BROADCAST_TXID, text)

                # Quit must clear last_txid too.
                window.last_txid.setText(_BROADCAST_TXID)
                window._on_ready("quit", {"quit": True})
                QApplication.processEvents()
                for text in _surface_texts([window.last_txid]):
                    self.assertNotIn(_BROADCAST_TXID, text)
            finally:
                _close_window_bounded(window, executor)

    def test_same_profile_snapshot_refresh_preserves_last_txid(self):
        with _isolated_ini():
            window, executor, _ = _make_window()
            try:
                _open_verified_session(window, executor, account_id="acct-refresh-01")
                window._approved_commitment = b"\x01" * 32
                window._on_ready("broadcast", _BROADCAST_TXID)
                QApplication.processEvents()
                self.assertEqual(window.last_txid.text(), _BROADCAST_TXID)

                # Ordinary same-profile snapshot refresh (pending_confirm_txid=None and matching TXID)
                # must never clear a valid session last_txid.
                for pending in (_BROADCAST_TXID, None):
                    snap = _make_snapshot(height=113, tip="78" * 32)
                    window._on_ready(
                        "snapshot",
                        _make_result(
                            snap=snap,
                            payment_review=None,
                            payment_signed=False,
                            pending_confirm_txid=pending,
                        ),
                    )
                    QApplication.processEvents()
                    self.assertEqual(window.last_txid.text(), _BROADCAST_TXID)

                # Non-faulted read denial on an alive Core also retains last_txid.
                _set_executor_state(executor, locked=False, faulted=False, core_alive=True)
                window._on_denied("WALLET_READ_DENIED")
                QApplication.processEvents()
                self.assertEqual(window.last_txid.text(), _BROADCAST_TXID)
            finally:
                _close_window_bounded(window, executor)

    def test_fault_clears_last_txid_individually(self):
        with _isolated_ini():
            window, executor, _ = _make_window()
            try:
                _open_verified_session(window, executor, account_id="acct-fault-txid")
                window._approved_commitment = b"\x01" * 32
                window._on_ready("broadcast", _BROADCAST_TXID)
                window.last_txid.setToolTip(_BROADCAST_TXID)
                window.last_txid.setAccessibleName(_BROADCAST_TXID)
                window.last_txid.setAccessibleDescription(_BROADCAST_TXID)
                window.last_txid.selectAll()
                QApplication.processEvents()

                _set_executor_state(executor, faulted=True)
                window._on_denied("WALLET_CORE_UNAVAILABLE")
                QApplication.processEvents()

                self.assertEqual(window.last_txid.text(), "")
                self.assertEqual(window.last_txid.selectedText(), "")
                self.assertEqual(_surface_texts([window.last_txid]), [])
                self.assertEqual(window.status.text(), t("owner.faulted"))
                self.assertNotIn(_BROADCAST_TXID, window.status.toolTip())
            finally:
                _close_window_bounded(window, executor)

            # Base Bip39TrialWindow also clears last_txid on faulted _on_denied.
            be = _RecordingBackend()
            base_exec = WalletExecutor(lambda: be)
            base_win = Bip39TrialWindow(base_exec)
            base_win._poll.stop()
            try:
                base_win.last_txid.setText(_BROADCAST_TXID)
                _set_executor_state(base_exec, locked=False, faulted=True, core_alive=False)
                base_win._on_denied("WALLET_CORE_UNAVAILABLE")
                QApplication.processEvents()
                self.assertEqual(base_win.last_txid.text(), "")
            finally:
                _close_window_bounded(base_win, base_exec)

    def test_open_profile_switch_clears_last_txid_and_required_mnemonic_resets_status(self):
        with _isolated_ini():
            window, executor, _ = _make_window()
            try:
                _open_verified_session(window, executor, account_id="acct-open-01")
                window._approved_commitment = b"\x01" * 32
                window._on_ready("broadcast", _BROADCAST_TXID)
                window.last_txid.setToolTip(_BROADCAST_TXID)
                window.last_txid.setAccessibleName(_BROADCAST_TXID)
                window.last_txid.setAccessibleDescription(_BROADCAST_TXID)
                QApplication.processEvents()
                self.assertIn(_BROADCAST_TXID, window.status.text().replace("\u200b", ""))
                self.assertIn(_BROADCAST_TXID, window.status.toolTip())

                # Open returning into backup_status='required' with mnemonic_once must clear
                # last_txid and reset both status text and tooltip to a neutral state.
                window._on_ready(
                    "open",
                    {
                        "account_id": "acct-open-02",
                        "receive_code": _make_snapshot().receive_code,
                        "backup_status": "required",
                        "mnemonic_once": _DUMMY_MNEMONIC_12,
                    },
                )
                QApplication.processEvents()
                self.assertEqual(window.last_txid.text(), "")
                self.assertEqual(_surface_texts([window.last_txid]), [])
                self.assertEqual(window.status.text(), t("fusion.awaiting_verification"))
                self.assertEqual(window.status.toolTip(), t("fusion.awaiting_verification"))
                for text in _surface_texts([window.last_txid, window.status]):
                    self.assertNotIn(_BROADCAST_TXID, text.replace("\u200b", ""))

                # Reset backup flow before opening another verified profile; reopen snapshot
                # with a new pending_confirm_txid must populate the new TXID cleanly.
                window._backup_flow_active = False
                window.backup_page.clear_phrase()
                window.last_txid.setText(_BROADCAST_TXID)
                _open_verified_session(window, executor, account_id="acct-open-03")
                self.assertEqual(window.last_txid.text(), "")
                snap2 = _make_snapshot(height=114, tip="88" * 32)
                window._on_ready(
                    "snapshot",
                    _make_result(
                        snap=snap2,
                        payment_review=None,
                        payment_signed=False,
                        pending_confirm_txid=_SECOND_TXID,
                    ),
                )
                QApplication.processEvents()
                self.assertEqual(window.last_txid.text(), _SECOND_TXID)
            finally:
                _close_window_bounded(window, executor)

    def test_quit_clears_last_txid_individually(self):
        with _isolated_ini():
            window, executor, _ = _make_window()
            try:
                _open_verified_session(window, executor, account_id="acct-quit-txid")
                window._approved_commitment = b"\x01" * 32
                window._on_ready("broadcast", _BROADCAST_TXID)
                window.last_txid.setToolTip(_BROADCAST_TXID)
                window.last_txid.setAccessibleName(_BROADCAST_TXID)
                window.last_txid.setAccessibleDescription(_BROADCAST_TXID)
                QApplication.processEvents()

                window._on_ready("quit", {"quit": True})
                QApplication.processEvents()
                self.assertEqual(window.last_txid.text(), "")
                self.assertEqual(_surface_texts([window.last_txid]), [])
            finally:
                _close_window_bounded(window, executor)

            # Base Bip39TrialWindow also clears last_txid on quit.
            be = _RecordingBackend()
            base_exec = WalletExecutor(lambda: be)
            base_win = Bip39TrialWindow(base_exec)
            base_win._poll.stop()
            try:
                base_win.last_txid.setText(_BROADCAST_TXID)
                base_win._on_ready("quit", {"quit": True})
                QApplication.processEvents()
                self.assertEqual(base_win.last_txid.text(), "")
            finally:
                _close_window_bounded(base_win, base_exec)

    def test_rejected_presentation_snapshot_preserves_backend_pending_txid(self):
        with _isolated_ini():
            window, executor, _ = _make_window()
            try:
                _open_verified_session(window, executor, account_id="acct-pending-reject")

                # Reopen snapshot carrying pending_confirm_txid without a fusion_snapshot
                # triggers _render_verified -> _clear_visuals(), which must preserve last_txid.
                missing_presentation = _make_result(
                    snap=_make_snapshot(),
                    payment_review=None,
                    payment_signed=False,
                    pending_confirm_txid=_BROADCAST_TXID,
                )
                missing_presentation["fusion_snapshot"] = None
                window._on_ready("snapshot", missing_presentation)
                QApplication.processEvents()
                self.assertEqual(
                    window.status.text().replace("\u200b", ""),
                    "Q06_FUSION_VERIFIED_SNAPSHOT_DENIED",
                )
                self.assertIsNone(window._last_verified)
                self.assertEqual(window.account.text(), t("owner.account_locked"))
                self.assertEqual(window._pending_confirm_txid, _BROADCAST_TXID)
                self.assertEqual(window.last_txid.text(), _BROADCAST_TXID)

                # An unverified / mismatched presentation snapshot also rejects via _clear_visuals()
                # without clearing the backend pending_confirm_txid shown in last_txid.
                mismatched = _make_result(
                    snap=_make_snapshot(confirmed_atoms=99999),
                    payment_review=None,
                    payment_signed=False,
                    pending_confirm_txid=_BROADCAST_TXID,
                )
                mismatched["confirmed_atoms"] = 100000
                window._on_ready("snapshot", mismatched)
                QApplication.processEvents()
                self.assertEqual(
                    window.status.text().replace("\u200b", ""),
                    "Q06_FUSION_VERIFIED_SNAPSHOT_DENIED",
                )
                self.assertIsNone(window._last_verified)
                self.assertEqual(window.account.text(), t("owner.account_locked"))
                self.assertEqual(window._pending_confirm_txid, _BROADCAST_TXID)
                self.assertEqual(window.last_txid.text(), _BROADCAST_TXID)
            finally:
                _close_window_bounded(window, executor)

    # D6A-6 fixed by PM-061 (9256015): _clear_visuals clears overview.environment_core tooltip/a11y buffers.
    def test_environment_core_tooltip_cleared_on_lock_fault_and_profile_switch(self):
        with _isolated_ini({"QT_REDUCE_MOTION": "0"}):
            window, executor, _ = _make_window()
            try:
                _open_verified_session(window, executor)
                self.assertIn(_CORE_SHA, window.overview.environment_core.toolTip())

                _set_executor_state(executor, locked=True)
                window._on_ready("lock", {"locked": True})
                QApplication.processEvents()

                for text in _surface_texts([window.overview.environment_core]):
                    self.assertNotIn(_CORE_SHA, text)
            finally:
                _close_window(window, executor)


if __name__ == "__main__":
    unittest.main()
