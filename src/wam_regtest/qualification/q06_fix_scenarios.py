"""Frozen macOS qualification for fixes the spend stage never exercises.

Disposable REGTEST only. This module does not change wallet behaviour. The
real scenarios run inside the frozen app (native cocoa). Source tests drive
the marker/evidence shell with fakes; they do not start Core.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import secrets
import subprocess
import sys
import tempfile
import time

from .. import custody
from . import failure_exception_name, valid_failure_exception

EVIDENCE_NAME = "q06-fix-scenarios-evidence.json"
_PASSWORD = b"public-disposable-q06-fix-scenarios-only"
_PAYMENT_ATOMS = 100_000_000
_ATOM_MAX = 22_000_000 * 100_000_000
_HEX16 = re.compile(r"[0-9A-Fa-f]{16}")
_TOKEN = re.compile(r"[A-Z][A-Za-z0-9_]{0,94}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9]*_[A-Z0-9_]{0,80}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_GIT = re.compile(r"[0-9a-f]{40}\Z")
_SCENARIOS = ("S1", "S2", "S3", "S4")
_S1_BOOL = (
    "same_txid_shown", "pending_matches", "confirm_enabled",
    "status_awaiting_confirmation", "reservation_held", "tx_in_verified_history",
    "balance_arithmetic_exact", "send_page_confirmed", "second_reopen_no_pending",
    "second_reopen_no_spurious",
    "no_stale_reservation_display_after_confirm", "no_stale_reservation_display_after_reopen",
)
_S1_INT = (
    "funded_atoms", "payment_atoms", "fee_atoms", "change_atoms",
    "confirmed_atoms", "available_atoms",
)
_S2_BOOL = (
    "stay_default", "stay_keeps_display", "leave_clears_phrase",
    "verified_ack", "defer_preserves_ack", "reopen_still_verified",
)
_S3_BOOL = (
    "welcome_visible", "not_modal", "quit_menu_enabled",
    "command_q_quit", "wallet_route_called",
)

_S4_BOOL = (
    "activation_preserved", "payment_signed", "fund_button_disabled",
    "backend_refused_exact", "owner_retained_after_shutdown",
    "payment_broadcast", "payment_confirmed", "nothing_pending",
    "fund1_read_only_shape",
) + tuple(f"fund{n}_{key}" for n in (1, 2, 3, 4)
          for key in ("button_enabled", "mainnet_allowed")) + tuple(
    f"fund{n}_{key}" for n in (2, 3, 4)
    for key in ("signer_allowed", "broadcast_allowed", "spend_enabled"))
_S4_INT = ("signed_reservation_count", "payment_confirmed_atoms") + tuple(
    f"fund{n}_{key}" for n in (1, 2, 3, 4)
    for key in ("before_atoms", "after_atoms", "reservation_count", "raw_reservation_count"))


def s4_passed(section):
    """Public, strict oracle shared by source evidence and the frozen gate."""
    if type(section) is not dict:
        return False
    if any(type(section.get(key)) is not bool for key in _S4_BOOL):
        return False
    if any(type(section.get(key)) is not int or not 0 <= section[key] <= _ATOM_MAX
           for key in _S4_INT):
        return False
    false_fields = {"owner_retained_after_shutdown"} | {
        f"fund{n}_mainnet_allowed" for n in (1, 2, 3, 4)}
    if any(section[key] is not (key not in false_fields) for key in _S4_BOOL):
        return False
    if section["signed_reservation_count"] <= 0:
        return False
    if (section["fund1_read_only_shape"] is not True
            or section["fund1_reservation_count"] != 0
            or section["fund1_raw_reservation_count"] != 0):
        return False
    for n in (1, 2, 3, 4):
        if section[f"fund{n}_after_atoms"] <= section[f"fund{n}_before_atoms"]:
            return False
        if n > 1 and section[f"fund{n}_reservation_count"] != 0:
            return False
        if n in (2, 3) and section[f"fund{n}_before_atoms"] != section[f"fund{n-1}_after_atoms"]:
            return False
    if section["fund4_before_atoms"] != section["payment_confirmed_atoms"]:
        return False
    return True


def _stage(name):
    print("MACOS_Q06_FIX_STAGE=" + name, flush=True)


def _token(value):
    return (type(value) is str and _TOKEN.match(value) is not None
            and _HEX16.search(value) is None)


def failure_code(error):
    """Fixed public code, or INTERNAL. Never the exception text."""
    args = getattr(error, "args", ())
    if (type(args) is tuple and len(args) == 1 and _token(args[0]) and _CODE.match(args[0])):
        return args[0]
    return "INTERNAL"


def record_failure(target, error):
    """Record failure_code, plus failure_exception (class name only) on INTERNAL fallback.

    When a specific public code is used, failure_exception is omitted.
    """
    code = failure_code(error)
    target["failure_code"] = code
    if code == "INTERNAL":
        target["failure_exception"] = failure_exception_name(error)
    return code


def diagnostic_records():
    """Public diagnostic tokens already recorded in this process."""
    from ..foundation.diagnostics import records
    items = []
    for record in records():
        stage = record.stage if _token(record.stage) else "INVALID_STAGE"
        category = record.category if _token(record.category) else "INTERNAL"
        open_stage = record.open_stage if _token(record.open_stage) else None
        items.append({"stage": stage, "category": category, "open_stage": open_stage})
    return items


def stay_is_default(stay_default, leave_default, leave_auto_default):
    return (stay_default is True and leave_default is False
            and leave_auto_default is False)


def ack_is_verified(raw):
    """MAC-verified acknowledgement. The MAC and seed id are not returned."""
    if type(raw) is not bytes or not raw:
        return False
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    if type(data) is not dict:
        return False
    mac = data.get("mac")
    allowed = {"version", "acknowledged", "deferred", "seed_id", "mac"}
    return (set(data) <= allowed
            and data.get("acknowledged") is True
            and data.get("deferred") is False
            and type(mac) is str and _HEX64.match(mac) is not None)


def reservation_still_held(funded, confirmed, available, reservation_count, reservations_before):
    values = (funded, confirmed, available, reservation_count, reservations_before)
    return (all(type(value) is int for value in values)
            and confirmed == funded
            and available < funded
            and reservation_count > reservations_before)


def exact_confirmed_balance(funded, payment, fee, change, confirmed, available, history, txid):
    """Spend net, change and confirmed/available balance are one identity."""
    numbers = (funded, payment, fee, change, confirmed, available)
    if any(type(value) is not int for value in numbers):
        return False
    if not (0 < payment and 0 < fee and change == funded - payment - fee):
        return False
    if confirmed != change or available != change:
        return False
    if type(txid) is not str or _HEX64.match(txid) is None:
        return False
    if type(history) not in (list, tuple) or len(history) < 2:
        return False
    matched = []
    total = 0
    for row in history:
        if not isinstance(row, dict):
            return False
        atoms = row.get("atoms")
        row_txid = row.get("txid")
        if type(atoms) is not int or type(row_txid) is not str:
            return False
        total += atoms
        if row_txid == txid:
            matched.append(atoms)
    return (len(matched) == 1 and matched[0] == -(payment + fee)
            and total == confirmed)


def _public_bools(section, names):
    if type(section) is not dict:
        return None
    kept = {}
    for name in names:
        if type(section.get(name)) is bool:
            kept[name] = section[name]
    denied = section.get("gui_denied")
    if _token(denied) and _CODE.match(denied):
        kept["gui_denied"] = denied
    return kept or None


def _public_ints(section, names):
    if type(section) is not dict:
        return {}
    kept = {}
    for name in names:
        value = section.get(name)
        if type(value) is int and 0 <= value <= _ATOM_MAX:
            kept[name] = value
    return kept


def public_evidence(raw):
    """Whitelist. Drops phrases, paths, MACs, passwords and unknown keys."""
    scenarios = raw.get("scenarios") if type(raw) is dict else None
    if type(scenarios) is not dict:
        scenarios = {}
    clean_scenarios = {}
    for key in _SCENARIOS:
        value = scenarios.get(key)
        clean_scenarios[key] = value if value in ("PASS", "FAIL", "NOT_RUN") else "FAIL"
    status = "PASS" if (raw.get("status") == "PASS"
                        and all(clean_scenarios[key] == "PASS" for key in _SCENARIOS)
                        and s4_passed(raw.get("s4"))) else "FAIL"
    out = {
        "status": status,
        "network": "regtest",
        "mainnet_allowed": False,
        "frozen": raw.get("frozen") is True,
        "scenarios": clean_scenarios,
    }
    source = raw.get("source_sha")
    if type(source) is str and (_GIT.match(source) or _HEX64.match(source)):
        out["source_sha"] = source
    executable = raw.get("frozen_executable_sha256")
    if type(executable) is str and _HEX64.match(executable):
        out["frozen_executable_sha256"] = executable
    commit = raw.get("wsp_source_commit")
    if type(commit) is str and _GIT.match(commit):
        out["wsp_source_commit"] = commit
    core = raw.get("core_sha256")
    if (type(core) is dict and set(core) <= {"wamd", "wam-cli"}
            and all(type(value) is str and _HEX64.match(value) for value in core.values())):
        out["core_sha256"] = dict(core)
    s1 = _public_bools(raw.get("s1"), _S1_BOOL)
    if s1 is not None:
        s1.update(_public_ints(raw.get("s1"), _S1_INT))
        txid_sha = raw.get("s1", {}).get("txid_sha256") if type(raw.get("s1")) is dict else None
        if type(txid_sha) is str and _HEX64.match(txid_sha):
            s1["txid_sha256"] = txid_sha
        out["s1"] = s1
    s2 = _public_bools(raw.get("s2"), _S2_BOOL)
    if s2 is not None:
        out["s2"] = s2
    s3 = _public_bools(raw.get("s3"), _S3_BOOL)
    if s3 is not None:
        out["s3"] = s3
    # S4 has no string-valued public fields, including diagnostic strings.
    section = raw.get("s4")
    if type(section) is dict:
        s4 = {key: section[key] for key in _S4_BOOL if type(section.get(key)) is bool}
        s4.update(_public_ints(section, _S4_INT))
        out["s4"] = s4
    if status != "PASS":
        code = raw.get("failure_code")
        out["failure_code"] = code if _token(code) and _CODE.match(code) else "INTERNAL"
        if out["failure_code"] == "INTERNAL" and valid_failure_exception(raw.get("failure_exception")):
            out["failure_exception"] = raw["failure_exception"]
        diagnostics = []
        for item in raw.get("diagnostics") or ():
            if type(item) is not dict:
                continue
            stage = item.get("stage")
            category = item.get("category")
            open_stage = item.get("open_stage")
            if not _token(stage) or not _token(category):
                continue
            diagnostics.append({
                "stage": stage,
                "category": category,
                "open_stage": open_stage if _token(open_stage) else None,
            })
        out["diagnostics"] = diagnostics
    return out


def drive(steps, preamble=None, evidence_path=None, setup_error=None):
    """Run scenario callables, print markers, write public evidence, return 0 or 2."""
    from ..foundation import diagnostics as diagnostic_ring
    diagnostic_ring.clear()
    evidence = dict(preamble or {})
    evidence["status"] = "FAIL"
    evidence["scenarios"] = {key: "NOT_RUN" for key in _SCENARIOS}
    code = 2
    try:
        if setup_error is not None:
            raise setup_error
        _stage("START")
        for key, function in steps:
            if key not in evidence["scenarios"]:
                raise ValueError("Q06_FIX_SCENARIO_KEY_DENIED")
            evidence["scenarios"][key] = "FAIL"
            function(evidence)
            evidence["scenarios"][key] = "PASS"
            _stage(key + "_PASS")
        if any(evidence["scenarios"][key] != "PASS" for key in _SCENARIOS):
            raise ValueError("Q06_FIX_SCENARIOS_INCOMPLETE")
        if not s4_passed(evidence.get("s4")):
            raise ValueError("Q06_FIX_S4_EVIDENCE_DENIED")
        evidence["status"] = "PASS"
        _stage("ALL_PASS")
        code = 0
    except Exception as error:
        record_failure(evidence, error)
        evidence["diagnostics"] = diagnostic_records()
        _stage("DENIED")
        code = 2
    path = Path(evidence_path) if evidence_path is not None else Path(EVIDENCE_NAME)
    try:
        with path.open("x") as output:
            json.dump(public_evidence(evidence), output, sort_keys=True, indent=2)
            output.write("\n")
    except Exception:
        _stage("EVIDENCE_WRITE_DENIED")
        return 2
    return code


def _require_cocoa():
    if sys.platform != "darwin" or platform.machine().lower() != "arm64":
        raise ValueError("Q06_FIX_MACOS_NATIVE_REQUIRED")
    from ..desktop import qt_application
    app = qt_application()
    if app.platformName() != "cocoa":
        raise ValueError("Q06_FIX_NATIVE_COCOA_REQUIRED")
    return app


def _identify(preamble, core, source):
    from ..core import verified_core_paths
    from ..wsp_live import _pinned_source
    _, _, receipt = verified_core_paths(core)
    _pinned_source(source)
    preamble["core_sha256"] = {
        "wamd": receipt["wamd_sha256"],
        "wam-cli": receipt["wam_cli_sha256"],
    }
    preamble["wsp_source_commit"] = "ac55f13423620252bdbf848c7e8a280c3b84721e"
    preamble["frozen"] = bool(getattr(sys, "frozen", False))
    if preamble["frozen"]:
        from ..q05_package_provenance import read
        preamble["source_sha"] = read()["candidate_source_sha"]
        preamble["frozen_executable_sha256"] = sha256(Path(sys.executable).read_bytes()).hexdigest()
    else:
        preamble["source_sha"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True).strip()


def _profile():
    parent = Path.cwd() / ".wam-regtest-temp"
    if not parent.exists():
        custody.create_directory(parent)
    directory = Path(tempfile.mkdtemp(prefix="q06-fix-", dir=parent)).resolve()
    root = directory / ("wam-fusion-core-" + secrets.token_hex(8))
    custody.create_directory(root)
    return root


def _note(report, name, **fields):
    current = report.get(name)
    if type(current) is not dict:
        current = {}
    current.update(fields)
    report[name] = current


def _drop_window(state):
    window = state.get("window")
    app = state.get("app")
    if window is None:
        return
    try:
        window._poll.stop()
        window.hide()
        window.deleteLater()
    except Exception:
        pass
    state["window"] = None
    if app is not None:
        app.processEvents()


def _shutdown(state, timeout=105):
    """Drain one in-flight action, then quit the original owner within one budget.

    Never skip quit merely because Cancel is still running. Never resubmit an
    unacknowledged quit, adopt a PID, or claim that a timed-out owner has stopped.
    """
    deadline = time.monotonic() + timeout
    executor = state.get("executor")
    app = state.get("app")
    state.pop("shutdown_failure_code", None)
    window = state.get("window")
    if window is not None:
        window._poll.stop()  # No new snapshot work while draining Cancel.

    def pump():
        if time.monotonic() >= deadline:
            raise TimeoutError
        if app is not None:
            app.processEvents()
        time.sleep(min(.01, max(0, deadline - time.monotonic())))

    try:
        if executor is not None:
            if not executor.closed:
                while executor.busy:
                    pump()
                future = executor.submit("quit")
                while not future.done():
                    pump()
                future.result()  # A refusal is not a shutdown acknowledgement.
            while not executor.join(0):
                pump()
            if not executor.closed:
                raise ValueError("Q06_FIX_SHUTDOWN_UNCERTAIN")
    except TimeoutError:
        state["shutdown_failure_code"] = "Q06_FIX_SHUTDOWN_TIMEOUT"
    except Exception:
        state["shutdown_failure_code"] = "Q06_FIX_SHUTDOWN_UNCERTAIN"
    finally:
        _drop_window(state)
    return "shutdown_failure_code" in state


def _bind(state, app, report, section):
    from PySide6.QtCore import QTimer
    from ..qualification_gui import click_visible_approval

    def idle():
        window = state["window"]
        executor = state["executor"]
        return window._worker is None and not executor.busy and not window._delivering_result

    def wait_for(predicate, label, timeout=240):
        deadline = time.monotonic() + timeout
        while not predicate():
            app.processEvents()
            window = state.get("window")
            if (window is not None and idle() and window._last_error_code is not None):
                code = window._last_error_code
                if _token(code) and _CODE.match(code):
                    _note(report, section, gui_denied=code)
                raise ValueError("Q06_FIX_GUI_DENIED_" + label)
            if time.monotonic() >= deadline:
                raise ValueError("Q06_FIX_WAIT_" + label)
            time.sleep(0.01)
        app.processEvents()

    def approve(button, caption, done, label):
        timer = QTimer()
        timer.setInterval(150)
        timer.timeout.connect(lambda: click_visible_approval(app, caption))
        timer.start()
        try:
            button.click()
            wait_for(lambda: idle() and done(), label)
        finally:
            timer.stop()

    return idle, wait_for, approve


def _open_owner(state, root, core, source, adapter, mode, keychain=None):
    from ..bip39_fusion_gui import Bip39FusionWindow
    from ..bip39_owner_backend import Bip39ReadOnlyBackend
    from ..wallet_executor import WalletExecutor
    if keychain is None:
        factory = lambda: Bip39ReadOnlyBackend(
            root, core, source, _anchor_factory=adapter.make_anchor)
    else:
        factory = lambda: Bip39ReadOnlyBackend(root, core, source, keychain=keychain)
    executor = WalletExecutor(factory)
    state["executor"] = executor
    window = Bip39FusionWindow(executor)
    state["window"] = window
    window.show()
    window.start(_PASSWORD, mode, "")
    return executor, window


def _finish_backup(window, idle, wait_for):
    created = dict(window._backup_result)
    phrase = created.pop("mnemonic_once")
    page = window.backup_page
    page._written_check.setChecked(True)
    page._back_up_now.click()
    words = phrase.split()
    phrase = None
    try:
        for position, field in zip(page._challenge_positions, page._verify_inputs):
            field.setText(words[position - 1])
    finally:
        words = None
    page._verify_button.click()
    if page._stack.currentWidget() is not page._success_page or not window._backup_verified:
        raise ValueError("Q06_FIX_BACKUP_VERIFY_DENIED")
    page._continue_button.click()
    wait_for(lambda: idle() and window._last_verified is not None, "BACKUP_SYNC")


def _phrase_cards(page):
    from PySide6.QtWidgets import QLabel
    count = 0
    for index in range(page._grid.count()):
        card = page._grid.itemAt(index).widget()
        if card is None or not card.isVisible():
            continue
        if any(label.text() and not label.text().isdecimal()
               for label in card.findChildren(QLabel)):
            count += 1
    return count


def _answer_leave(app, page, choice):
    from PySide6.QtCore import QTimer
    from ..bip39_backup_page import BackupLeaveConfirm
    seen = {"ticks": 0}
    timer = QTimer()
    timer.setInterval(50)

    def tick():
        seen["ticks"] += 1
        dialogs = [widget for widget in app.topLevelWidgets()
                   if isinstance(widget, BackupLeaveConfirm) and widget.isVisible()]
        if not dialogs:
            if seen["ticks"] > 100:
                timer.stop()
            return
        dialog = dialogs[0]
        if seen["ticks"] > 100:
            seen["watchdog"] = True
            timer.stop()
            dialog.reject()
            return
        seen["stay_default"] = dialog.stay_button.isDefault()
        seen["leave_default"] = dialog.leave_button.isDefault()
        seen["leave_auto_default"] = dialog.leave_button.autoDefault()
        timer.stop()
        if choice == "stay":
            dialog.stay_button.click()
        else:
            dialog.leave_button.click()

    timer.timeout.connect(tick)
    timer.start()
    try:
        page._back_up_later.click()
    finally:
        timer.stop()
    app.processEvents()
    return seen


def _history_txids(window):
    return tuple(row.txid for row in window.history_page.rows)


def scenario_unconfirmed_restart(app, adapter, core, source, report):
    """S1. Broadcast, quit before confirmation, reopen, confirm once, reopen again."""
    from mnemonic import Mnemonic
    from ..bip39_12 import Bip39Regtest12Keys
    state = {"app": app, "window": None, "executor": None}
    failed = True
    try:
        root = _profile()
        idle, wait_for, approve = _bind(state, app, report, "s1")
        executor, window = _open_owner(state, root, core, source, adapter, "create")
        wait_for(lambda: idle() and window._backup_flow_active, "S1_CREATE")
        _stage("S1_CREATE_PASS")
        _finish_backup(window, idle, wait_for)
        _stage("S1_BACKUP_PASS")
        funded = executor.request("mine", timeout=240)
        funded_atoms = funded["atoms"]
        baseline = executor.request("snapshot", timeout=120)
        if (baseline["confirmed_atoms"] != funded_atoms
                or baseline["available_atoms"] != funded_atoms):
            raise ValueError("Q06_FIX_S1_FUND_DENIED")
        _stage("S1_FUND_PASS")
        approve(window.activate, "Approve", lambda: window._spend_enabled, "S1_ENABLE")
        _stage("S1_ENABLE_PASS")
        reservations_before = executor.request("snapshot", timeout=120)["reservation_count"]
        with Bip39Regtest12Keys(
                Mnemonic("english").to_mnemonic(bytes([7] * 16)),
                source=source, authorized_disposable=True) as payee:
            destination = payee.public_metadata()["receive_code"]
        window.recipient_input.setText(destination)
        window.amount_input.setText("1.00000000")
        destination = None
        approve(window.send, "Approve Sign", lambda: window._signed_ready, "S1_SIGN")
        prepared = window._last_review
        from .fee_oracles import quoted_fee_holds
        try:
            quoted = quoted_fee_holds(prepared)
        except ValueError:
            quoted = False
        if (not quoted or prepared.atoms != _PAYMENT_ATOMS
                or prepared.change_atoms != funded_atoms - prepared.atoms - prepared.fee
                or prepared.available_before != funded_atoms):
            raise ValueError("Q06_FIX_S1_PREPARE_DENIED")
        approve(window.broadcast, "Approve Broadcast",
                lambda: window._pending_confirm_txid is not None, "S1_BROADCAST")
        txid = window._pending_confirm_txid
        if type(txid) is not str or _HEX64.match(txid) is None:
            raise ValueError("Q06_FIX_S1_TXID_DENIED")
        _note(report, "s1", txid_sha256=sha256(txid.encode("ascii")).hexdigest(),
              funded_atoms=funded_atoms, payment_atoms=prepared.atoms,
              fee_atoms=prepared.fee, change_atoms=prepared.change_atoms)
        _stage("S1_BROADCAST_PASS")
        # Quit before any confirmation. No second sign, broadcast, cancel or mine.
        executor.request("quit", timeout=90)
        if not executor.join(15) or not executor.closed:
            raise ValueError("Q06_FIX_S1_QUIT_DENIED")
        _drop_window(state)
        _stage("S1_QUIT_BEFORE_CONFIRM_PASS")
        keychain = root / "q05-disposable.keychain-db"
        executor, window = _open_owner(
            state, root, core, source, adapter, "reopen", keychain=keychain)
        wait_for(lambda: idle() and window._ready, "S1_REOPEN")
        approve(window.activate, "Approve", lambda: window._spend_enabled, "S1_ENABLE_REOPEN")
        wait_for(lambda: idle() and window._pending_confirm_txid == txid
                 and window.confirm.isEnabled(), "S1_REOPEN_PENDING")
        pending = executor.request("snapshot", timeout=240)
        status = window.status.text().lower()
        shown = (window.last_txid.text().strip() == txid
                 and window._pending_confirm_txid == txid
                 and pending["pending_confirm_txid"] == txid
                 and window.confirm.isEnabled()
                 and "awaiting" in status and "confirmation" in status)
        held = reservation_still_held(
            funded_atoms, pending["confirmed_atoms"], pending["available_atoms"],
            pending["reservation_count"], reservations_before)
        _note(report, "s1", same_txid_shown=window.last_txid.text().strip() == txid,
              pending_matches=pending["pending_confirm_txid"] == txid,
              confirm_enabled=window.confirm.isEnabled(),
              status_awaiting_confirmation=("awaiting" in status and "confirmation" in status),
              reservation_held=held)
        if not shown:
            raise ValueError("Q06_FIX_S1_REOPEN_PENDING_DENIED")
        if not held:
            raise ValueError("Q06_FIX_S1_RESERVATION_RELEASED")
        _stage("S1_REOPEN_PENDING_PASS")
        approve(window.confirm, "Approve", lambda: window._pending_confirm_txid is None, "S1_CONFIRM")
        after = executor.request("snapshot", timeout=240)
        window.navigation.setCurrentRow(3)
        app.processEvents()
        history = tuple(dict(row) for row in after["history"])
        arithmetic = exact_confirmed_balance(
            funded_atoms, prepared.atoms, prepared.fee, prepared.change_atoms,
            after["confirmed_atoms"], after["available_atoms"], history, txid)
        on_send = (window.page_title.text() == "Send"
                   and window.send_result.text().startswith("Confirmed")
                   and txid in window.send_result.text())
        in_history = txid in [row["txid"] for row in history] and txid in _history_txids(window)
        _note(report, "s1", tx_in_verified_history=in_history,
              balance_arithmetic_exact=arithmetic, send_page_confirmed=on_send,
              confirmed_atoms=after["confirmed_atoms"],
              available_atoms=after["available_atoms"])
        if not in_history:
            raise ValueError("Q06_FIX_S1_HISTORY_DENIED")
        if not arithmetic:
            raise ValueError("Q06_FIX_S1_BALANCE_DENIED")
        if not on_send:
            raise ValueError("Q06_FIX_S1_SEND_PAGE_DENIED")
        _stage("S1_CONFIRM_PASS")
        # W-TX-03 / W-TX-03b: a confirmed payment's leftover 'broadcast' rows
        # must not be shown as a reservation warning or as unavailable inputs.
        from wam_regtest.bip39_owner_gui import reservation_warning
        from wam_regtest.bip39_fusion_gui import displayed_reserved_inputs
        stale_after_confirm = (after.get("reservation_states") != ("broadcast",)
                               or reservation_warning(after)
                               or displayed_reserved_inputs(after) != 0
                               or "anchored transaction reservations exist"
                               in window.status.text().lower()
                               or "reserved input" in window.overview.fund_details.text().lower())
        _note(report, "s1", no_stale_reservation_display_after_confirm=not stale_after_confirm)
        if stale_after_confirm:
            raise ValueError("Q06_FIX_S1_STALE_RESERVATION_DISPLAY")
        _stage("S1_NO_STALE_RESERVATION_DISPLAY_PASS")
        confirmed_atoms = after["confirmed_atoms"]
        available_atoms = after["available_atoms"]
        reservations = after["reservation_count"]
        executor.request("quit", timeout=90)
        if not executor.join(15) or not executor.closed:
            raise ValueError("Q06_FIX_S1_SECOND_QUIT_DENIED")
        _drop_window(state)
        executor, window = _open_owner(
            state, root, core, source, adapter, "reopen", keychain=keychain)
        wait_for(lambda: idle() and window._ready, "S1_REOPEN_FINAL")
        approve(window.activate, "Approve", lambda: window._spend_enabled, "S1_ENABLE_FINAL")
        wait_for(lambda: idle() and window._pending_confirm_txid is None
                 and not window.confirm.isEnabled(), "S1_SECOND_REOPEN")
        final = executor.request("snapshot", timeout=240)
        send_text = window.send_result.text()
        status_text = window.status.text().lower()
        clean = (window._pending_confirm_txid is None
                 and final["pending_confirm_txid"] is None
                 and not window.confirm.isEnabled()
                 and not window.last_txid.text().strip()
                 and txid not in send_text
                 and "awaiting" not in status_text
                 and final["payment_signed"] is False
                 and final["payment_review"] is None
                 and final["recovered_unsigned_cancel_available"] is False
                 and final["confirmed_atoms"] == confirmed_atoms
                 and final["available_atoms"] == available_atoms
                 and final["reservation_count"] == reservations
                 and txid in [row["txid"] for row in final["history"]])
        _note(report, "s1", second_reopen_no_pending=window._pending_confirm_txid is None
              and final["pending_confirm_txid"] is None,
              second_reopen_no_spurious=clean)
        if not clean:
            raise ValueError("Q06_FIX_S1_SECOND_REOPEN_DENIED")
        rendered_stale = ("anchored transaction reservations exist" in status_text
                          or "reserved input" in window.overview.fund_details.text().lower())
        _note(report, "s1", no_stale_reservation_display_after_reopen=not rendered_stale)
        if rendered_stale:
            raise ValueError("Q06_FIX_S1_STALE_RESERVATION_DISPLAY_REOPEN")
        _stage("S1_SECOND_REOPEN_PASS")
        failed = False
    finally:
        retained = _shutdown(state)
        if retained and not failed:
            raise ValueError("Q06_FIX_S1_OWNER_RETAINED")


def scenario_backup_leave(app, adapter, core, source, report):
    """S2. Stay keeps the seed display; Leave clears it; defer keeps a verified ack."""
    state = {"app": app, "window": None, "executor": None}
    failed = True
    try:
        idle, wait_for, _approve = _bind(state, app, report, "s2")
        root = _profile()
        _executor, window = _open_owner(state, root, core, source, adapter, "create")
        wait_for(lambda: idle() and window._backup_flow_active, "S2_CREATE")
        page = window.backup_page
        if _phrase_cards(page) != 12 or not page.holds_unverified_phrase():
            raise ValueError("Q06_FIX_S2_PHRASE_NOT_SHOWN")
        stayed = _answer_leave(app, page, "stay")
        stay_default = stay_is_default(
            stayed.get("stay_default"), stayed.get("leave_default"),
            stayed.get("leave_auto_default"))
        keeps = (not stayed.get("watchdog") and stay_default
                 and _phrase_cards(page) == 12 and page.holds_unverified_phrase()
                 and page._stack.currentWidget() is page._phrase_page
                 and window._backup_flow_active and not window.executor.state.locked)
        _note(report, "s2", stay_default=stay_default, stay_keeps_display=keeps)
        if not stay_default:
            raise ValueError("Q06_FIX_S2_STAY_NOT_DEFAULT")
        _stage("S2_STAY_DEFAULT_PASS")
        if not keeps:
            raise ValueError("Q06_FIX_S2_STAY_CLEARED_PHRASE")
        _stage("S2_STAY_KEEPS_DISPLAY_PASS")
        left = _answer_leave(app, page, "leave")
        cleared = (not left.get("watchdog")
                   and _phrase_cards(page) == 0
                   and not page.holds_unverified_phrase()
                   and not window._backup_flow_active
                   and window.executor.state.locked)
        _note(report, "s2", leave_clears_phrase=cleared)
        if not cleared:
            raise ValueError("Q06_FIX_S2_LEAVE_KEPT_PHRASE")
        _stage("S2_LEAVE_CLEARS_PHRASE_PASS")
        if _shutdown(state):
            raise ValueError("Q06_FIX_S2_LEAVE_OWNER_RETAINED")
        root = _profile()
        executor, window = _open_owner(state, root, core, source, adapter, "create")
        wait_for(lambda: idle() and window._backup_flow_active, "S2_VERIFY_CREATE")
        created = dict(window._backup_result)
        phrase = created.pop("mnemonic_once")
        page = window.backup_page
        page._written_check.setChecked(True)
        page._back_up_now.click()
        words = phrase.split()
        phrase = None
        try:
            for position, field in zip(page._challenge_positions, page._verify_inputs):
                field.setText(words[position - 1])
        finally:
            words = None
        page._verify_button.click()
        if not window._backup_verified or page._stack.currentWidget() is not page._success_page:
            raise ValueError("Q06_FIX_S2_VERIFY_DENIED")
        ack_path = executor._backend._q06_ack_path(executor._backend._seed_folder)
        verified = ack_path.read_bytes()
        verified_ok = ack_is_verified(verified)
        _note(report, "s2", verified_ack=verified_ok)
        if not verified_ok:
            raise ValueError("Q06_FIX_S2_ACK_NOT_VERIFIED")
        _stage("S2_VERIFIED_BACKUP_PASS")
        executor.request("backup_defer", timeout=30)
        deferred = ack_path.read_bytes()
        preserved = verified_ok and deferred == verified and ack_is_verified(deferred)
        _note(report, "s2", defer_preserves_ack=preserved)
        if not preserved or not executor.state.locked:
            raise ValueError("Q06_FIX_S2_DEFER_DOWNGRADED_ACK")
        _stage("S2_DEFER_PRESERVES_ACK_PASS")
        if _shutdown(state):
            raise ValueError("Q06_FIX_S2_DEFER_OWNER_RETAINED")
        keychain = root / "q05-disposable.keychain-db"
        executor, window = _open_owner(
            state, root, core, source, adapter, "reopen", keychain=keychain)
        wait_for(lambda: idle() and window._ready and not window._backup_flow_active,
                 "S2_REOPEN")
        reopened = executor._backend._q06_ack_path(executor._backend._seed_folder).read_bytes()
        still = (reopened == verified and ack_is_verified(reopened)
                 and window._ready and not window._backup_flow_active
                 and not window.backup_page.holds_unverified_phrase())
        _note(report, "s2", reopen_still_verified=still)
        if not still:
            raise ValueError("Q06_FIX_S2_REOPEN_DOWNGRADED")
        _stage("S2_REOPEN_VERIFIED_PASS")
        failed = False
    finally:
        retained = _shutdown(state)
        if retained and not failed:
            raise ValueError("Q06_FIX_S2_OWNER_RETAINED")


def send_command_q():
    """Real Command+Q NSEvent through -[NSApplication sendEvent:], as in WelcomeQuit."""
    import ctypes
    objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
    ctypes.CDLL("/System/Library/Frameworks/AppKit.framework/AppKit")
    objc.objc_getClass.restype = objc.sel_registerName.restype = ctypes.c_void_p
    objc.objc_getClass.argtypes = objc.sel_registerName.argtypes = [ctypes.c_char_p]
    send = objc.objc_msgSend

    def msg(obj, sel, *args, restype=ctypes.c_void_p, argtypes=()):
        send.restype, send.argtypes = restype, [ctypes.c_void_p, ctypes.c_void_p, *argtypes]
        return send(obj, objc.sel_registerName(sel.encode()), *args)

    def cls(name):
        return objc.objc_getClass(name.encode())

    class NSPoint(ctypes.Structure):
        _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double)]

    app = msg(cls("NSApplication"), "sharedApplication")
    window = msg(app, "keyWindow")
    number = msg(window, "windowNumber", restype=ctypes.c_long) if window else 0
    q = msg(cls("NSString"), "stringWithUTF8String:", b"q", argtypes=(ctypes.c_char_p,))
    event = msg(
        cls("NSEvent"),
        "keyEventWithType:location:modifierFlags:timestamp:windowNumber:context:"
        "characters:charactersIgnoringModifiers:isARepeat:keyCode:",
        10, NSPoint(0, 0), 1 << 20, 0.0, number, None, q, q, False, 12,
        argtypes=(ctypes.c_ulong, NSPoint, ctypes.c_ulong, ctypes.c_double, ctypes.c_long,
                  ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool,
                  ctypes.c_ushort))
    msg(app, "sendEvent:", event, restype=None, argtypes=(ctypes.c_void_p,))


def quit_menu_enabled():
    """Validated state of AppKit's application-menu Command+Q item."""
    import ctypes
    objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
    ctypes.CDLL("/System/Library/Frameworks/AppKit.framework/AppKit")
    objc.objc_getClass.restype = objc.sel_registerName.restype = ctypes.c_void_p
    objc.objc_getClass.argtypes = objc.sel_registerName.argtypes = [ctypes.c_char_p]
    send = objc.objc_msgSend

    def msg(obj, sel, *args, restype=ctypes.c_void_p, argtypes=()):
        send.restype, send.argtypes = restype, [ctypes.c_void_p, ctypes.c_void_p, *argtypes]
        return send(obj, objc.sel_registerName(sel.encode()), *args)

    def cls(name):
        return objc.objc_getClass(name.encode())

    app = msg(cls("NSApplication"), "sharedApplication")
    menu = msg(msg(msg(app, "mainMenu"), "itemAtIndex:", 0, argtypes=(ctypes.c_long,)), "submenu")
    msg(menu, "update", restype=None)
    for index in range(msg(menu, "numberOfItems", restype=ctypes.c_long)):
        item = msg(menu, "itemAtIndex:", index, argtypes=(ctypes.c_long,))
        key = msg(msg(item, "keyEquivalent"), "UTF8String", restype=ctypes.c_char_p)
        if key == b"q":
            return bool(msg(item, "isEnabled", restype=ctypes.c_bool))
    raise ValueError("Q06_FIX_S3_QUIT_ITEM_MISSING")


def scenario_welcome_quit(app, core, source, report):
    """S3. Real Command+Q on Welcome quits with no wallet route."""
    from unittest.mock import patch
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication, QFileDialog
    from .. import managed_onboarding as onboarding
    if app.platformName() != "cocoa":
        raise ValueError("Q06_FIX_S3_COCOA_REQUIRED")
    seen = {"welcome": 0}
    routes = {"bip39": 0, "managed": 0, "folder": 0}
    original = onboarding.welcome_dialog

    def welcome():
        seen["welcome"] += 1
        dialog = original()
        if seen["welcome"] > 1:
            QTimer.singleShot(0, dialog.reject)
            return dialog

        def quit_while_waiting():
            seen["visible"] = dialog.isVisible()
            seen["modal"] = QApplication.activeModalWidget() is not None
            seen["quit_enabled"] = quit_menu_enabled()
            send_command_q()
            seen["selection"] = dialog.selection
            seen["visible_after"] = dialog.isVisible()

        def fallback():
            if dialog.isVisible():
                seen["trigger_ignored"] = True
                dialog.reject()

        QTimer.singleShot(0, quit_while_waiting)
        QTimer.singleShot(3000, fallback)
        return dialog

    def count_bip39(*_args, **_kwargs):
        routes["bip39"] += 1
        return 0

    def count_managed(*_args, **_kwargs):
        routes["managed"] += 1
        return 0

    def count_folder(*_args, **_kwargs):
        routes["folder"] += 1
        return ""

    with patch.object(onboarding, "welcome_dialog", side_effect=welcome), \
            patch("wam_regtest.bip39_owner_gui.launch_bip39_trial", count_bip39), \
            patch("wam_regtest.managed_gui.launch_managed", count_managed), \
            patch.object(QFileDialog, "getExistingDirectory", count_folder):
        result = onboarding.launch(core, source)
    routed = routes["bip39"] or routes["managed"] or routes["folder"] or seen["welcome"] > 1
    visible = seen.get("visible") is True
    not_modal = seen.get("modal") is False
    enabled = seen.get("quit_enabled") is True
    quit_ok = (result == 0 and not seen.get("trigger_ignored")
               and seen.get("visible_after") is False and seen.get("selection") is None
               and not routed)
    _note(report, "s3", welcome_visible=visible, not_modal=not_modal,
          quit_menu_enabled=enabled, command_q_quit=quit_ok, wallet_route_called=bool(routed))
    if not visible:
        raise ValueError("Q06_FIX_S3_WELCOME_NOT_VISIBLE")
    _stage("S3_WELCOME_VISIBLE_PASS")
    if not not_modal or not enabled:
        raise ValueError("Q06_FIX_S3_QUIT_DISABLED")
    _stage("S3_QUIT_MENU_ENABLED_PASS")
    if not quit_ok:
        raise ValueError("Q06_FIX_S3_COMMAND_Q_DENIED")
    _stage("S3_COMMAND_Q_NO_ROUTE_PASS")


def scenario_repeat_funding(app, adapter, core, source, report):
    """S4. Repeat GUI funding, refuse in-flight, then fund a confirmed payment."""
    from mnemonic import Mnemonic
    from ..bip39_12 import Bip39Regtest12Keys
    state = {"app": app, "window": None, "executor": None}
    failed = True
    try:
        idle, wait_for, approve = _bind(state, app, report, "s4")
        executor, window = _open_owner(state, _profile(), core, source, adapter, "create")
        wait_for(lambda: idle() and window._backup_flow_active, "S4_CREATE")
        _finish_backup(window, idle, wait_for)
        _stage("S4_CREATE_BACKUP_PASS")

        def settle():
            for _ in range(3):
                wait_for(lambda: idle() and window._pending_action is None, "S4_SETTLE")
                app.processEvents()

        def fund_once(n):
            from ..bip39_fusion_gui import displayed_reserved_inputs
            before = executor.request("snapshot", timeout=240)
            enabled = window.fund.isEnabled()
            _note(report, "s4", **{f"fund{n}_button_enabled": enabled})
            if not enabled:
                raise ValueError("Q06_FIX_S4_FUND_BUTTON_DISABLED")
            approve(window.fund, "Approve", lambda: True, f"S4_FUND{n}")
            settle()
            after = executor.request("snapshot", timeout=240)
            displayed_reservations = displayed_reserved_inputs(after)
            raw_reservations = after["reservation_count"]
            lock_summary = after.get("reservation_lock_summary")
            fund1_read_only_shape = (
                n == 1
                and displayed_reservations is None
                and isinstance(lock_summary, dict)
                and lock_summary.get("read_only") is True
                and (raw_reservations is None
                     or (type(raw_reservations) is int and raw_reservations == 0)))
            fields = {f"fund{n}_before_atoms": before["confirmed_atoms"],
                      f"fund{n}_after_atoms": after["confirmed_atoms"],
                      # Record a pre-activation read-only view separately from active locks.
                      f"fund{n}_reservation_count": (
                          0 if fund1_read_only_shape else displayed_reservations),
                      f"fund{n}_raw_reservation_count": (
                          0 if fund1_read_only_shape and raw_reservations is None
                          else raw_reservations),
                      f"fund{n}_mainnet_allowed": after["mainnet_allowed"]}
            if n == 1:
                fields["fund1_read_only_shape"] = bool(fund1_read_only_shape)
            if n > 1:
                fields.update({f"fund{n}_signer_allowed": after["signer_allowed"],
                               f"fund{n}_broadcast_allowed": after["broadcast_allowed"],
                               f"fund{n}_spend_enabled": window._spend_enabled})
            _note(report, "s4", **fields)
            if after["confirmed_atoms"] <= before["confirmed_atoms"]:
                raise ValueError("Q06_FIX_S4_BALANCE_NOT_INCREASED")
            if after["mainnet_allowed"] is not False:
                raise ValueError("Q06_FIX_S4_MAINNET_DENIED")
            reservation_ok = (fund1_read_only_shape if n == 1
                              else displayed_reservations == 0)
            if not reservation_ok:
                raise ValueError("Q06_FIX_S4_UNEXPECTED_RESERVATION")
            if n > 1 and not (after["signer_allowed"] is True
                               and after["broadcast_allowed"] is True
                               and window._spend_enabled):
                raise ValueError("Q06_FIX_S4_SPEND_STATE_CHANGED")
            _stage(f"S4_FUND{n}_PASS")

        for n in (1, 2, 3):
            fund_once(n)
            if n == 1:
                approve(window.activate, "Approve", lambda: window._spend_enabled, "S4_ENABLE")
                settle()
                active = executor.request("snapshot", timeout=240)
                activated = (active["signer_allowed"] is True
                             and active["broadcast_allowed"] is True and window._spend_enabled)
                _note(report, "s4", activation_preserved=bool(activated))
                if not activated:
                    raise ValueError("Q06_FIX_S4_ACTIVATION_DENIED")
                _stage("S4_ENABLE_PASS")

        with Bip39Regtest12Keys(Mnemonic("english").to_mnemonic(bytes([7] * 16)),
                                source=source, authorized_disposable=True) as payee:
            destination = payee.public_metadata()["receive_code"]
        window.recipient_input.setText(destination)
        window.amount_input.setText("1.00000000")
        approve(window.send, "Approve Sign", lambda: window._signed_ready, "S4_SIGN")
        settle()
        disabled = not window.fund.isEnabled()
        refused = False
        try:
            executor.request("mine", timeout=240)
        except Exception as error:
            refused = failure_code(error) == "Q06_GUI_TEST_FUNDING_IN_FLIGHT"
        signed = executor.request("snapshot", timeout=240)
        _note(report, "s4", fund_button_disabled=disabled, backend_refused_exact=refused,
              payment_signed=signed["payment_signed"],
              signed_reservation_count=signed["reservation_count"])
        if not disabled or not refused:
            raise ValueError("Q06_FIX_S4_IN_FLIGHT_NOT_REFUSED")
        if signed["payment_signed"] is not True or signed["reservation_count"] <= 0:
            raise ValueError("Q06_FIX_S4_SIGNED_PAYMENT_MISSING")
        _stage("S4_IN_FLIGHT_REFUSAL_PASS")
        approve(window.broadcast, "Approve Broadcast",
                lambda: window._pending_confirm_txid is not None, "S4_BROADCAST")
        txid = window._pending_confirm_txid
        broadcast = type(txid) is str and _HEX64.match(txid) is not None
        _note(report, "s4", payment_broadcast=bool(broadcast))
        if not broadcast:
            raise ValueError("Q06_FIX_S4_BROADCAST_DENIED")
        wait_for(lambda: idle() and window.confirm.isEnabled(), "S4_CONFIRM_READY")
        approve(window.confirm, "Approve",
                lambda: window._pending_confirm_txid is None, "S4_CONFIRM")
        settle()
        after_payment = executor.request("snapshot", timeout=240)
        confirmed = (any(row["txid"] == txid and row["confirmations"] > 0
                         for row in after_payment["history"])
                     and txid in _history_txids(window)
                     and window.send_result.text().startswith("Confirmed")
                     and txid in window.send_result.text())
        nothing_pending = (window._pending_confirm_txid is None
                           and not window.confirm.isEnabled()
                           and after_payment["pending_confirm_txid"] is None
                           and after_payment["payment_signed"] is False
                           and after_payment["payment_review"] is None
                           and after_payment["recovered_unsigned_cancel_available"] is False)
        _note(report, "s4", payment_confirmed=bool(confirmed),
              nothing_pending=bool(nothing_pending),
              payment_confirmed_atoms=after_payment["confirmed_atoms"])
        if not confirmed or not nothing_pending:
            raise ValueError("Q06_FIX_S4_CONFIRMATION_DENIED")
        _stage("S4_CONFIRM_PASS")
        fund_once(4)
        failed = False
    except Exception as error:
        # Shared helpers can report GUI/wait/backup failures; keep S4's public
        # failure namespace stable without copying exception messages.
        if failure_code(error).startswith("Q06_FIX_S4_"):
            raise
        raise ValueError("Q06_FIX_S4_OPERATION_DENIED") from error
    finally:
        retained = _shutdown(state)
        _note(report, "s4", owner_retained_after_shutdown=bool(retained))
        if retained and not failed:
            raise ValueError("Q06_FIX_S4_OWNER_RETAINED")
    if not s4_passed(report.get("s4")):
        raise ValueError("Q06_FIX_S4_EVIDENCE_DENIED")
    _stage("S4_SHUTDOWN_PASS")


def run(core, source):
    """Entry from the frozen app. 0 only when S1–S4 all PASS."""
    preamble = {
        "network": "regtest",
        "mainnet_allowed": False,
        "frozen": bool(getattr(sys, "frozen", False)),
    }
    try:
        _identify(preamble, Path(core), Path(source))
        app = _require_cocoa()
        from ..q05_platforms import DarwinArm64Adapter
        adapter = DarwinArm64Adapter()
        adapter.enforce_host()
    except Exception as error:
        return drive((), preamble, setup_error=error)
    return drive((
        ("S1", lambda report: scenario_unconfirmed_restart(app, adapter, Path(core), Path(source), report)),
        ("S2", lambda report: scenario_backup_leave(app, adapter, Path(core), Path(source), report)),
        # Keep the real Command+Q scenario last.
        ("S4", lambda report: scenario_repeat_funding(app, adapter, Path(core), Path(source), report)),
        ("S3", lambda report: scenario_welcome_quit(app, Path(core), Path(source), report)),
    ), preamble)
