"""Genuine-Core Q05 D-QUIT-1 acceptance harness (S-Q05-A and S-Q05-B).

Qualification-only module; never imported by production code. Create, prepare,
sign, mine, and recover call WalletSession and wallet_recovery on the owner
thread. Quit, notices, acknowledgement, and an existing-profile reopen stay on
ManagedWalletBackend. There is no product flag that re-enables a retired action.
"""
from __future__ import annotations

import argparse
from concurrent.futures import Future
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess
import sys
import tempfile
import threading
from unittest.mock import patch

from ..wallet_executor import (
    COMMANDS,
    ManagedWalletBackend,
    WalletExecutor,
    WalletExecutorError,
)
from .q06_fix_scenarios import failure_code as _base_failure_code

SCHEMA = "wam-q05-dquit1-source/v1"
REQUIRED_SCENARIOS = ("S-Q05-A", "S-Q05-B")
ALLOWED_STATUSES = frozenset(("PASS", "FAIL", "BLOCKED"))
FAULT_BOUNDARIES = {
    "S-Q05-A": "Signer.sign:raise before crypto after durable mark",
    "S-Q05-B": "custody.storage.publish:raise after durable ciphertext before anchor",
}
WSP_COMMIT = "ac55f13423620252bdbf848c7e8a280c3b84721e"

_PUBLIC_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,95}\Z")
_HEX40_RE = re.compile(r"^[0-9a-f]{40}\Z")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}\Z")
_PASSWORD = b"public-disposable-q05-dquit1-only"
_QUALIFICATION_COMMANDS = frozenset((
    "fixture_fund",
    "engine_open_owned",
    "engine_prepare_auto",
    "engine_sign",
    "engine_mine",
    "engine_recover",
))


class _AfterPublicationCut(ValueError):
    pass


class _BlockedSetup(ValueError):
    pass


class QualificationQ05Executor(WalletExecutor):
    """Qualification-only executor admitting fixture_fund alongside COMMANDS."""

    ALLOWED_COMMANDS = COMMANDS | _QUALIFICATION_COMMANDS

    def submit(self, action, *args, **kwargs):
        future = Future()
        with self._guard:
            if (action not in self.ALLOWED_COMMANDS or self._closed
                    or self._pending is not None
                    or threading.get_ident() == self._thread.ident):
                future.set_exception(WalletExecutorError("WALLET_EXECUTOR_BUSY_OR_CLOSED"))
                return future
            self._pending = future
            self._queue.put_nowait((action, args, kwargs, future))
        return future


class QualificationQ05Backend(ManagedWalletBackend):
    """ManagedWalletBackend subclass with fixture funding and lifecycle tracing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events: list[str] = []
        self.quit_count = 0
        self.lease_checks: list[dict[str, bool]] = []
        self.spawned_popens: list[tuple[subprocess.Popen, int]] = []
        self._release_wrapped_for: set[int] = set()

    def _record_popen(self):
        owner = self.owner
        if owner is not None and isinstance(owner.process, subprocess.Popen):
            pair = (owner.process, owner.process.pid)
            if all(existing is not pair[0] for existing, _ in self.spawned_popens):
                self.spawned_popens.append(pair)

    def _wrap_owner_release_close(self):
        owner = self.owner
        if owner is None or id(owner) in self._release_wrapped_for:
            return
        self._release_wrapped_for.add(id(owner))
        from ..supervisor_store import held_lease

        orig_release = owner.release
        orig_close = owner.close

        def wrapped_release():
            lease_held = held_lease(self.root) is not None
            self.events.append("OWNER_RELEASE" if lease_held else "OWNER_RELEASE_NO_LEASE")
            return orig_release()

        def wrapped_close():
            result = orig_close()
            lease_released = held_lease(self.root) is None
            self.events.append("OWNER_CLOSE" if lease_released else "OWNER_CLOSE_LEASE_STILL_HELD")
            return result

        owner.release = wrapped_release
        owner.close = wrapped_close

    def _publish_quit_notice(self, owner, *, core_stop, stop_error=None):
        from ..supervisor_store import held_lease

        before = held_lease(self.root) is not None
        notice = super()._publish_quit_notice(owner, core_stop=core_stop, stop_error=stop_error)
        after = held_lease(self.root) is not None
        self.lease_checks.append({"lease_held_before": before, "lease_held_after": after})
        self.events.append("PUBLISH_NOTICE")
        return notice

    def _engine_open_owned(self, password, create=False):
        from ..wallet_session import WalletSession
        if create is not True:
            raise ValueError("Q05_DQUIT1_ENGINE_CREATE_REQUIRED")
        if type(password) is not bytes or not 12 <= len(password) <= 1024:
            raise ValueError("WALLET_MANAGED_INPUT_DENIED")
        owner = self._core()
        if self._anchor_factory is not None and not self._anchor_ready:
            self.keychain = self._anchor_factory(self.root)
            self._anchor_ready = True
        self.session = WalletSession.open_owned(
            owner, self.source, password, authorized=True, create=True,
            keychain=self.keychain, mining_address=self.mining_address)
        return self.session.snapshot()

    def _engine_prepare_auto(self, code, atoms):
        return self.session.prepare_auto(code, atoms)

    def _engine_sign(self, commitment):
        return self.session.sign(commitment)

    def _engine_mine(self):
        return self.session.mine()

    def _engine_recover(self, password):
        from ..wallet_recovery import recover_checkpoint
        self._lock()
        owner = self.owner if self.owner is not None else self._core()
        if self.keychain is None and self._anchor_factory is not None and not self._anchor_ready:
            self.keychain = self._anchor_factory(self.root)
            self._anchor_ready = True
        return recover_checkpoint(
            owner, self.source, password, authorized=True, keychain=self.keychain)

    def execute(self, action, args, kwargs):
        try:
            if action == "fixture_fund":
                from ..managed_wallet_session import check_session
                from ..wallet_session import WalletCoreCli
                from ..wsp_live import public_regtest_mining_address, _public_fixture_payment
                from wam_sp.keystore import Keyring

                check_session(self.session)
                address = self.mining_address or public_regtest_mining_address(self.source)
                rpc = WalletCoreCli(self.owner.cli, self.owner.directory)
                try:
                    rpc.attest()
                    rpc._call("generatetoaddress", ["101", address])
                    txid, atoms, height = _public_fixture_payment(
                        rpc, self.session.ring.accounts()[0], address
                    )
                finally:
                    if getattr(rpc, "_transport", None) is not None:
                        rpc._transport.close()
                recipient = Keyring()
                try:
                    recipient_code = recipient.accounts()[0].payment_code()
                finally:
                    recipient.close()
                return {
                    "txid": txid,
                    "atoms": atoms,
                    "height": height,
                    "recipient": recipient_code,
                }
            if action == "engine_open_owned":
                return self._engine_open_owned(*args, **kwargs)
            if action == "engine_prepare_auto":
                return self._engine_prepare_auto(*args, **kwargs)
            if action == "engine_sign":
                return self._engine_sign(*args, **kwargs)
            if action == "engine_mine":
                return self._engine_mine()
            if action == "engine_recover":
                return self._engine_recover(*args, **kwargs)
            if action == "quit":
                self.quit_count += 1
                self.events.append("ACTION_QUIT")
                self._wrap_owner_release_close()
            return super().execute(action, args, kwargs)
        finally:
            self._record_popen()


def map_refusal_code(error) -> str:
    """Map an arbitrary exception to a fixed public refusal token."""
    code = _base_failure_code(error)
    if code == "INTERNAL" and isinstance(error, BaseException):
        args = getattr(error, "args", ())
        if len(args) == 1 and type(args[0]) is str and _PUBLIC_CODE_RE.match(args[0]):
            return args[0]
    return code


def pid_is_alive(pid: int) -> bool:
    """Read-only POSIX existence check for a single harness-owned PID (signal 0)."""
    if type(pid) is not int or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def check_popen_stopped(popen, pid: int | None = None) -> tuple[bool, int | None, bool]:
    """Return (stopped, observed_exit, orphan_free) for a harness-owned Popen."""
    observed_exit = popen.poll() if popen is not None else None
    target_pid = pid if pid is not None else getattr(popen, "pid", None)
    stopped = observed_exit is not None
    orphan_free = stopped and (target_pid is None or not pid_is_alive(target_pid))
    return stopped, observed_exit, orphan_free


def plain_value(value):
    """Convert FrozenDict/tuple executor results to plain JSON-serializable data."""
    if isinstance(value, dict):
        return {k: plain_value(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [plain_value(v) for v in value]
    return value


def validate_scenario_report(scenario: dict) -> bool:
    """Validate one per-scenario report record against the D-QUIT-1 contract."""
    if not isinstance(scenario, dict):
        return False
    required = {
        "scenario_id", "name", "status", "stage", "failure_code",
        "test_layer", "fault_boundary", "one_quit", "quit_count",
        "orphan_free", "observed_exit", "core_stopped",
        "lease_released_only_after_notice", "assertions", "events",
    }
    if not required <= set(scenario):
        return False
    if scenario["scenario_id"] not in REQUIRED_SCENARIOS:
        return False
    if scenario["status"] not in ALLOWED_STATUSES:
        return False
    if type(scenario["stage"]) is not str or not scenario["stage"]:
        return False
    if scenario["test_layer"] != "FAULT_INJECTED_REAL_CORE":
        return False
    if scenario["status"] == "PASS":
        if scenario["failure_code"] is not None:
            return False
        if scenario["one_quit"] is not True or scenario["quit_count"] != 1:
            return False
        if scenario["orphan_free"] is not True or scenario["core_stopped"] is not True:
            return False
        if type(scenario["observed_exit"]) is not int:
            return False
        if scenario["lease_released_only_after_notice"] is not True:
            return False
        assertions = scenario["assertions"]
        if not isinstance(assertions, dict) or not assertions:
            return False
        if not all(v is True for v in assertions.values()):
            return False
    else:
        code = scenario["failure_code"]
        if type(code) is not str or not _PUBLIC_CODE_RE.match(code):
            return False
    return isinstance(scenario["events"], list)


def aggregate_run_status(scenarios: dict, *, source_unchanged: bool = True) -> str:
    """Aggregate scenario statuses into PASS / FAIL / BLOCKED."""
    if source_unchanged is not True or not isinstance(scenarios, dict):
        return "FAIL"
    if set(scenarios) != set(REQUIRED_SCENARIOS):
        return "FAIL"
    statuses = [scenarios[k].get("status") for k in REQUIRED_SCENARIOS]
    if any(s not in ALLOWED_STATUSES for s in statuses) or "FAIL" in statuses:
        return "FAIL"
    if "BLOCKED" in statuses:
        return "BLOCKED"
    return "PASS"


def validate_run_report(report: dict) -> bool:
    """Validate the top-level JSON report schema and cross-field invariants."""
    if not isinstance(report, dict):
        return False
    if report.get("schema") != SCHEMA or report.get("status") not in ALLOWED_STATUSES:
        return False
    checkout_sha = report.get("checkout_sha")
    if type(checkout_sha) is not str or not _HEX40_RE.match(checkout_sha):
        return False
    core_sha256 = report.get("core_sha256")
    if (not isinstance(core_sha256, dict)
            or set(core_sha256) != {"wamd", "wam-cli"}
            or any(type(v) is not str or not _HEX64_RE.match(v) for v in core_sha256.values())):
        return False
    if report.get("accepted") is not False or report.get("mainnet_allowed") is not False:
        return False
    scenarios = report.get("scenarios")
    if not isinstance(scenarios, dict) or set(scenarios) != set(REQUIRED_SCENARIOS):
        return False
    if not all(validate_scenario_report(scenarios[k]) for k in REQUIRED_SCENARIOS):
        return False
    expected_one_quit = all(scenarios[k]["one_quit"] is True for k in REQUIRED_SCENARIOS)
    expected_orphan_free = all(scenarios[k]["orphan_free"] is True for k in REQUIRED_SCENARIOS)
    if report.get("one_quit") is not expected_one_quit:
        return False
    if report.get("orphan_free") is not expected_orphan_free:
        return False
    if report["status"] == "PASS":
        return (
            report.get("source_unchanged") is True
            and report.get("one_quit") is True
            and report.get("orphan_free") is True
            and report.get("exit_code") == 0
            and all(scenarios[k]["status"] == "PASS" for k in REQUIRED_SCENARIOS)
        )
    return type(report.get("exit_code")) is int and report["exit_code"] != 0


def validate_cli_scope(args, project_root: Path) -> None:
    """Enforce disposable-regtest consent, absolute paths, and external output dir."""
    if getattr(sys, "frozen", False):
        raise ValueError("Q05_DQUIT1_SOURCE_ONLY_DENIED")
    if args.confirm_disposable_regtest is not True:
        raise ValueError("Q05_DQUIT1_CONSENT_REQUIRED")
    for path in (args.core, args.core_archive, args.signed_manifest_dir,
                 args.wsp_source, args.output):
        if not path.is_absolute():
            raise ValueError("Q05_DQUIT1_ABSOLUTE_PATH_REQUIRED")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Q05_DQUIT1_NEW_OUTPUT_REQUIRED")
    if args.output.resolve().is_relative_to(project_root.resolve()):
        raise ValueError("Q05_DQUIT1_EXTERNAL_OUTPUT_REQUIRED")


def _new_scenario_record(scenario_id: str, name: str, profile_name: str) -> dict:
    return {
        "scenario_id": scenario_id,
        "name": name,
        "profile_fixture_id": profile_name,
        "status": "FAIL",
        "stage": "SETUP",
        "failure_code": "Q05_DQUIT1_NOT_RUN",
        "test_layer": "FAULT_INJECTED_REAL_CORE",
        "fault_boundary": FAULT_BOUNDARIES[scenario_id],
        "one_quit": False,
        "quit_count": 0,
        "orphan_free": False,
        "observed_exit": None,
        "reopen_observed_exit": None,
        "core_stopped": False,
        "lease_released_only_after_notice": False,
        "assertions": {},
        "events": [],
    }


def _lease_order_holds(backend: QualificationQ05Backend) -> bool:
    events = backend.events
    if ("PUBLISH_NOTICE" not in events or "OWNER_RELEASE" not in events
            or "OWNER_CLOSE" not in events):
        return False
    if not backend.lease_checks:
        return False
    last_check = backend.lease_checks[-1]
    if not (last_check["lease_held_before"] and last_check["lease_held_after"]):
        return False
    pub_idx = events.index("PUBLISH_NOTICE")
    rel_idx = events.index("OWNER_RELEASE")
    cls_idx = events.index("OWNER_CLOSE")
    return pub_idx < rel_idx < cls_idx


def _cleanup_executor(executor: QualificationQ05Executor | None) -> tuple[bool, int | None]:
    if executor is None:
        return True, None
    backend = getattr(executor, "_backend", None)
    if not executor.closed:
        try:
            executor.request("quit", timeout=60)
        except Exception:
            pass
    joined = executor.join(10)
    if backend is None or not backend.spawned_popens:
        return joined, None
    all_orphan_free = True
    last_exit = None
    for popen, pid in backend.spawned_popens:
        stopped, code, orphan_free = check_popen_stopped(popen, pid)
        last_exit = code
        if not stopped or not orphan_free:
            all_orphan_free = False
    return joined and all_orphan_free, last_exit


def _run_scenario_a(
    *,
    profile_parent: Path,
    core_dir: Path,
    wsp_source: Path,
    adapter,
    mining_address: str,
) -> tuple[dict, bool]:
    """S-Q05-A: faulted-then-reopen (N-d-Q05)."""
    from ..quit_notice import unacknowledged
    from ..supervisor_store import held_lease
    from wam_sp.wallet import Signer

    profile_root = profile_parent / f"wam-fusion-core-{secrets.token_hex(8)}"
    record = _new_scenario_record("S-Q05-A", "faulted-then-reopen", profile_root.name)
    executor1 = executor2 = None
    prior_uncertain = False
    try:
        record["stage"] = "CREATE_SESSION"
        executor1 = QualificationQ05Executor(
            lambda: QualificationQ05Backend(
                profile_root, core_dir, wsp_source,
                mining_address=mining_address, _anchor_factory=adapter.make_anchor,
            )
        )
        initial = executor1.request("engine_open_owned", _PASSWORD, create=True, timeout=120)
        backend1 = executor1._backend
        popen1, pid1 = backend1.spawned_popens[0]
        if initial.height != 0 or popen1.poll() is not None:
            raise ValueError("Q05_DQUIT1_INITIAL_SESSION_UNEXPECTED")

        record["stage"] = "FIXTURE_FUND_AND_PREPARE"
        funded = executor1.request("fixture_fund", timeout=120)
        snap = executor1.request("snapshot", timeout=120)
        if snap.confirmed_atoms != funded["atoms"] or snap.height < funded["height"]:
            raise ValueError("Q05_DQUIT1_FUNDING_MISMATCH")
        review = executor1.request("engine_prepare_auto", funded["recipient"], 100_000, timeout=120)

        record["stage"] = "FAULT_INJECT_SIGNER_CRYPTO_FAILURE"
        def fault_sign(*_args, **_kwargs):
            raise ValueError("Q05_DQUIT1_INJECTED_CRYPTO_FAILURE")

        with patch.object(Signer, "sign", fault_sign):
            try:
                executor1.request("engine_sign", review.commitment, timeout=120)
                raise ValueError("Q05_DQUIT1_FAULT_NOT_TRIGGERED")
            except WalletExecutorError as error:
                sign_refusal = map_refusal_code(error)
        if sign_refusal != "WALLET_SIGN_UNCERTAIN_LOCK_RETAINED":
            raise ValueError("Q05_DQUIT1_UNEXPECTED_SIGN_REFUSAL")
        if backend1.session.faulted is not True or executor1.state.faulted is not True:
            raise ValueError("Q05_DQUIT1_SESSION_NOT_FAULTED")

        record["stage"] = "QUIT_ONCE_FAULTED"
        quit_res = plain_value(executor1.request("quit", timeout=60))
        joined1 = executor1.join(10)
        stopped1, observed_exit1, orphan_free1 = check_popen_stopped(popen1, pid1)
        record["quit_count"] = backend1.quit_count
        record["one_quit"] = backend1.quit_count == 1
        record["observed_exit"] = observed_exit1
        record["core_stopped"] = stopped1 and executor1.state.core_alive is False
        record["orphan_free"] = orphan_free1
        record["events"].extend(backend1.events)
        lease_released = held_lease(profile_root) is None
        lease_after_notice = lease_released and _lease_order_holds(backend1)
        record["lease_released_only_after_notice"] = lease_after_notice
        record["quit_result"] = quit_res

        runtime_path = profile_root / "chain" / "wallet-runtime.sqlite"
        profile_id = backend1.owner.profile["profile_id"]
        notices = unacknowledged(profile_root, expected_profile_id=profile_id)
        if not (joined1 and stopped1 and orphan_free1 and lease_after_notice
                and quit_res.get("runtime_preserved") is True
                and runtime_path.exists() and len(notices) == 1):
            raise ValueError("Q05_DQUIT1_FAULTED_QUIT_INVARIANT_FAILED")
        record["notice"] = plain_value(notices[0]["notice"])

        record["stage"] = "REOPEN_REFUSED_BEFORE_ACK"
        keychain2 = adapter.reopen_anchor(profile_root)
        executor2 = QualificationQ05Executor(
            lambda: QualificationQ05Backend(
                profile_root, core_dir, wsp_source,
                keychain=keychain2, mining_address=mining_address,
            )
        )
        try:
            executor2.request("open", _PASSWORD, create=False, timeout=120)
            raise ValueError("Q05_DQUIT1_REOPEN_BYPASSED_NOTICE")
        except WalletExecutorError as error:
            refused_before_ack = map_refusal_code(error)
        if refused_before_ack != "QUIT_NOTICE_REVIEW_REQUIRED":
            raise ValueError("Q05_DQUIT1_REOPEN_UNEXPECTED_REFUSAL")

        backend2 = executor2._backend
        popen2, pid2 = backend2.spawned_popens[0]
        listed = plain_value(executor2.request("quit_notices", timeout=30))
        if listed["count"] != 1:
            raise ValueError("Q05_DQUIT1_NOTICE_NOT_SURFACED")

        record["stage"] = "ACKNOWLEDGE_AND_RECOVER_AND_REOPEN"
        acked = plain_value(executor2.request("acknowledge_quit_notices", timeout=30))
        if acked["count"] != 1:
            raise ValueError("Q05_DQUIT1_ACK_COUNT_MISMATCH")
        try:
            executor2.request("open", _PASSWORD, create=False, timeout=120)
            raise ValueError("Q05_DQUIT1_PRIOR_RUNTIME_BYPASSED")
        except WalletExecutorError as error:
            refused_prior_runtime = map_refusal_code(error)
        if refused_prior_runtime != "WALLET_MANAGED_OPEN_DENIED":
            raise ValueError("Q05_DQUIT1_UNEXPECTED_PRIOR_RUNTIME_REFUSAL")

        recovered = plain_value(executor2.request("engine_recover", _PASSWORD, timeout=120))
        reopened = executor2.request("open", _PASSWORD, create=False, timeout=120)
        if (reopened.confirmed_atoms != funded["atoms"]
                or list(reopened.reservation_states or ()) != ["signed"]):
            raise ValueError("Q05_DQUIT1_REOPEN_STATE_DIVERGED")

        record["stage"] = "REOPEN_CLEAN_QUIT"
        quit2 = plain_value(executor2.request("quit", timeout=60))
        joined2 = executor2.join(10)
        stopped2, observed_exit2, orphan_free2 = check_popen_stopped(popen2, pid2)
        record["reopen_observed_exit"] = observed_exit2
        record["orphan_free"] = bool(record["orphan_free"] and orphan_free2)
        record["events"].extend("REOPEN_" + e for e in backend2.events)

        record["reopen"] = {
            "refused_before_ack_code": refused_before_ack,
            "unresolved_notice_count": listed["count"],
            "acknowledged_count": acked["count"],
            "refused_after_ack_before_recovery_code": refused_prior_runtime,
            "explicit_recovery_completed": True,
            "reopened_after_ack_and_recovery": True,
            "preserved_reservation_states": list(reopened.reservation_states or ()),
            "runtime_preserved_on_disk": runtime_path.exists(),
            "reopen_clean_quit": bool(joined2 and stopped2 and orphan_free2 and quit2["runtime_preserved"] is False),
        }
        record["assertions"] = {
            "fault_triggered": sign_refusal == "WALLET_SIGN_UNCERTAIN_LOCK_RETAINED",
            "one_quit": record["one_quit"],
            "core_stopped": record["core_stopped"],
            "orphan_free": record["orphan_free"],
            "lease_released_only_after_notice": lease_after_notice,
            "reopen_refused_quit_notice": refused_before_ack == "QUIT_NOTICE_REVIEW_REQUIRED",
            "prior_runtime_preserved_before_recovery": refused_prior_runtime == "WALLET_MANAGED_OPEN_DENIED",
            "reopen_allowed_after_ack_and_recovery": True,
            "reservation_preserved_across_fault_and_recovery": list(recovered["reservation_states"]) == ["signed"],
            "reopen_core_stopped_clean": bool(joined2 and stopped2 and orphan_free2),
        }
        record["stage"] = "COMPLETED"
        record["failure_code"] = None
        record["status"] = "PASS"
    except Exception as error:
        record["status"] = "FAIL"
        record["failure_type"] = type(error).__name__
        record["failure_code"] = map_refusal_code(error)
    finally:
        cleanup_ok = True
        for ex in (executor2, executor1):
            ok, last_exit = _cleanup_executor(ex)
            if not ok:
                cleanup_ok = False
                record["orphan_free"] = False
                prior_uncertain = True
            if record["observed_exit"] is None and ex is executor1 and last_exit is not None:
                record["observed_exit"] = last_exit
        if record["status"] != "PASS":
            record["orphan_free"] = cleanup_ok and not prior_uncertain
            record["core_stopped"] = cleanup_ok and record["observed_exit"] is not None
    return record, prior_uncertain


def _run_scenario_b(
    *,
    profile_parent: Path,
    core_dir: Path,
    wsp_source: Path,
    adapter,
    mining_address: str,
) -> tuple[dict, bool]:
    """S-Q05-B: uncertain-checkpoint Quit."""
    from .. import custody
    from ..quit_notice import unacknowledged
    from ..supervisor_store import held_lease
    from ..vault import CheckpointVault

    profile_root = profile_parent / f"wam-fusion-core-{secrets.token_hex(8)}"
    record = _new_scenario_record("S-Q05-B", "uncertain-checkpoint-quit", profile_root.name)
    executor1 = executor2 = None
    prior_uncertain = False
    try:
        record["stage"] = "CREATE_SESSION"
        executor1 = QualificationQ05Executor(
            lambda: QualificationQ05Backend(
                profile_root, core_dir, wsp_source,
                mining_address=mining_address, _anchor_factory=adapter.make_anchor,
            )
        )
        initial = executor1.request("engine_open_owned", _PASSWORD, create=True, timeout=120)
        backend1 = executor1._backend
        popen1, pid1 = backend1.spawned_popens[0]
        if initial.height != 0 or popen1.poll() is not None:
            raise ValueError("Q05_DQUIT1_INITIAL_SESSION_UNEXPECTED")

        record["stage"] = "FAULT_INJECT_UNCERTAIN_CHECKPOINT"
        store = custody.storage()
        orig_publish = store.publish
        folder = profile_root / "chain" / "wallet-vault"
        next_name = CheckpointVault._filename(len(list(folder.glob("snapshot-*.enc"))) + 1)

        def cut_after_publish(directory, name, blob):
            orig_publish(directory, name, blob)
            if directory == folder and name == next_name:
                raise _AfterPublicationCut("Q05_DQUIT1_CUT_AFTER_PUBLICATION")

        with patch.object(store, "publish", cut_after_publish):
            try:
                executor1.request("engine_mine", timeout=120)
                raise ValueError("Q05_DQUIT1_CHECKPOINT_CUT_NOT_TRIGGERED")
            except WalletExecutorError as error:
                save_refusal = map_refusal_code(error)
        if save_refusal != "WALLET_ANCHORED_SAVE_FAILED":
            raise ValueError("Q05_DQUIT1_UNEXPECTED_SAVE_REFUSAL")
        if not getattr(backend1.session, "_managed_checkpoint_uncertain", False):
            raise ValueError("Q05_DQUIT1_CHECKPOINT_NOT_UNCERTAIN")

        record["stage"] = "QUIT_ONCE_UNCERTAIN_CHECKPOINT"
        quit_res = plain_value(executor1.request("quit", timeout=60))
        joined1 = executor1.join(10)
        stopped1, observed_exit1, orphan_free1 = check_popen_stopped(popen1, pid1)
        record["quit_count"] = backend1.quit_count
        record["one_quit"] = backend1.quit_count == 1
        record["observed_exit"] = observed_exit1
        record["core_stopped"] = stopped1 and executor1.state.core_alive is False
        record["orphan_free"] = orphan_free1
        record["events"].extend(backend1.events)
        lease_released = held_lease(profile_root) is None
        lease_after_notice = lease_released and _lease_order_holds(backend1)
        record["lease_released_only_after_notice"] = lease_after_notice
        record["quit_result"] = quit_res

        runtime_path = profile_root / "chain" / "wallet-runtime.sqlite"
        orphan_enc = folder / next_name
        profile_id = backend1.owner.profile["profile_id"]
        notices = unacknowledged(profile_root, expected_profile_id=profile_id)
        if not (joined1 and stopped1 and orphan_free1 and lease_after_notice
                and quit_res.get("runtime_preserved") is True
                and executor1.state.runtime_preserved is True
                and runtime_path.exists() and orphan_enc.exists() and len(notices) == 1):
            raise ValueError("Q05_DQUIT1_UNCERTAIN_QUIT_INVARIANT_FAILED")
        record["notice"] = plain_value(notices[0]["notice"])

        record["stage"] = "REOPEN_SURFACES_UNCERTAIN"
        keychain2 = adapter.reopen_anchor(profile_root)
        executor2 = QualificationQ05Executor(
            lambda: QualificationQ05Backend(
                profile_root, core_dir, wsp_source,
                keychain=keychain2, mining_address=mining_address,
            )
        )
        try:
            executor2.request("open", _PASSWORD, create=False, timeout=120)
            raise ValueError("Q05_DQUIT1_REOPEN_BYPASSED_UNCERTAIN")
        except WalletExecutorError as error:
            reopen_refusal = map_refusal_code(error)
        if reopen_refusal != "QUIT_NOTICE_REVIEW_REQUIRED":
            raise ValueError("Q05_DQUIT1_REOPEN_UNEXPECTED_REFUSAL")

        backend2 = executor2._backend
        popen2, pid2 = backend2.spawned_popens[0]
        listed = plain_value(executor2.request("quit_notices", timeout=30))
        if listed["count"] != 1:
            raise ValueError("Q05_DQUIT1_UNCERTAIN_NOTICE_MISSING")
        surfaced = listed["notices"][0]["notice"]
        if surfaced["wallet_outcome"] != "RUNTIME_PRESERVED":
            raise ValueError("Q05_DQUIT1_NOTICE_NOT_PRESERVED")

        record["stage"] = "REOPEN_CLEAN_QUIT"
        quit2 = plain_value(executor2.request("quit", timeout=60))
        joined2 = executor2.join(10)
        stopped2, observed_exit2, orphan_free2 = check_popen_stopped(popen2, pid2)
        record["reopen_observed_exit"] = observed_exit2
        record["orphan_free"] = bool(record["orphan_free"] and orphan_free2)
        record["events"].extend("REOPEN_" + e for e in backend2.events)

        record["reopen"] = {
            "checkpoint_uncertain_at_quit": True,
            "quit_reported_uncertain_preserved": quit_res["runtime_preserved"] is True,
            "reopen_refused_code": reopen_refusal,
            "reopen_surfaced_notices_count": listed["count"],
            "reopen_surfaced_wallet_outcome": surfaced["wallet_outcome"],
            "reopen_surfaced_core_stop": surfaced["core_stop"],
            "reopen_surfaced_codes": list(surfaced["codes"]),
            "orphan_ciphertext_preserved": orphan_enc.exists(),
            "runtime_preserved_on_disk": runtime_path.exists(),
            "reopen_clean_quit": bool(joined2 and stopped2 and orphan_free2 and quit2["runtime_preserved"] is False),
        }
        record["assertions"] = {
            "uncertain_checkpoint_triggered": save_refusal == "WALLET_ANCHORED_SAVE_FAILED",
            "one_quit": record["one_quit"],
            "core_stopped": record["core_stopped"],
            "orphan_free": record["orphan_free"],
            "lease_released_only_after_notice": lease_after_notice,
            "quit_outcome_reported_preserved_never_clean": (
                quit_res["runtime_preserved"] is True
                and surfaced["wallet_outcome"] == "RUNTIME_PRESERVED"
            ),
            "reopen_refused_and_surfaced_notice": (
                reopen_refusal == "QUIT_NOTICE_REVIEW_REQUIRED" and listed["count"] == 1
            ),
            "reopen_core_stopped_clean": bool(joined2 and stopped2 and orphan_free2),
        }
        record["stage"] = "COMPLETED"
        record["failure_code"] = None
        record["status"] = "PASS"
    except Exception as error:
        record["status"] = "FAIL"
        record["failure_type"] = type(error).__name__
        record["failure_code"] = map_refusal_code(error)
    finally:
        cleanup_ok = True
        for ex in (executor2, executor1):
            ok, last_exit = _cleanup_executor(ex)
            if not ok:
                cleanup_ok = False
                record["orphan_free"] = False
                prior_uncertain = True
            if record["observed_exit"] is None and ex is executor1 and last_exit is not None:
                record["observed_exit"] = last_exit
        if record["status"] != "PASS":
            record["orphan_free"] = cleanup_ok and not prior_uncertain
            record["core_stopped"] = cleanup_ok and record["observed_exit"] is not None
    return record, prior_uncertain


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", "--core-dir", dest="core", required=True, type=Path)
    parser.add_argument("--core-archive", required=True, type=Path)
    parser.add_argument("--signed-manifest-dir", required=True, type=Path)
    parser.add_argument("--wsp-source", required=True, type=Path)
    parser.add_argument("--output", "--output-dir", dest="output", required=True, type=Path)
    parser.add_argument("--gpg", default="gpg")
    parser.add_argument(
        "--confirm-disposable-regtest",
        "--consent-disposable-regtest",
        dest="confirm_disposable_regtest",
        action="store_true",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    project_root = Path(__file__).resolve().parents[3]
    try:
        validate_cli_scope(args, project_root)
    except ValueError as error:
        raise SystemExit(map_refusal_code(error)) from None

    from ..probe_source import verify_source
    from ..q05_platforms import DarwinArm64Adapter
    from ..wsp_live import _pinned_source, public_regtest_mining_address
    from .fee_regtest_runner import authenticate

    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    started_utc = datetime.now(timezone.utc).isoformat()
    checkout_sha = subprocess.check_output(
        ["git", "-C", str(project_root), "rev-parse", "HEAD"], text=True
    ).strip()

    setup_code = None
    proof = None
    core_identity = None
    adapter = None
    mining_address = None
    try:
        if sys.platform != "darwin" or platform.machine().lower() != "arm64":
            raise _BlockedSetup("Q05_DQUIT1_NATIVE_MACOS_ARM64_REQUIRED")
        adapter = DarwinArm64Adapter()
        adapter.enforce_host()
        proof = verify_source(project_root)
        _pinned_source(args.wsp_source)
        core_identity = authenticate(
            args.core, args.core_archive, args.gpg, args.signed_manifest_dir
        )
        mining_address = public_regtest_mining_address(args.wsp_source)
    except Exception as error:
        setup_code = map_refusal_code(error)

    profile_parent = Path(tempfile.mkdtemp(prefix="wam-q05-dquit1-")).resolve(strict=True)
    scenarios = {}
    prior_uncertain = False
    for scenario_id, name, runner in (
        ("S-Q05-A", "faulted-then-reopen", _run_scenario_a),
        ("S-Q05-B", "uncertain-checkpoint-quit", _run_scenario_b),
    ):
        if setup_code is not None or prior_uncertain:
            rec = _new_scenario_record(scenario_id, name, "not-created")
            rec["status"] = "BLOCKED"
            rec["stage"] = "SETUP"
            rec["failure_code"] = (
                "Q05_DQUIT1_PRIOR_OWNER_UNCERTAIN" if prior_uncertain else setup_code
            )
        else:
            rec, leaked = runner(
                profile_parent=profile_parent,
                core_dir=args.core,
                wsp_source=args.wsp_source,
                adapter=adapter,
                mining_address=mining_address,
            )
            prior_uncertain = prior_uncertain or leaked
        scenarios[scenario_id] = rec
        print(f"Q05_DQUIT1 {scenario_id} {rec['status']} code={rec['failure_code']}", flush=True)

    source_unchanged = False
    if proof is not None:
        try:
            source_unchanged = verify_source(project_root) == proof
        except Exception:
            source_unchanged = False

    status = aggregate_run_status(scenarios, source_unchanged=source_unchanged)
    core_sha256 = (
        dict(core_identity["members"])
        if isinstance(core_identity, dict) and isinstance(core_identity.get("members"), dict)
        else {"wamd": "", "wam-cli": ""}
    )
    report = {
        "schema": SCHEMA,
        "status": status,
        "checkout_sha": checkout_sha,
        "source_provenance": proof,
        "source_unchanged": source_unchanged,
        "core": core_identity,
        "core_sha256": core_sha256,
        "wsp_source_commit": WSP_COMMIT,
        "platform": adapter.platform_id if adapter is not None else f"{platform.system().lower()}-{platform.machine().lower()}",
        "python_version": platform.python_version(),
        "command": [sys.executable, str(Path(__file__).name), *(argv if argv is not None else sys.argv[1:])],
        "started_utc": started_utc,
        "ended_utc": datetime.now(timezone.utc).isoformat(),
        "one_quit": all(scenarios[k]["one_quit"] is True for k in REQUIRED_SCENARIOS),
        "orphan_free": all(scenarios[k]["orphan_free"] is True for k in REQUIRED_SCENARIOS),
        "accepted": False,
        "mainnet_allowed": False,
        "exit_code": 0 if status == "PASS" else 2,
        "scenarios": scenarios,
    }
    if status == "PASS" and not validate_run_report(report):
        report["status"] = "FAIL"
        report["exit_code"] = 2
        report["failure_code"] = "Q05_DQUIT1_REPORT_CONTRACT_INCOMPLETE"

    report_path = args.output / "report.json"
    with report_path.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")

    if prior_uncertain:
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(2)
    return report["exit_code"]
