"""PM-075 / D-QUIT-1 gate evidence qualification runner (R-n1/R-n2, T1, T2).

Qualification-only module; never imported by production code. Produces
exact-candidate JSON receipts in an outside-checkout directory for:
  1. R-n1 / R-n2 real SIGKILL process-crash tests on APFS (I3);
  2. T1 exit-budget measurement (>=10 genuine stop reply -> exit samples on signed Core v0.1.13);
  3. T2 byte identity across the stop on genuine Q06 faulted Quit (F3-14/crypto-failure + lost-send-response).
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

from .q05_dquit1_runner import (
    WSP_COMMIT,
    check_popen_stopped,
    map_refusal_code,
    pid_is_alive,
    plain_value,
)

CRASH_SCHEMA = "wam-dquit1-rn1-rn2-crash/v1"
T1_SCHEMA = "wam-dquit1-t1-exit-budget/v1"
T2_SCHEMA = "wam-dquit1-t2-byte-identity/v1"

ALLOWED_MODES = ("crash", "t1", "t2", "all")
ALLOWED_STATUSES = frozenset(("PASS", "FAIL", "BLOCKED"))
REQUIRED_CRASH_CASES = ("R-n1-Q06", "R-n1-Q05", "R-n2-Q06", "R-n2-Q05", "R-n2-ACK")
MIN_T1_SAMPLES = 10
DEFAULT_T1_SAMPLES = 12
T2_SCENARIO_NAMES = ("crypto-failure", "lost-send-response")

_HEX40_RE = re.compile(r"^[0-9a-f]{40}\Z")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}\Z")
_SQLITE_NAME_RE = re.compile(r"^wallet-runtime.*\.sqlite(?:-wal|-shm|-journal|\.scan\.lock)?\Z")
_PROFILE_ID = "b" * 32


def validate_cli_scope(args, project_root: Path) -> None:
    """Enforce source-only execution, disposable consent, absolute paths, and external output."""
    if getattr(sys, "frozen", False):
        raise ValueError("DQUIT1_GATE_SOURCE_ONLY_DENIED")
    if args.mode not in ALLOWED_MODES:
        raise ValueError("DQUIT1_GATE_MODE_DENIED")
    if args.confirm_disposable_regtest is not True:
        raise ValueError("DQUIT1_GATE_CONSENT_REQUIRED")
    if args.mode in ("t1", "all") and (type(args.t1_samples) is not int or args.t1_samples < MIN_T1_SAMPLES):
        raise ValueError("DQUIT1_GATE_T1_MIN_SAMPLES_REQUIRED")
    if not args.output.is_absolute():
        raise ValueError("DQUIT1_GATE_ABSOLUTE_PATH_REQUIRED")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("DQUIT1_GATE_NEW_OUTPUT_REQUIRED")
    if args.output.resolve().is_relative_to(project_root.resolve()):
        raise ValueError("DQUIT1_GATE_EXTERNAL_OUTPUT_REQUIRED")
    if args.mode in ("t1", "t2", "all"):
        required_paths = (args.core, args.core_archive, args.signed_manifest_dir, args.wsp_source)
        if any(p is None for p in required_paths):
            raise ValueError("DQUIT1_GATE_CORE_INPUTS_REQUIRED")
        if any(not p.is_absolute() for p in required_paths):
            raise ValueError("DQUIT1_GATE_ABSOLUTE_PATH_REQUIRED")


def require_apfs_filesystem(path: Path) -> str:
    """Verify on macOS that the given directory resides on APFS."""
    if sys.platform != "darwin":
        return platform.system().lower()
    res = subprocess.run(
        ["df", "-T", "apfs", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        raise ValueError("DQUIT1_GATE_APFS_REQUIRED")
    return "apfs"


def summarize_exit_samples(
    samples: list[dict],
    budget_s: int | float,
    *,
    min_samples: int = MIN_T1_SAMPLES,
) -> dict:
    """Compute min/median/max and budget compliance over T1 stop reply -> exit samples."""
    if type(budget_s) not in (int, float) or not math.isfinite(budget_s) or budget_s <= 0:
        raise ValueError("DQUIT1_GATE_INVALID_BUDGET")
    if not isinstance(samples, list) or len(samples) < min_samples:
        raise ValueError("DQUIT1_GATE_INSUFFICIENT_SAMPLES")
    durations: list[float] = []
    all_exit_zero = True
    all_orphan_free = True
    for item in samples:
        if not isinstance(item, dict):
            raise ValueError("DQUIT1_GATE_INVALID_SAMPLE")
        val = item.get("reply_to_exit_s")
        if type(val) not in (int, float) or not math.isfinite(val) or val < 0:
            raise ValueError("DQUIT1_GATE_INVALID_SAMPLE")
        durations.append(float(val))
        if item.get("observed_exit_code") != 0:
            all_exit_zero = False
        if item.get("orphan_free") is not True:
            all_orphan_free = False
    min_s = min(durations)
    median_s = float(statistics.median(durations))
    max_s = max(durations)
    mean_s = float(statistics.mean(durations))
    all_fit = all(d <= budget_s for d in durations)
    return {
        "sample_count": len(durations),
        "min_required_samples": min_samples,
        "stop_exit_budget_s": budget_s,
        "min_reply_to_exit_s": round(min_s, 6),
        "median_reply_to_exit_s": round(median_s, 6),
        "max_reply_to_exit_s": round(max_s, 6),
        "mean_reply_to_exit_s": round(mean_s, 6),
        "max_budget_ratio": round(max_s / float(budget_s), 6),
        "all_samples_fit_budget": all_fit,
        "all_exit_zero": all_exit_zero,
        "all_orphan_free": all_orphan_free,
    }


def _hash_regular_file(path: Path, rel_path: str) -> dict:
    if path.is_symlink():
        raise ValueError("DQUIT1_GATE_SYMLINK_DENIED")
    data = path.read_bytes()
    return {
        "path": rel_path,
        "size": len(data),
        "sha256": sha256(data).hexdigest(),
    }


def snapshot_wallet_files(chain_dir: Path) -> dict[str, list[dict]]:
    """Record deterministic size + sha256 lists for WSP SQLite, payment evidence, and checkpoints."""
    chain_dir = Path(chain_dir)
    if chain_dir.is_symlink() or not chain_dir.is_dir():
        raise ValueError("DQUIT1_GATE_CHAIN_DIR_DENIED")
    wsp_sqlite: list[dict] = []
    payment_evidence: list[dict] = []
    native_checkpoint: list[dict] = []

    for entry in sorted(chain_dir.iterdir(), key=lambda p: p.name):
        if _SQLITE_NAME_RE.match(entry.name):
            if entry.is_symlink() or not entry.is_file():
                raise ValueError("DQUIT1_GATE_SYMLINK_DENIED")
            wsp_sqlite.append(_hash_regular_file(entry, entry.name))
        elif entry.name == "q06-payment-evidence":
            if entry.is_symlink() or not entry.is_dir():
                raise ValueError("DQUIT1_GATE_SYMLINK_DENIED")
            for sub in sorted(entry.rglob("*"), key=lambda p: p.as_posix()):
                if sub.is_symlink():
                    raise ValueError("DQUIT1_GATE_SYMLINK_DENIED")
                if sub.is_file():
                    payment_evidence.append(
                        _hash_regular_file(sub, sub.relative_to(chain_dir).as_posix())
                    )
        elif entry.name.startswith("bip39-12-"):
            if entry.is_symlink() or not entry.is_dir():
                raise ValueError("DQUIT1_GATE_SYMLINK_DENIED")
            for sub in sorted(entry.rglob("*"), key=lambda p: p.as_posix()):
                if sub.is_symlink():
                    raise ValueError("DQUIT1_GATE_SYMLINK_DENIED")
                if sub.is_file():
                    native_checkpoint.append(
                        _hash_regular_file(sub, sub.relative_to(chain_dir).as_posix())
                    )

    return {
        "wsp_sqlite": wsp_sqlite,
        "payment_evidence": payment_evidence,
        "native_checkpoint": native_checkpoint,
    }


def compare_file_snapshots(
    before: dict[str, list[dict]],
    after: dict[str, list[dict]],
    *,
    categories: tuple[str, ...] = ("wsp_sqlite", "payment_evidence"),
    expected_reasons: dict[str, str] | None = None,
) -> dict:
    """Compare selected file snapshot categories and report exact diffs."""
    reasons = expected_reasons or {}
    before_map: dict[tuple[str, str], dict] = {}
    after_map: dict[tuple[str, str], dict] = {}
    for cat in categories:
        for item in before.get(cat, ()):
            before_map[(cat, item["path"])] = item
        for item in after.get(cat, ()):
            after_map[(cat, item["path"])] = item

    changed_files: list[dict] = []
    for key in sorted(set(before_map) | set(after_map)):
        cat, rel_path = key
        b = before_map.get(key)
        a = after_map.get(key)
        if b is None:
            changed_files.append({
                "category": cat,
                "path": rel_path,
                "change_kind": "added",
                "before_sha256": None,
                "after_sha256": a["sha256"],
                "before_size": None,
                "after_size": a["size"],
                "expected_reason": reasons.get(rel_path),
            })
        elif a is None:
            changed_files.append({
                "category": cat,
                "path": rel_path,
                "change_kind": "removed",
                "before_sha256": b["sha256"],
                "after_sha256": None,
                "before_size": b["size"],
                "after_size": None,
                "expected_reason": reasons.get(rel_path),
            })
        elif b["sha256"] != a["sha256"] or b["size"] != a["size"]:
            changed_files.append({
                "category": cat,
                "path": rel_path,
                "change_kind": "modified",
                "before_sha256": b["sha256"],
                "after_sha256": a["sha256"],
                "before_size": b["size"],
                "after_size": a["size"],
                "expected_reason": reasons.get(rel_path),
            })

    return {
        "categories": list(categories),
        "before_count": len(before_map),
        "after_count": len(after_map),
        "byte_identical": len(changed_files) == 0,
        "changed_files": changed_files,
    }


def _valid_common_header(receipt: dict, schema: str) -> bool:
    if not isinstance(receipt, dict) or receipt.get("schema") != schema:
        return False
    if receipt.get("status") not in ALLOWED_STATUSES:
        return False
    checkout_sha = receipt.get("checkout_sha")
    if type(checkout_sha) is not str or not _HEX40_RE.match(checkout_sha):
        return False
    if receipt.get("accepted") is not False or receipt.get("mainnet_allowed") is not False:
        return False
    if receipt["status"] == "PASS":
        return receipt.get("source_unchanged") is True and receipt.get("exit_code") == 0
    return type(receipt.get("exit_code")) is int and receipt["exit_code"] != 0


def _valid_core_pins(receipt: dict) -> bool:
    core_sha = receipt.get("core_sha256")
    return (
        isinstance(core_sha, dict)
        and set(core_sha) == {"wamd", "wam-cli"}
        and all(type(v) is str and _HEX64_RE.match(v) for v in core_sha.values())
    )


def validate_crash_receipt(receipt: dict) -> bool:
    """Validate the R-n1 / R-n2 real SIGKILL process-crash receipt."""
    if not _valid_common_header(receipt, CRASH_SCHEMA):
        return False
    cases = receipt.get("cases")
    if not isinstance(cases, dict) or set(cases) != set(REQUIRED_CRASH_CASES):
        return False
    for cid in REQUIRED_CRASH_CASES:
        case = cases[cid]
        if not isinstance(case, dict) or case.get("status") not in ALLOWED_STATUSES:
            return False
        if receipt["status"] == "PASS":
            assertions = case.get("assertions")
            if (case.get("status") != "PASS"
                    or case.get("signal_sent") != "SIGKILL"
                    or case.get("observed_returncode") != -9
                    or not isinstance(assertions, dict)
                    or not assertions
                    or not all(v is True for v in assertions.values())):
                return False
    return True


def validate_t1_receipt(receipt: dict) -> bool:
    """Validate the T1 exit-budget measurement receipt."""
    if not _valid_common_header(receipt, T1_SCHEMA) or not _valid_core_pins(receipt):
        return False
    samples = receipt.get("samples")
    summary = receipt.get("summary")
    if not isinstance(samples, list) or not isinstance(summary, dict):
        return False
    if receipt["status"] == "PASS":
        if len(samples) < MIN_T1_SAMPLES:
            return False
        if summary.get("sample_count") != len(samples):
            return False
        if (summary.get("all_samples_fit_budget") is not True
                or summary.get("all_exit_zero") is not True
                or summary.get("all_orphan_free") is not True):
            return False
        budget = receipt.get("stop_exit_budget_s")
        if type(budget) not in (int, float) or summary.get("stop_exit_budget_s") != budget:
            return False
        if not (0 <= summary["min_reply_to_exit_s"]
                <= summary["median_reply_to_exit_s"]
                <= summary["max_reply_to_exit_s"]
                <= budget):
            return False
    return True


def validate_t2_receipt(receipt: dict) -> bool:
    """Validate the T2 genuine Q06 faulted Quit byte-identity receipt."""
    if not _valid_common_header(receipt, T2_SCHEMA) or not _valid_core_pins(receipt):
        return False
    scenarios = receipt.get("scenarios")
    if not isinstance(scenarios, dict) or "F3-14/crypto-failure" not in scenarios:
        return False
    for name, sc in scenarios.items():
        if not isinstance(sc, dict) or sc.get("status") not in ALLOWED_STATUSES:
            return False
        if receipt["status"] == "PASS":
            across_stop = sc.get("across_stop")
            if (sc.get("status") != "PASS"
                    or sc.get("one_quit") is not True
                    or sc.get("quit_count") != 1
                    or sc.get("orphan_free") is not True
                    or sc.get("observed_exit") != 0
                    or sc.get("runtime_preserved") is not True
                    or type(sc.get("wsp_sqlite_file_count")) is not int
                    or sc["wsp_sqlite_file_count"] < 1
                    or not isinstance(across_stop, dict)
                    or across_stop.get("byte_identical") is not True):
                return False
            if name == "F3-14/lost-send-response" and (
                type(sc.get("payment_evidence_file_count")) is not int
                or sc["payment_evidence_file_count"] < 2
            ):
                return False
    return True


def _run_crash_case(
    *,
    case_id: str,
    boundary: str,
    session_kind: str,
    code: str,
    action_kind: str,
    parent_dir: Path,
    project_root: Path,
) -> dict:
    from ..quit_notice import (
        acknowledge_unresolved,
        parse_notice_bytes,
        publish_notice,
        read_store,
        unacknowledged,
    )
    from ..supervisor_store import SupervisorStorageError, exclusive_lease

    case_parent = parent_dir / case_id
    case_parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    fs_type = require_apfs_filesystem(case_parent)
    root = case_parent / f"wam-fusion-core-{secrets.token_hex(8)}"
    root.mkdir(mode=0o700)

    ack_payload = None
    if action_kind == "ack":
        with exclusive_lease(root):
            published = publish_notice(
                root,
                profile_id=_PROFILE_ID,
                session_kind=session_kind,
                wallet_outcome="RUNTIME_PRESERVED",
                core_stop="CLEAN",
                codes=(code,),
                journal_seq=1,
            )
        ack_payload = {
            "kind": "notice",
            "seq": published["seq"],
            "body_sha256": published["body_sha256"],
        }

    pythonpath = os.pathsep.join((
        str(project_root / "src"),
        str(project_root / "wsp-upstream" / "src"),
    ))
    child_code = (
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "from wam_regtest import quit_notice as qn\n"
        "from wam_regtest.supervisor_store import exclusive_lease\n"
        "root = Path(sys.argv[1])\n"
        "profile_id, session_kind, boundary, code = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]\n"
        "journal_seq = int(sys.argv[6])\n"
        "ack_json = sys.argv[7]\n"
        "orig_link, orig_unlink = os.link, os.unlink\n"
        "def _is_stage(name):\n"
        "    return isinstance(name, str) and name.startswith('supervisor.notice.stage-')\n"
        "def _barrier(stage_name):\n"
        "    print(f'BOUNDARY_READY {stage_name}', flush=True)\n"
        "    while os.read(0, 1):\n"
        "        pass\n"
        "    os._exit(99)\n"
        "def _wrapped_link(src, dst, *args, **kwargs):\n"
        "    if boundary == 'before_link' and _is_stage(src):\n"
        "        _barrier(src)\n"
        "    return orig_link(src, dst, *args, **kwargs)\n"
        "def _wrapped_unlink(path, *args, **kwargs):\n"
        "    if boundary == 'before_unlink' and _is_stage(path):\n"
        "        _barrier(path)\n"
        "    return orig_unlink(path, *args, **kwargs)\n"
        "qn.os.link = _wrapped_link\n"
        "qn.os.unlink = _wrapped_unlink\n"
        "with exclusive_lease(root):\n"
        "    if ack_json:\n"
        "        qn.publish_ack(root, json.loads(ack_json))\n"
        "    else:\n"
        "        qn.publish_notice(\n"
        "            root,\n"
        "            profile_id=profile_id,\n"
        "            session_kind=session_kind,\n"
        "            wallet_outcome='RUNTIME_PRESERVED',\n"
        "            core_stop='CLEAN',\n"
        "            codes=(code,),\n"
        "            journal_seq=journal_seq,\n"
        "        )\n"
    )
    env = dict(os.environ, PYTHONPATH=pythonpath)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            child_code,
            str(root),
            _PROFILE_ID,
            session_kind,
            boundary,
            code,
            "2" if boundary == "before_link" else "5",
            json.dumps(ack_payload) if ack_payload is not None else "",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        ready_line = proc.stdout.readline().strip()
        if not ready_line.startswith("BOUNDARY_READY "):
            raise ValueError(f"DQUIT1_CRASH_BARRIER_MISSED:{ready_line!r}")
        stage_name = ready_line.split(" ", 1)[1]
        stage_path = root / stage_name
        final_name = "supervisor.notice-ack.000001" if action_kind == "ack" else "supervisor.notice.000001"
        final_path = root / final_name

        lease_busy_at_barrier = False
        try:
            with exclusive_lease(root):
                pass
        except SupervisorStorageError as err:
            lease_busy_at_barrier = err.args == ("SUPERVISOR_STORAGE_LEASE_BUSY",)

        stage_nlink_before = stage_path.lstat().st_nlink if stage_path.exists() else 0
        final_nlink_before = final_path.lstat().st_nlink if final_path.exists() else 0

        os.kill(proc.pid, signal.SIGKILL)
        returncode = proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            os.kill(proc.pid, signal.SIGKILL)
            proc.wait(timeout=10)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None and not stream.closed:
                stream.close()

    final_present_after = final_path.exists()
    stage_present_after = stage_path.exists()
    ro_store = read_store(root, expected_profile_id=_PROFILE_ID)

    with exclusive_lease(root):
        lease_store = read_store(root, expected_profile_id=_PROFILE_ID)
        stage_exists_after_lease_read = stage_path.exists()
        final_nlink_after_lease_read = final_path.lstat().st_nlink if final_path.exists() else 0

        if boundary == "before_link":
            stage_bytes = stage_path.read_bytes()
            stage_valid = parse_notice_bytes(
                stage_bytes, expected_seq=1, expected_profile_id=_PROFILE_ID
            )["codes"] == [code]
            next_pub = publish_notice(
                root,
                profile_id=_PROFILE_ID,
                session_kind=session_kind,
                wallet_outcome="RUNTIME_PRESERVED",
                core_stop="CLEAN",
                codes=(code,),
                journal_seq=3,
            )
            subsequent_publish_ok = next_pub["seq"] == 1
            acks = acknowledge_unresolved(root, expected_profile_id=_PROFILE_ID)
            ack_ok = len(acks) == 2 and unacknowledged(root, expected_profile_id=_PROFILE_ID) == ()
            assertions = {
                "apfs_verified": sys.platform != "darwin" or fs_type == "apfs",
                "lease_held_at_barrier": lease_busy_at_barrier,
                "sigkill_observed": returncode == -signal.SIGKILL,
                "final_absent_after_crash": not final_present_after,
                "stage_present_and_complete": stage_present_after and stage_valid,
                "reader_tolerates_orphan_stage": (
                    len(ro_store["notices"]) == 0
                    and len(ro_store["unreadable"]) == 1
                    and ro_store["unreadable"][0]["name"] == stage_name
                    and ro_store["unreadable"][0]["reason"] == "NOTICE_STAGE_ORPHAN"
                ),
                "subsequent_publish_never_collides": subsequent_publish_ok,
                "ack_and_preserve_artifacts": (
                    ack_ok and stage_path.exists() and final_path.exists()
                ),
            }
            stage_completed_on_lease_read = False
        else:
            if action_kind == "ack":
                complete_ok = (
                    len(ro_store["notices"]) == 1
                    and len(ro_store["acks"]) == 1
                    and len(ro_store["unreadable"]) == 0
                    and len(lease_store["notices"]) == 1
                    and len(lease_store["acks"]) == 1
                    and len(lease_store["unreadable"]) == 0
                    and not stage_exists_after_lease_read
                    and final_nlink_after_lease_read == 1
                )
                subsequent_publish_ok = True
                ack_ok = unacknowledged(root, expected_profile_id=_PROFILE_ID) == ()
            else:
                final_valid = parse_notice_bytes(
                    final_path.read_bytes(), expected_seq=1, expected_profile_id=_PROFILE_ID
                )["codes"] == [code]
                complete_ok = (
                    final_valid
                    and len(ro_store["notices"]) == 1
                    and len(ro_store["unreadable"]) == 0
                    and len(lease_store["notices"]) == 1
                    and len(lease_store["unreadable"]) == 0
                    and not stage_exists_after_lease_read
                    and final_nlink_after_lease_read == 1
                )
                next_pub = publish_notice(
                    root,
                    profile_id=_PROFILE_ID,
                    session_kind=session_kind,
                    wallet_outcome="RUNTIME_PRESERVED",
                    core_stop="CLEAN",
                    codes=(code,),
                    journal_seq=6,
                )
                subsequent_publish_ok = next_pub["seq"] == 2
                acks = acknowledge_unresolved(root, expected_profile_id=_PROFILE_ID)
                ack_ok = len(acks) == 2 and unacknowledged(root, expected_profile_id=_PROFILE_ID) == ()
            assertions = {
                "apfs_verified": sys.platform != "darwin" or fs_type == "apfs",
                "lease_held_at_barrier": lease_busy_at_barrier,
                "sigkill_observed": returncode == -signal.SIGKILL,
                "linked_pair_nlink_two_before_kill": (
                    stage_nlink_before == 2 and final_nlink_before == 2
                ),
                "reader_accepts_and_completes_under_lease": complete_ok,
                "subsequent_publish_ok": subsequent_publish_ok,
                "ack_and_preserve_final": ack_ok and final_path.exists(),
            }
            stage_completed_on_lease_read = not stage_exists_after_lease_read

    passed = all(v is True for v in assertions.values())
    return {
        "case_id": case_id,
        "boundary": boundary,
        "action_kind": action_kind,
        "session_kind": session_kind,
        "filesystem": fs_type,
        "signal_sent": "SIGKILL",
        "observed_returncode": returncode,
        "stage_name": stage_name,
        "stage_nlink_before_kill": stage_nlink_before,
        "final_nlink_before_kill": final_nlink_before,
        "final_present_after_crash": final_present_after,
        "stage_present_after_crash": stage_present_after,
        "stage_completed_on_lease_read": stage_completed_on_lease_read,
        "reader_without_lease": {
            "notice_count": len(ro_store["notices"]),
            "unreadable_count": len(ro_store["unreadable"]),
            "unreadable_reasons": [u["reason"] for u in ro_store["unreadable"]],
        },
        "reader_with_lease": {
            "notice_count": len(lease_store["notices"]),
            "unreadable_count": len(lease_store["unreadable"]),
        },
        "assertions": assertions,
        "status": "PASS" if passed else "FAIL",
    }


def run_crash_gate(*, project_root: Path, checkout_sha: str, proof: dict | None, output_dir: Path) -> dict:
    """Execute R-n1 / R-n2 real SIGKILL process-crash cases on APFS and write receipt."""
    from ..probe_source import verify_source

    temp_parent = Path(tempfile.mkdtemp(prefix="wam-rn1-rn2-crash-")).resolve(strict=True)
    specs = (
        ("R-n1-Q06", "before_link", "Q06", "Q06_SPEND_RUNTIME_PRESERVED", "notice"),
        ("R-n1-Q05", "before_link", "Q05", "WALLET_MANAGED_RUNTIME_PRESERVED", "notice"),
        ("R-n2-Q06", "before_unlink", "Q06", "Q06_SPEND_RUNTIME_PRESERVED", "notice"),
        ("R-n2-Q05", "before_unlink", "Q05", "WALLET_MANAGED_RUNTIME_PRESERVED", "notice"),
        ("R-n2-ACK", "before_unlink", "Q05", "WALLET_MANAGED_RUNTIME_PRESERVED", "ack"),
    )
    cases: dict[str, dict] = {}
    try:
        for case_id, boundary, session_kind, code, action_kind in specs:
            try:
                rec = _run_crash_case(
                    case_id=case_id,
                    boundary=boundary,
                    session_kind=session_kind,
                    code=code,
                    action_kind=action_kind,
                    parent_dir=temp_parent,
                    project_root=project_root,
                )
            except Exception as exc:
                rec = {
                    "case_id": case_id,
                    "boundary": boundary,
                    "action_kind": action_kind,
                    "session_kind": session_kind,
                    "status": "FAIL",
                    "failure_code": map_refusal_code(exc),
                    "assertions": {},
                }
            cases[case_id] = rec
            print(f"DQUIT1_CRASH {case_id} {rec['status']}", flush=True)
    finally:
        shutil.rmtree(temp_parent, ignore_errors=True)

    source_unchanged = False
    if proof is not None:
        try:
            source_unchanged = verify_source(project_root) == proof
        except Exception:
            source_unchanged = False

    status = (
        "PASS"
        if source_unchanged and all(cases[cid]["status"] == "PASS" for cid in REQUIRED_CRASH_CASES)
        else "FAIL"
    )
    receipt = {
        "schema": CRASH_SCHEMA,
        "status": status,
        "checkout_sha": checkout_sha,
        "source_provenance": proof,
        "source_unchanged": source_unchanged,
        "platform": f"{platform.system().lower()}-{platform.machine().lower()}",
        "python_version": platform.python_version(),
        "accepted": False,
        "mainnet_allowed": False,
        "exit_code": 0 if status == "PASS" else 2,
        "cases": cases,
    }
    if status == "PASS" and not validate_crash_receipt(receipt):
        receipt["status"] = "FAIL"
        receipt["exit_code"] = 2
        receipt["failure_code"] = "DQUIT1_CRASH_RECEIPT_CONTRACT_INCOMPLETE"
    out_path = output_dir / "rn1-rn2-crash-receipt.json"
    with out_path.open("x", encoding="utf-8") as fh:
        json.dump(receipt, fh, indent=2)
        fh.write("\n")
    return receipt


def _populate_mempool_tx(owner, wsp_source: Path) -> str:
    """Mine 101 blocks and submit one regtest tx so Core mempool.dat is non-empty on stop."""
    from ..wallet_session import WalletCoreCli
    from ..wsp_live import public_regtest_mining_address
    from wam_sp.core import Input, pub
    from wam_sp.transaction import p2wpkh, signed_single_input
    from .fee_regtest import exact_atoms
    from decimal import Decimal

    address = public_regtest_mining_address(wsp_source)
    rpc = WalletCoreCli(owner.cli, owner.directory)
    try:
        rpc.attest()
        rpc._call("generatetoaddress", ["101", address])
        block_hash = rpc.call("getblockhash", [1])
        block = rpc._call("getblock", [block_hash, "2"])
        coinbase = block["tx"][0]
        matches = [
            v for v in coinbase["vout"]
            if v["scriptPubKey"].get("hex") == p2wpkh(31).hex()
        ]
        out = matches[0]
        value = exact_atoms(Decimal(str(out["value"])))
        txin = Input(
            coinbase["txid"], out["n"], p2wpkh(31),
            witness=(b"\x30", pub(31)), secret=31,
        )
        raw = signed_single_input(txin, value, ((value - 10_000, p2wpkh(31)),), 31)
        txid = rpc._call("sendrawtransaction", [raw])
        return txid
    finally:
        if getattr(rpc, "_transport", None) is not None:
            rpc._transport.close()


def run_t1_gate(
    *,
    project_root: Path,
    checkout_sha: str,
    proof: dict | None,
    core_identity: dict | None,
    core_dir: Path,
    wsp_source: Path,
    sample_count: int,
    output_dir: Path,
    setup_code: str | None = None,
) -> dict:
    """Measure >=10 genuine stop reply -> observed process exit samples on signed Core v0.1.13."""
    from .. import core_supervisor as cs_mod
    from ..core_supervisor import CoreSupervisor, STOP_EXIT_BUDGET
    from ..probe_source import verify_source

    samples: list[dict] = []
    profile_parent = Path(tempfile.mkdtemp(prefix="wam-t1-exit-")).resolve(strict=True)
    prior_uncertain = False

    if setup_code is None:
        orig_read_cli = cs_mod._read_cli
        orig_popen_wait = subprocess.Popen.wait

        for idx in range(sample_count):
            mode_kind = "recover_stop" if idx >= (sample_count * 2) // 3 else "shutdown"
            fixture_state = "fresh" if idx < sample_count // 3 else "blocks_101_mempool_tx"
            profile_root = profile_parent / f"wam-fusion-core-{secrets.token_hex(8)}"
            profile_root.mkdir(mode=0o700)

            timing: dict = {
                "sample_index": idx + 1,
                "stop_path": mode_kind,
                "fixture_state": fixture_state,
                "profile_fixture_id": profile_root.name,
            }
            owner = None
            target_popen = None
            target_pid = None
            t_before_rpc = None
            t_after_reply = None
            t_observed_exit = None
            observed_rc = None

            def timed_read_cli(argv, *a, **kw):
                nonlocal t_before_rpc, t_after_reply
                is_stop = isinstance(argv, (list, tuple)) and len(argv) > 0 and argv[-1] == "stop"
                if is_stop:
                    t_before_rpc = time.perf_counter()
                res = orig_read_cli(argv, *a, **kw)
                if is_stop:
                    t_after_reply = time.perf_counter()
                return res

            def timed_wait(proc, *a, **kw):
                nonlocal t_observed_exit, observed_rc
                rc = orig_popen_wait(proc, *a, **kw)
                if proc is target_popen and t_after_reply is not None and t_observed_exit is None:
                    t_observed_exit = time.perf_counter()
                    observed_rc = rc
                return rc

            try:
                owner = CoreSupervisor(profile_root, core_dir, authorized=True)
                owner.start()
                target_popen = owner.process
                target_pid = target_popen.pid
                if fixture_state == "blocks_101_mempool_tx":
                    timing["mempool_txid_sha256"] = sha256(
                        _populate_mempool_tx(owner, wsp_source).encode("ascii")
                    ).hexdigest()
                with patch.object(cs_mod, "_read_cli", timed_read_cli), \
                        patch.object(subprocess.Popen, "wait", timed_wait):
                    if mode_kind == "recover_stop":
                        owner._faulted = True
                        owner.recover_stop()
                    else:
                        owner.shutdown()
                owner.release()
                owner.close()
                owner = None

                stopped, polled_rc, orphan_free = check_popen_stopped(target_popen, target_pid)
                reply_to_exit_s = (
                    (t_observed_exit - t_after_reply)
                    if (t_after_reply is not None and t_observed_exit is not None)
                    else -1.0
                )
                stop_rpc_reply_s = (
                    (t_after_reply - t_before_rpc)
                    if (t_before_rpc is not None and t_after_reply is not None)
                    else -1.0
                )
                total_stop_s = (
                    (t_observed_exit - t_before_rpc)
                    if (t_before_rpc is not None and t_observed_exit is not None)
                    else -1.0
                )
                final_rc = observed_rc if observed_rc is not None else polled_rc
                timing.update({
                    "stop_rpc_reply_s": round(stop_rpc_reply_s, 6),
                    "reply_to_exit_s": round(reply_to_exit_s, 6),
                    "total_stop_s": round(total_stop_s, 6),
                    "stop_exit_budget_s": STOP_EXIT_BUDGET,
                    "observed_exit_code": final_rc,
                    "fits_budget": (0.0 <= reply_to_exit_s <= STOP_EXIT_BUDGET),
                    "orphan_free": bool(stopped and orphan_free),
                    "status": (
                        "PASS"
                        if stopped and orphan_free and final_rc == 0 and 0.0 <= reply_to_exit_s <= STOP_EXIT_BUDGET
                        else "FAIL"
                    ),
                })
                if not (stopped and orphan_free):
                    prior_uncertain = True
            except Exception as exc:
                timing.update({
                    "reply_to_exit_s": 0.0,
                    "observed_exit_code": None,
                    "fits_budget": False,
                    "orphan_free": False,
                    "status": "FAIL",
                    "failure_code": map_refusal_code(exc),
                })
                prior_uncertain = True
            finally:
                if owner is not None:
                    try:
                        if owner.process is not None and owner.process.poll() is None:
                            owner.recover_stop()
                        owner.release()
                        owner.close()
                    except Exception:
                        prior_uncertain = True
            samples.append(timing)
            print(
                f"DQUIT1_T1 sample={idx + 1}/{sample_count} {timing['status']} "
                f"reply_to_exit_s={timing.get('reply_to_exit_s')} mode={mode_kind}",
                flush=True,
            )
            if prior_uncertain:
                break

    if not prior_uncertain:
        shutil.rmtree(profile_parent, ignore_errors=True)

    source_unchanged = False
    if proof is not None:
        try:
            source_unchanged = verify_source(project_root) == proof
        except Exception:
            source_unchanged = False

    summary = None
    status = "BLOCKED" if setup_code is not None else "FAIL"
    if setup_code is None and len(samples) >= MIN_T1_SAMPLES:
        try:
            summary = summarize_exit_samples(samples, STOP_EXIT_BUDGET, min_samples=MIN_T1_SAMPLES)
            if (source_unchanged
                    and not prior_uncertain
                    and all(s.get("status") == "PASS" for s in samples)
                    and summary["all_samples_fit_budget"]
                    and summary["all_exit_zero"]
                    and summary["all_orphan_free"]):
                status = "PASS"
        except ValueError:
            status = "FAIL"

    core_sha256 = (
        dict(core_identity["members"])
        if isinstance(core_identity, dict) and isinstance(core_identity.get("members"), dict)
        else {"wamd": "", "wam-cli": ""}
    )
    receipt = {
        "schema": T1_SCHEMA,
        "status": status,
        "failure_code": setup_code if status == "BLOCKED" else None,
        "checkout_sha": checkout_sha,
        "source_provenance": proof,
        "source_unchanged": source_unchanged,
        "core": core_identity,
        "core_sha256": core_sha256,
        "wsp_source_commit": WSP_COMMIT,
        "platform": f"{platform.system().lower()}-{platform.machine().lower()}",
        "python_version": platform.python_version(),
        "stop_exit_budget_s": STOP_EXIT_BUDGET,
        "summary": summary or {
            "sample_count": len(samples),
            "min_required_samples": MIN_T1_SAMPLES,
            "stop_exit_budget_s": STOP_EXIT_BUDGET,
            "all_samples_fit_budget": False,
            "all_exit_zero": False,
            "all_orphan_free": False,
        },
        "samples": samples,
        "accepted": False,
        "mainnet_allowed": False,
        "exit_code": 0 if status == "PASS" else 2,
    }
    if status == "PASS" and not validate_t1_receipt(receipt):
        receipt["status"] = "FAIL"
        receipt["exit_code"] = 2
        receipt["failure_code"] = "DQUIT1_T1_RECEIPT_CONTRACT_INCOMPLETE"
    out_path = output_dir / "t1-exit-budget-receipt.json"
    with out_path.open("x", encoding="utf-8") as fh:
        json.dump(receipt, fh, indent=2)
        fh.write("\n")
    return receipt


def run_t2_gate(
    *,
    project_root: Path,
    checkout_sha: str,
    proof: dict | None,
    core_identity: dict | None,
    core_dir: Path,
    wsp_source: Path,
    output_dir: Path,
    setup_code: str | None = None,
) -> dict:
    """Measure WSP SQLite and payment-evidence SHA-256 byte identity across Q06 faulted Quit."""
    from ..probe_source import verify_source
    from ..q05_platforms import DarwinArm64Adapter
    from ..quit_notice import unacknowledged
    from . import fee_regtest_runner as fee_runner
    from .fee_regtest import FIXTURES
    from .q06_fix_scenarios import _require_cocoa

    scenarios: dict[str, dict] = {}
    prior_uncertain = False

    if setup_code is None:
        app = _require_cocoa()
        adapter = DarwinArm64Adapter()
        base_backend_cls = fee_runner.backend_type()
        orig_popen_wait = subprocess.Popen.wait

        for name in T2_SCENARIO_NAMES:
            scenario_key = f"F3-14/{name}"
            if prior_uncertain:
                scenarios[scenario_key] = {
                    "scenario": scenario_key,
                    "status": "BLOCKED",
                    "failure_code": "DQUIT1_T2_PRIOR_OWNER_UNCERTAIN",
                }
                continue

            fixture = next(f for f in FIXTURES if f.case == "F3-14" and f.name == name)
            captured: dict = {"quit_count": 0, "recover_stop_called": False, "shutdown_called": False}

            class T2ObservedBackend(base_backend_cls):
                def execute(self, action, args, kwargs):
                    if action != "quit":
                        return super().execute(action, args, kwargs)
                    captured["quit_count"] += 1
                    owner = self.owner
                    chain_dir = owner.directory
                    captured["root"] = str(self.root)
                    captured["profile_id"] = owner.profile["profile_id"]
                    captured["before_quit"] = snapshot_wallet_files(chain_dir)

                    orig_recover_stop = owner.recover_stop
                    orig_shutdown = owner.shutdown
                    core_popen = owner.process
                    core_pid = core_popen.pid if core_popen is not None else None
                    captured["observed_exit"] = None

                    def timed_wait(proc, *wa, **wkw):
                        rc = orig_popen_wait(proc, *wa, **wkw)
                        if proc is core_popen and captured["observed_exit"] is None:
                            captured["observed_exit"] = rc
                        return rc

                    def wrapped_recover_stop():
                        captured["recover_stop_called"] = True
                        captured["before_stop"] = snapshot_wallet_files(chain_dir)
                        with patch.object(subprocess.Popen, "wait", timed_wait):
                            res = orig_recover_stop()
                        captured["after_observed_exit"] = snapshot_wallet_files(chain_dir)
                        captured["orphan_free"] = core_pid is None or not pid_is_alive(core_pid)
                        return res

                    def wrapped_shutdown():
                        captured["shutdown_called"] = True
                        return orig_shutdown()

                    owner.recover_stop = wrapped_recover_stop
                    owner.shutdown = wrapped_shutdown
                    quit_result = super().execute(action, args, kwargs)
                    captured["after_quit"] = snapshot_wallet_files(chain_dir)
                    captured["quit_result"] = plain_value(quit_result)
                    return quit_result

            result = {
                "schema": "wam-fee3-source/v1",
                "case_id": fixture.case,
                "fixture": fixture.name,
                "status": "BLOCKED",
                "started_utc": fee_runner.utc(),
                "test_layer": "FAULT_INJECTED_REAL_CORE",
                "network": "regtest",
                "mainnet_allowed": False,
                "assertions": {},
                "artifacts": {},
                "profile_fixture_id": None,
                "cleanup": {"not_started": True},
            }
            with patch.object(fee_runner, "backend_type", return_value=T2ObservedBackend):
                fee_runner.run_fixture(fixture, app, adapter, core_dir, wsp_source, result)

            before_stop = captured.get("before_stop")
            after_exit = captured.get("after_observed_exit")
            before_quit = captured.get("before_quit")
            after_quit = captured.get("after_quit")
            if before_stop is not None and after_exit is not None:
                across_stop = compare_file_snapshots(
                    before_stop, after_exit, categories=("wsp_sqlite", "payment_evidence")
                )
                checkpoint_across_stop = compare_file_snapshots(
                    before_stop, after_exit, categories=("native_checkpoint",)
                )
            else:
                across_stop = {"byte_identical": False, "changed_files": []}
                checkpoint_across_stop = {"byte_identical": False, "changed_files": []}

            if before_quit is not None and after_quit is not None:
                across_quit = compare_file_snapshots(
                    before_quit, after_quit, categories=("wsp_sqlite", "payment_evidence")
                )
            else:
                across_quit = {"byte_identical": False, "changed_files": []}

            root_path = Path(captured["root"]) if "root" in captured else None
            notices = (
                unacknowledged(root_path, expected_profile_id=captured["profile_id"])
                if root_path is not None
                else ()
            )
            wsp_count = len(before_stop.get("wsp_sqlite", ())) if before_stop else 0
            ev_count = len(before_stop.get("payment_evidence", ())) if before_stop else 0
            quit_res = captured.get("quit_result") or {}
            orphan_free = captured.get("orphan_free") is True
            if not orphan_free:
                prior_uncertain = True

            sc_pass = (
                result.get("status") == "PASS"
                and result.get("cleanup", {}).get("verified_original_owner_shutdown") is True
                and captured.get("quit_count") == 1
                and captured.get("recover_stop_called") is True
                and captured.get("shutdown_called") is False
                and orphan_free
                and captured.get("observed_exit") == 0
                and quit_res.get("runtime_preserved") is True
                and len(notices) == 1
                and wsp_count >= 1
                and across_stop.get("byte_identical") is True
                and (name != "lost-send-response" or ev_count >= 2)
            )
            scenarios[scenario_key] = {
                "scenario": scenario_key,
                "status": "PASS" if sc_pass else "FAIL",
                "failure_code": result.get("failure_code"),
                "fee3_status": result.get("status"),
                "profile_fixture_id": result.get("profile_fixture_id"),
                "one_quit": captured.get("quit_count") == 1,
                "quit_count": captured.get("quit_count"),
                "recover_stop_called": captured.get("recover_stop_called"),
                "shutdown_called": captured.get("shutdown_called"),
                "observed_exit": captured.get("observed_exit"),
                "orphan_free": orphan_free,
                "runtime_preserved": quit_res.get("runtime_preserved"),
                "quit_codes": quit_res.get("codes"),
                "unresolved_notice_count": len(notices),
                "wsp_sqlite_file_count": wsp_count,
                "payment_evidence_file_count": ev_count,
                "files_before_stop": before_stop,
                "files_after_observed_exit": after_exit,
                "across_stop": across_stop,
                "checkpoint_across_stop": checkpoint_across_stop,
                "across_quit": across_quit,
            }
            print(
                f"DQUIT1_T2 {scenario_key} {scenarios[scenario_key]['status']} "
                f"wsp={wsp_count} ev={ev_count} byte_identical={across_stop.get('byte_identical')}",
                flush=True,
            )
    else:
        for name in T2_SCENARIO_NAMES:
            scenario_key = f"F3-14/{name}"
            scenarios[scenario_key] = {
                "scenario": scenario_key,
                "status": "BLOCKED",
                "failure_code": setup_code,
            }

    source_unchanged = False
    if proof is not None:
        try:
            source_unchanged = verify_source(project_root) == proof
        except Exception:
            source_unchanged = False

    if setup_code is not None:
        status = "BLOCKED"
    elif source_unchanged and not prior_uncertain and all(
        scenarios[f"F3-14/{n}"]["status"] == "PASS" for n in T2_SCENARIO_NAMES
    ):
        status = "PASS"
    else:
        status = "FAIL"

    core_sha256 = (
        dict(core_identity["members"])
        if isinstance(core_identity, dict) and isinstance(core_identity.get("members"), dict)
        else {"wamd": "", "wam-cli": ""}
    )
    receipt = {
        "schema": T2_SCHEMA,
        "status": status,
        "failure_code": setup_code if status == "BLOCKED" else None,
        "checkout_sha": checkout_sha,
        "source_provenance": proof,
        "source_unchanged": source_unchanged,
        "core": core_identity,
        "core_sha256": core_sha256,
        "wsp_source_commit": WSP_COMMIT,
        "platform": f"{platform.system().lower()}-{platform.machine().lower()}",
        "python_version": platform.python_version(),
        "scenarios": scenarios,
        "accepted": False,
        "mainnet_allowed": False,
        "exit_code": 0 if status == "PASS" else 2,
    }
    if status == "PASS" and not validate_t2_receipt(receipt):
        receipt["status"] = "FAIL"
        receipt["exit_code"] = 2
        receipt["failure_code"] = "DQUIT1_T2_RECEIPT_CONTRACT_INCOMPLETE"
    out_path = output_dir / "t2-byte-identity-receipt.json"
    with out_path.open("x", encoding="utf-8") as fh:
        json.dump(receipt, fh, indent=2)
        fh.write("\n")
    return receipt


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=ALLOWED_MODES, default="all")
    parser.add_argument("--core", "--core-dir", dest="core", type=Path, default=None)
    parser.add_argument("--core-archive", type=Path, default=None)
    parser.add_argument("--signed-manifest-dir", type=Path, default=None)
    parser.add_argument("--wsp-source", type=Path, default=None)
    parser.add_argument("--t1-samples", type=int, default=DEFAULT_T1_SAMPLES)
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

    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    checkout_sha = subprocess.check_output(
        ["git", "-C", str(project_root), "rev-parse", "HEAD"], text=True
    ).strip()

    proof = None
    setup_code = None
    core_identity = None
    try:
        proof = verify_source(project_root)
        if args.mode in ("t1", "t2", "all"):
            from ..q05_platforms import DarwinArm64Adapter
            from ..wsp_live import _pinned_source
            from .fee_regtest_runner import authenticate

            if sys.platform != "darwin" or platform.machine().lower() != "arm64":
                raise ValueError("DQUIT1_GATE_NATIVE_MACOS_ARM64_REQUIRED")
            adapter = DarwinArm64Adapter()
            adapter.enforce_host()
            _pinned_source(args.wsp_source)
            core_identity = authenticate(
                args.core, args.core_archive, args.gpg, args.signed_manifest_dir
            )
    except Exception as error:
        setup_code = map_refusal_code(error)

    receipts: dict[str, dict] = {}
    if args.mode in ("crash", "all"):
        receipts["crash"] = run_crash_gate(
            project_root=project_root,
            checkout_sha=checkout_sha,
            proof=proof,
            output_dir=args.output,
        )
    if args.mode in ("t1", "all"):
        receipts["t1"] = run_t1_gate(
            project_root=project_root,
            checkout_sha=checkout_sha,
            proof=proof,
            core_identity=core_identity,
            core_dir=args.core,
            wsp_source=args.wsp_source,
            sample_count=args.t1_samples,
            output_dir=args.output,
            setup_code=setup_code,
        )
    if args.mode in ("t2", "all"):
        receipts["t2"] = run_t2_gate(
            project_root=project_root,
            checkout_sha=checkout_sha,
            proof=proof,
            core_identity=core_identity,
            core_dir=args.core,
            wsp_source=args.wsp_source,
            output_dir=args.output,
            setup_code=setup_code,
        )

    return 0 if all(r.get("status") == "PASS" for r in receipts.values()) else 2
