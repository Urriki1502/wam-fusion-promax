"""Qualification-only FROZEN FEE-3 mode: ``--ci-fee-regtest``. Never in production.

Runs the integrated runner's fixture logic (``fee_regtest_runner.run_fixture``)
inside the frozen qualification app on native Cocoa, against the bundled signed
Core and pinned WSP, for the CLOSED frozen-required set of FEE-3 plan §6:
F3-01..F3-06, F3-09 positive, F3-11..F3-13 recovery and F3-14 natural safety cases. It accepts no argument, rate, flag,
case list or developer test import. Each case uses a NEW retained disposable
REGTEST profile and requires verified original-owner shutdown. Every other
FEE-3 row is written BLOCKED or NOT_IN_SCOPE, never PASS.

``gate()`` is the pure, fail-closed report check the macOS builder runs on the
copied report. It imports no Qt and starts nothing.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import sys

from .fee_regtest_safety import NATURAL, FAULTS

from .fee_regtest import (
    FIXTURES, FROZEN_RESULT_SCHEMA, FROZEN_SOURCE_KEYS, FROZEN_TEST_LAYER,
    valid_frozen_pass_result, write_artifact,
)

FLAG = "--ci-fee-regtest"
EVIDENCE_NAME = "fee3-frozen-evidence.json"
CASES_DIR = "fee3-frozen-cases"
SCHEMA = "wam-fee3-frozen/v1"
WSP_SOURCE_COMMIT = "ac55f13423620252bdbf848c7e8a280c3b84721e"
FROZEN_REQUIRED_CASES = ("F3-01", "F3-02", "F3-03", "F3-04", "F3-05", "F3-06", "F3-11", "F3-12", "F3-13", "D-FEE2-2")


def row_name(fixture):
    return fixture.case + "/" + fixture.name


FROZEN_FIXTURES = tuple(
    f for f in FIXTURES
    if not f.characterization
    and (f.case in FROZEN_REQUIRED_CASES or (f.case, f.name) == ("F3-09", "positive")
         or (f.case == "F3-14" and f.name in NATURAL)))
REQUIRED_ROWS = tuple(row_name(f) for f in FROZEN_FIXTURES)

# Plan §6. BLOCKED: the plan wants frozen coverage that is not implemented or
# packaged yet. NOT_IN_SCOPE: the plan marks the row source-only.
NON_FROZEN_ROWS = {
    "F3-07": ("BLOCKED", "BLOCKED_STARTUP_SEAM_NOT_PACKAGED"),
    "F3-08": ("BLOCKED", "BLOCKED_STARTUP_FILLER_SEAM_NOT_PACKAGED"),
    "F3-10": ("BLOCKED", "BLOCKED_FILLER_SEAM_NOT_PACKAGED"),
    "F3-09/low-fee": ("NOT_IN_SCOPE", "NOT_IN_SCOPE_SOURCE_ONLY_EXPLICIT_FEE_SEAM"),
    **{"F3-14/" + name: ("BLOCKED", "BLOCKED_SOURCE_ONLY_FAULT_EXECUTION_DENIED_" + name.upper().replace("-", "_"))
       for name, boundary in FAULTS.items()},
    "F3-14/remaining-authority-publication-duplicates": (
        "BLOCKED", "BLOCKED_ADDITIONAL_AUTHORITY_PUBLICATION_DUPLICATE_SCENARIOS_NOT_IMPLEMENTED"),
}
NON_FROZEN_STATUSES = ("BLOCKED", "NOT_IN_SCOPE")

if (len(FROZEN_FIXTURES) != 27 or len(set(REQUIRED_ROWS)) != 27
        or set(REQUIRED_ROWS) & set(NON_FROZEN_ROWS)):
    raise RuntimeError("F3_FROZEN_CLOSED_SET_DENIED")

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_GIT = re.compile(r"[0-9a-f]{40}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{4,110}\Z")


def _stage(name):
    print("MACOS_FEE3_FROZEN_STAGE=" + name, flush=True)


def frozen_source_identity():
    """The embedded build stamp plus the running executable digest."""
    if not getattr(sys, "frozen", False):
        raise ValueError("F3_FROZEN_RUNTIME_REQUIRED")
    from ..q05_package_provenance import read
    stamp = read()
    return {key: stamp[key] for key in FROZEN_SOURCE_KEYS}


def frozen_core_identity(core):
    """Re-verify the bundled receipt and member bytes against the v0.1.13 pins."""
    from ..core import verified_core_paths
    from ..official_core_v013 import ARCHIVES, MEMBERS
    node, cli, receipt = verified_core_paths(Path(core))
    members = {"wamd": sha256(node.read_bytes()).hexdigest(),
               "wam-cli": sha256(cli.read_bytes()).hexdigest()}
    if (members != MEMBERS["macos-arm64"]
            or receipt.get("archive_sha256") != ARCHIVES["macos-arm64"][2]):
        raise ValueError("F3_FROZEN_CORE_PINS")
    return {"members": members, "archive_sha256": receipt["archive_sha256"],
            "trust": "official-signed-v0.1.13", "bundle_receipt_verified_now": True,
            "signature_verified_now": False,
            "signature_authentication": "build intake; signed archive is not bundled",
            "publisher_fingerprint": receipt["publisher_fingerprint"]}


def _require_cocoa():
    if sys.platform != "darwin" or platform.machine().lower() != "arm64":
        raise ValueError("F3_FROZEN_NATIVE_MACOS_ARM64_REQUIRED")
    from ..desktop import qt_application
    app = qt_application()
    if app.platformName() != "cocoa":
        raise ValueError("F3_FROZEN_NATIVE_COCOA_REQUIRED")
    return app


def _case_result(fixture, identity, core_identity, app, started):
    return {"schema": FROZEN_RESULT_SCHEMA, "case_id": fixture.case, "fixture": fixture.name,
            "status": "BLOCKED", "started_utc": started, "test_layer": FROZEN_TEST_LAYER,
            "network": "regtest", "mainnet_allowed": False, "frozen": True,
            "command": [Path(sys.executable).name, FLAG], "source": identity,
            "core": core_identity,
            "os": {"system": platform.system(), "arch": platform.machine(),
                   "qt_platform": app.platformName() if app is not None else None},
            "wsp_source_commit": WSP_SOURCE_COMMIT, "safe_startup_flags": [],
            "assertions": {}, "artifacts": {}, "profile_fixture_id": None,
            "cleanup": {"not_started": True}}


def run(core, source):
    """Entry from the frozen app. 0 only when all 19 required rows PASS."""
    from .fee_regtest_runner import resolve_actor, run_fixture, utc
    from .q06_fix_scenarios import failure_code
    started = utc()
    actor = resolve_actor()
    identity = core_identity = app = adapter = None
    setup = None
    _stage("START")
    try:
        identity = frozen_source_identity()
        core_identity = frozen_core_identity(core)
        from ..wsp_live import _pinned_source
        _pinned_source(Path(source))
        app = _require_cocoa()
        from ..q05_platforms import DarwinArm64Adapter
        adapter = DarwinArm64Adapter()
        adapter.enforce_host()
    except Exception as error:
        setup = failure_code(error)
        _stage("SETUP_DENIED")
    cases = Path(CASES_DIR)
    cases.mkdir(mode=0o700, exist_ok=False)
    rows = {}
    for fixture in FROZEN_FIXTURES:
        folder = cases / fixture.case / fixture.name
        folder.mkdir(mode=0o700, parents=True)
        result = _case_result(fixture, identity, core_identity, app, utc())
        if setup:
            result["blocker"] = {"actor": actor, "code": setup,
                                 "action": "provide native Cocoa host and verified bundle inputs"}
        else:
            try:
                run_fixture(fixture, app, adapter, Path(core), Path(source), result, actor=actor)
            except Exception as error:
                # Outside the protected lifetime: never permit a second owner.
                result.update(status="FAIL", failure_code=failure_code(error), cleanup={
                    "verified_original_owner_shutdown": False, "profile_retained": True,
                    "actor": actor, "action": "inspect unverified setup/owner before continuing"})
        result["ended_utc"] = utc()
        result["exit_code"] = 0 if result["status"] == "PASS" else 2
        observations = result.pop("observations", {})
        for name, payload in (("policy.json", observations.get("policy", [])),
                              ("events.json", {k: v for k, v in observations.items() if k != "policy"}),
                              ("tma.json", result.pop("tma", {}))):
            result["artifacts"][name] = write_artifact(folder / name, payload)
        if result["status"] == "PASS" and not valid_frozen_pass_result(result):
            result.update(status="FAIL", exit_code=2, failure_code="F3_REPORT_CONTRACT_INCOMPLETE")
        row = {"status": result["status"],
               "result_sha256": write_artifact(folder / "result.json", result)}
        if result.get("failure_code"):
            row["failure_code"] = result["failure_code"]
        rows[row_name(fixture)] = row
        print("MACOS_FEE3_FROZEN_CASE=%s %s" % (row_name(fixture), result["status"]), flush=True)
        if result.get("cleanup", {}).get("verified_original_owner_shutdown") is False:
            setup = "F3_PRIOR_OWNER_UNCERTAIN"
    for name, (status, reason) in NON_FROZEN_ROWS.items():
        rows[name] = {"status": status, "reason": reason}
    required = [rows[name]["status"] for name in REQUIRED_ROWS]
    status = ("PASS" if all(s == "PASS" for s in required)
              else "FAIL" if "FAIL" in required else "BLOCKED")
    unchanged = False
    if identity is not None:
        try:
            unchanged = frozen_source_identity() == identity
        except Exception:
            unchanged = False
    if not unchanged and status == "PASS":
        status = "FAIL"
    report = {"schema": SCHEMA, "status": status, "network": "regtest",
              "mainnet_allowed": False, "frozen": True, "test_layer": FROZEN_TEST_LAYER,
              "flag": FLAG, "started_utc": started, "ended_utc": utc(),
              "source": identity, "source_unchanged": unchanged,
              "core_sha256": core_identity["members"] if core_identity else None,
              "core": core_identity, "wsp_source_commit": WSP_SOURCE_COMMIT,
              "os": {"system": platform.system(), "arch": platform.machine(),
                     "qt_platform": app.platformName() if app is not None else None},
              "required_rows": list(REQUIRED_ROWS), "rows": rows,
              "cases_dir": CASES_DIR, "setup_failure_code": setup,
              "accepted": False, "engineering_handoff": False}
    write_artifact(Path(EVIDENCE_NAME), report)
    _stage(status)
    return 0 if status == "PASS" else 2


def _file_sha256(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def gate(report, *, cases_dir, source_sha, checkout_sha, inventory_sha256,
         executable_sha256, core_sha256, wsp_source_commit=WSP_SOURCE_COMMIT):
    """Return the list of failed checks; empty means the frozen report PASSES.

    Fails closed on a missing/unknown row, a NOT RUN or non-PASS required row,
    a PASS claimed for a non-frozen row, a changed per-case result file, a
    case filed under another row, or any disagreement with the bundle's
    source, executable, Core or WSP identity.

    Row binding: each row's result.json must name that row's case_id and
    fixture, be a regular file in that row's own folder, and have a digest and
    disposable profile that no other row uses. Its artifact digests must match
    regular files in that same folder. Artifact digests themselves are NOT
    required to be unique: refusal rows legitimately write identical bytes
    (e.g. an empty tma.json).
    """
    problems = []

    def check(condition, code):
        if condition is not True:
            problems.append(code)

    if type(report) is not dict:
        return ["F3_FROZEN_REPORT_TYPE"]
    check(report.get("schema") == SCHEMA, "F3_FROZEN_SCHEMA")
    check(report.get("status") == "PASS", "F3_FROZEN_STATUS")
    check(report.get("mainnet_allowed") is False, "F3_FROZEN_MAINNET_ALLOWED")
    check(report.get("network") == "regtest", "F3_FROZEN_NETWORK")
    check(report.get("frozen") is True, "F3_FROZEN_NOT_FROZEN")
    check(report.get("test_layer") == FROZEN_TEST_LAYER, "F3_FROZEN_LAYER")
    check(report.get("source_unchanged") is True, "F3_FROZEN_SOURCE_CHANGED")
    check(report.get("flag") == FLAG, "F3_FROZEN_FLAG")
    check(report.get("accepted") is False, "F3_FROZEN_ACCEPTED_CLAIMED")
    check(report.get("engineering_handoff") is False, "F3_FROZEN_HANDOFF_CLAIMED")
    os_info = report.get("os")
    check(type(os_info) is dict and os_info.get("qt_platform") == "cocoa", "F3_FROZEN_QT_PLATFORM")
    expected_source = {"candidate_source_sha": source_sha, "checkout_sha": checkout_sha,
                       "build_source_inventory_sha256": inventory_sha256,
                       "frozen_executable_sha256": executable_sha256}
    if not (all(type(v) is str for v in expected_source.values())
            and _GIT.match(source_sha) and _GIT.match(checkout_sha)
            and _HEX64.match(inventory_sha256) and _HEX64.match(executable_sha256)):
        problems.append("F3_FROZEN_EXPECTED_IDENTITY_INVALID")
    source = report.get("source")
    for key, value in expected_source.items():
        check(type(source) is dict and source.get(key) == value, "F3_FROZEN_SOURCE_MISMATCH:" + key)
    check(type(core_sha256) is dict and set(core_sha256) == {"wamd", "wam-cli"}
          and report.get("core_sha256") == core_sha256, "F3_FROZEN_CORE_MISMATCH")
    check(report.get("wsp_source_commit") == wsp_source_commit, "F3_FROZEN_WSP_MISMATCH")
    rows = report.get("rows")
    if type(rows) is not dict:
        problems.append("F3_FROZEN_ROWS_MISSING")
        return problems
    check(report.get("required_rows") == list(REQUIRED_ROWS), "F3_FROZEN_REQUIRED_ROWS")
    for name in sorted(set(rows) - set(REQUIRED_ROWS) - set(NON_FROZEN_ROWS)):
        problems.append("F3_FROZEN_ROW_UNKNOWN:" + name)
    for name in NON_FROZEN_ROWS:
        row = rows.get(name)
        if type(row) is not dict:
            problems.append("F3_FROZEN_ROW_MISSING:" + name)
            continue
        check(row.get("status") in NON_FROZEN_STATUSES, "F3_FROZEN_NON_FROZEN_ROW_STATUS:" + name)
        check(type(row.get("reason")) is str and _CODE.match(row["reason"]) is not None,
              "F3_FROZEN_NON_FROZEN_ROW_REASON:" + name)
    folder = Path(cases_dir)
    seen_results, seen_profiles = {}, {}
    for fixture in FROZEN_FIXTURES:
        name = row_name(fixture)
        row = rows.get(name)
        if type(row) is not dict:
            problems.append("F3_FROZEN_ROW_MISSING:" + name)
            continue
        if row.get("status") != "PASS":
            problems.append("F3_FROZEN_ROW_NOT_PASS:" + name)
            continue
        path = folder / fixture.case / fixture.name / "result.json"
        digest = row.get("result_sha256")
        try:
            if path.is_symlink() or path.parent.is_symlink():
                raise OSError("linked")
            raw = path.read_bytes()
            result = json.loads(raw)
        except (OSError, ValueError):
            problems.append("F3_FROZEN_CASE_RESULT_MISSING:" + name)
            continue
        check(type(digest) is str and _HEX64.match(digest) is not None
              and sha256(raw).hexdigest() == digest, "F3_FROZEN_CASE_RESULT_DIGEST:" + name)
        check(type(result) is dict and valid_frozen_pass_result(result),
              "F3_FROZEN_CASE_CONTRACT:" + name)
        if type(result) is not dict:
            problems.append("F3_FROZEN_CASE_IDENTITY:" + name)
            continue
        # The file under this row must BE this row's case, not another row's.
        check(result.get("case_id") == fixture.case and result.get("fixture") == fixture.name,
              "F3_FROZEN_CASE_IDENTITY:" + name)
        for seen, value, code in ((seen_results, digest, "F3_FROZEN_CASE_RESULT_REUSED:"),
                                  (seen_profiles, result.get("profile_fixture_id"),
                                   "F3_FROZEN_CASE_PROFILE_REUSED:")):
            if type(value) is str and value in seen:
                problems.append(code + name)
            elif type(value) is str:
                seen[value] = name
        check(result.get("source") == source, "F3_FROZEN_CASE_SOURCE_MISMATCH:" + name)
        check(type(result.get("core")) is dict
              and result["core"].get("members") == core_sha256, "F3_FROZEN_CASE_CORE_MISMATCH:" + name)
        check(result.get("wsp_source_commit") == wsp_source_commit,
              "F3_FROZEN_CASE_WSP_MISMATCH:" + name)
        artifacts = result.get("artifacts")
        for artifact in ("policy.json", "events.json", "tma.json"):
            artifact_path = path.parent / artifact
            check(type(artifacts) is dict and artifact_path.is_file()
                  and not artifact_path.is_symlink()
                  and artifacts.get(artifact) == _file_sha256(artifact_path),
                  "F3_FROZEN_CASE_ARTIFACT_DIGEST:" + name + "/" + artifact)
    return problems
