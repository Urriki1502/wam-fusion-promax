"""PM-039: qualification-only frozen FEE-3 mode. No daemon, profile, build or Qt window."""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

from wam_regtest import production_entry
from wam_regtest.qualification import fee_regtest_frozen as frozen
from wam_regtest.qualification.fee_regtest import (
    FIXTURES, FROZEN_RESULT_SCHEMA, FROZEN_TEST_LAYER, required_assertions,
    valid_frozen_pass_result, valid_pass_result, write_artifact,
)

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("packaging_policy_pm039", ROOT / "scripts/production_packaging.py")
policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy)

SOURCE = {
    "candidate_source_sha": "a" * 40, "checkout_sha": "b" * 40,
    "build_source_inventory_sha256": "c" * 64, "bundled_source_stamp_sha256": "d" * 64,
    "frozen_executable_sha256": "e" * 64,
}
CORE_MEMBERS = {"wamd": "1" * 64, "wam-cli": "2" * 64}
CORE = {"members": dict(CORE_MEMBERS), "archive_sha256": "3" * 64,
        "trust": "official-signed-v0.1.13", "bundle_receipt_verified_now": True,
        "signature_verified_now": False,
        "signature_authentication": "build intake; signed archive is not bundled",
        "publisher_fingerprint": "F" * 40}
GATE_KWARGS = dict(source_sha="a" * 40, checkout_sha="b" * 40, inventory_sha256="c" * 64,
                   executable_sha256="e" * 64, core_sha256=dict(CORE_MEMBERS),
                   wsp_source_commit=frozen.WSP_SOURCE_COMMIT)


def passing_fields(fixture):
    """What run_fixture writes into a PASS result for this fixture."""
    fields = {
        "status": "PASS",
        "assertions": {key: True for key in required_assertions(fixture)},
        "core_runtime": {"version": 113, "peers": 0, "genesis": "4" * 64, "chain": "regtest",
                         "subversion": "/WAM:0.1.13/", "funding": []},
        "baseline": {"quote": {"floor_atoms_per_kvb": 1000}},
        "profile_fixture_id": "5" * 64,
        "cleanup": {"verified_original_owner_shutdown": True, "profile_retained": True,
                    "actor": "test", "action": "none"},
    }
    if not fixture.refusal and fixture.case != "F3-01":
        fields["confirmed_atoms"] = {"pre": sum(fixture.coins), "post": 0}
    return fields


def frozen_case(fixture, source=SOURCE, core=CORE):
    result = {"schema": FROZEN_RESULT_SCHEMA, "case_id": fixture.case, "fixture": fixture.name,
              "started_utc": "2026-11-13T00:00:00+00:00", "ended_utc": "2026-11-13T00:00:01+00:00",
              "test_layer": FROZEN_TEST_LAYER, "network": "regtest", "mainnet_allowed": False,
              "frozen": True, "command": ["WAM Privacy Wallet REGTEST QUALIFICATION", frozen.FLAG],
              "source": copy.deepcopy(source), "core": copy.deepcopy(core),
              "os": {"system": "Darwin", "arch": "arm64", "qt_platform": "cocoa"},
              "wsp_source_commit": frozen.WSP_SOURCE_COMMIT, "safe_startup_flags": [],
              "artifacts": {name: "6" * 64 for name in ("policy.json", "events.json", "tma.json")},
              "exit_code": 0}
    result.update(passing_fields(fixture))
    return result


def write_report(folder, mutate_case=None):
    """Create a PASSING frozen report and case tree exactly as run() lays it out."""
    cases = Path(folder) / frozen.CASES_DIR
    rows = {}
    for fixture in frozen.FROZEN_FIXTURES:
        case_dir = cases / fixture.case / fixture.name
        case_dir.mkdir(parents=True)
        result = frozen_case(fixture)
        for name in ("policy.json", "events.json", "tma.json"):
            result["artifacts"][name] = write_artifact(case_dir / name, {"name": name})
        if mutate_case is not None:
            mutate_case(fixture, result)
        rows[frozen.row_name(fixture)] = {
            "status": "PASS", "result_sha256": write_artifact(case_dir / "result.json", result)}
    for name, (status, reason) in frozen.NON_FROZEN_ROWS.items():
        rows[name] = {"status": status, "reason": reason}
    report = {"schema": frozen.SCHEMA, "status": "PASS", "network": "regtest",
              "mainnet_allowed": False, "frozen": True, "test_layer": FROZEN_TEST_LAYER,
              "flag": frozen.FLAG, "source": copy.deepcopy(SOURCE), "source_unchanged": True,
              "core_sha256": dict(CORE_MEMBERS), "core": copy.deepcopy(CORE),
              "wsp_source_commit": frozen.WSP_SOURCE_COMMIT,
              "os": {"system": "Darwin", "arch": "arm64", "qt_platform": "cocoa"},
              "required_rows": list(frozen.REQUIRED_ROWS), "rows": rows,
              "cases_dir": frozen.CASES_DIR, "setup_failure_code": None,
              "accepted": False, "engineering_handoff": False}
    return report, cases


class ClosedCaseSet(unittest.TestCase):
    def test_required_set_is_exactly_f3_01_to_06_and_f3_09_positive(self):
        expected = [(f.case, f.name) for f in FIXTURES
                    if f.case in ("F3-01", "F3-02", "F3-03", "F3-04", "F3-05", "F3-06")
                    or (f.case, f.name) == ("F3-09", "positive")]
        self.assertEqual([(f.case, f.name) for f in frozen.FROZEN_FIXTURES], expected)
        self.assertEqual(len(frozen.REQUIRED_ROWS), 15)
        self.assertFalse(any(f.characterization for f in frozen.FROZEN_FIXTURES))
        self.assertNotIn("D-FEE2-2/subdust-sweep-characterization", frozen.REQUIRED_ROWS)

    def test_every_non_frozen_row_is_present_and_never_pass(self):
        self.assertEqual(set(frozen.NON_FROZEN_ROWS), {
            "F3-07", "F3-08", "F3-10", "F3-09/low-fee", "F3-11", "F3-12", "F3-13", "F3-14",
            "D-FEE2-2/subdust-sweep-characterization"})
        for name, (status, reason) in frozen.NON_FROZEN_ROWS.items():
            self.assertIn(status, ("BLOCKED", "NOT_IN_SCOPE"), name)
            self.assertTrue(reason.startswith(status + "_"), name)
        self.assertFalse(set(frozen.NON_FROZEN_ROWS) & set(frozen.REQUIRED_ROWS))


class FrozenCaseContract(unittest.TestCase):
    def test_frozen_case_contract_binds_build_stamp_not_git(self):
        fixture = frozen.FROZEN_FIXTURES[0]
        result = frozen_case(fixture)
        self.assertTrue(valid_frozen_pass_result(result))
        # A frozen case can never satisfy the source contract and vice versa.
        self.assertFalse(valid_pass_result(result))
        source_shaped = copy.deepcopy(result)
        source_shaped.update(schema="wam-fee3-source/v1", test_layer="REAL_CORE",
                             source={"sha": "a" * 40, "tree": "b" * 40,
                                     "inventory_sha256": "c" * 64, "dirty_inventory": []})
        self.assertFalse(valid_frozen_pass_result(source_shaped))
        for mutate in (
            lambda r: r["source"].pop("frozen_executable_sha256"),
            lambda r: r["source"].update(candidate_source_sha="abc"),
            lambda r: r["source"].update(extra="x"),
            lambda r: r["core"].update(bundle_receipt_verified_now=False),
            lambda r: r["core"].update(signature_verified_now=True),
            lambda r: r["core"].update(trust="developer-built"),
            lambda r: r.update(mainnet_allowed=True),
            lambda r: r["os"].update(qt_platform="offscreen"),
            lambda r: r["cleanup"].update(verified_original_owner_shutdown=False),
            lambda r: r["assertions"].update(confirmed_debit=False),
            lambda r: r["artifacts"].pop("tma.json"),
        ):
            bad = frozen_case(frozen.FROZEN_FIXTURES[2])
            mutate(bad)
            self.assertFalse(valid_frozen_pass_result(bad))


class ReportGate(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def gate(self, report, cases, **overrides):
        return frozen.gate(report, cases_dir=cases, **{**GATE_KWARGS, **overrides})

    def test_complete_matching_report_passes(self):
        report, cases = write_report(self.folder.name)
        self.assertEqual(self.gate(report, cases), [])

    def test_missing_rows_fail_closed(self):
        report, cases = write_report(self.folder.name)
        for name in (frozen.REQUIRED_ROWS[0], frozen.REQUIRED_ROWS[-1], "F3-11", "F3-09/low-fee"):
            bad = copy.deepcopy(report)
            del bad["rows"][name]
            self.assertIn("F3_FROZEN_ROW_MISSING:" + name, self.gate(bad, cases), name)
        bad = copy.deepcopy(report)
        bad.pop("rows")
        self.assertIn("F3_FROZEN_ROWS_MISSING", self.gate(bad, cases))
        bad = copy.deepcopy(report)
        bad["rows"]["F3-99/invented"] = {"status": "PASS"}
        self.assertIn("F3_FROZEN_ROW_UNKNOWN:F3-99/invented", self.gate(bad, cases))
        self.assertEqual(self.gate(None, cases), ["F3_FROZEN_REPORT_TYPE"])

    def test_not_run_or_non_pass_required_row_fails(self):
        report, cases = write_report(self.folder.name)
        name = frozen.REQUIRED_ROWS[3]
        for status in ("NOT RUN", "NOT_RUN", "BLOCKED", "FAIL", None):
            bad = copy.deepcopy(report)
            bad["rows"][name]["status"] = status
            self.assertIn("F3_FROZEN_ROW_NOT_PASS:" + name, self.gate(bad, cases), status)
        bad = copy.deepcopy(report)
        bad["status"] = "BLOCKED"
        self.assertIn("F3_FROZEN_STATUS", self.gate(bad, cases))

    def test_pass_claimed_for_a_non_frozen_row_fails(self):
        report, cases = write_report(self.folder.name)
        for name in frozen.NON_FROZEN_ROWS:
            for status in ("PASS", "NOT RUN", "SKIPPED"):
                bad = copy.deepcopy(report)
                bad["rows"][name]["status"] = status
                self.assertIn("F3_FROZEN_NON_FROZEN_ROW_STATUS:" + name, self.gate(bad, cases))

    def test_identity_hash_mismatches_fail(self):
        report, cases = write_report(self.folder.name)
        for key, code in (("source_sha", "F3_FROZEN_SOURCE_MISMATCH:candidate_source_sha"),
                          ("checkout_sha", "F3_FROZEN_SOURCE_MISMATCH:checkout_sha"),
                          ("inventory_sha256", "F3_FROZEN_SOURCE_MISMATCH:build_source_inventory_sha256"),
                          ("executable_sha256", "F3_FROZEN_SOURCE_MISMATCH:frozen_executable_sha256")):
            other = "9" * (40 if key in ("source_sha", "checkout_sha") else 64)
            self.assertIn(code, self.gate(report, cases, **{key: other}), key)
        self.assertIn("F3_FROZEN_CORE_MISMATCH",
                      self.gate(report, cases, core_sha256={"wamd": "9" * 64, "wam-cli": "2" * 64}))
        self.assertIn("F3_FROZEN_WSP_MISMATCH", self.gate(report, cases, wsp_source_commit="0" * 40))
        self.assertIn("F3_FROZEN_EXPECTED_IDENTITY_INVALID", self.gate(report, cases, source_sha="HEAD"))

    def test_case_files_must_match_report_and_bundle(self):
        report, cases = write_report(self.folder.name)
        name = frozen.REQUIRED_ROWS[1]
        fixture = frozen.FROZEN_FIXTURES[1]
        result_path = cases / fixture.case / fixture.name / "result.json"
        result_path.chmod(0o600)
        result_path.write_text(result_path.read_text().replace('"PASS"', '"PASS" '))
        self.assertIn("F3_FROZEN_CASE_RESULT_DIGEST:" + name, self.gate(report, cases))
        result_path.unlink()
        self.assertIn("F3_FROZEN_CASE_RESULT_MISSING:" + name, self.gate(report, cases))

    def test_case_bound_to_other_source_or_core_fails(self):
        def other_source(fixture, result):
            if fixture is frozen.FROZEN_FIXTURES[0]:
                result["source"]["candidate_source_sha"] = "9" * 40
        report, cases = write_report(self.folder.name, other_source)
        self.assertIn("F3_FROZEN_CASE_SOURCE_MISMATCH:" + frozen.REQUIRED_ROWS[0],
                      self.gate(report, cases))

    def test_mainnet_or_unfrozen_report_fails(self):
        report, cases = write_report(self.folder.name)
        for key, value, code in (("mainnet_allowed", True, "F3_FROZEN_MAINNET_ALLOWED"),
                                 ("frozen", False, "F3_FROZEN_NOT_FROZEN"),
                                 ("source_unchanged", False, "F3_FROZEN_SOURCE_CHANGED"),
                                 ("network", "main", "F3_FROZEN_NETWORK")):
            bad = copy.deepcopy(report)
            bad[key] = value
            self.assertIn(code, self.gate(bad, cases), key)


class FrozenRunShell(unittest.TestCase):
    """run() with fake identity/Cocoa/runner: report layout, never PASS without all rows."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.cwd = os.getcwd()
        os.chdir(self.folder.name)
        self.addCleanup(os.chdir, self.cwd)

    def run_shell(self, fake_fixture, *, setup_error=None):
        class App:
            def platformName(self):
                return "cocoa"

        class Adapter:
            def enforce_host(self):
                return None

        def identity():
            if setup_error is not None:
                raise setup_error
            return copy.deepcopy(SOURCE)

        out = io.StringIO()
        with patch.object(frozen, "frozen_source_identity", identity), \
                patch.object(frozen, "frozen_core_identity", lambda core: copy.deepcopy(CORE)), \
                patch.object(frozen, "_require_cocoa", lambda: App()), \
                patch("wam_regtest.wsp_live._pinned_source", lambda source: None), \
                patch("wam_regtest.q05_platforms.DarwinArm64Adapter", Adapter), \
                patch("wam_regtest.qualification.fee_regtest_runner.run_fixture", fake_fixture), \
                patch.object(frozen.platform, "machine", lambda: "arm64"), \
                patch.object(frozen.platform, "system", lambda: "Darwin"), \
                contextlib.redirect_stdout(out):
            code = frozen.run(Path("/bundle/core"), Path("/bundle/wsp-source"))
        report = json.loads(Path(frozen.EVIDENCE_NAME).read_text())
        return code, report, out.getvalue()

    def test_all_required_cases_pass_and_the_gate_accepts_the_written_report(self):
        calls = []

        def fake(fixture, app, adapter, core, source, result, actor=None):
            calls.append((fixture.case, fixture.name, core, source))
            result.update(passing_fields(fixture))
            result["observations"] = {"policy": [], "events": []}

        code, report, printed = self.run_shell(fake)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual([c[:2] for c in calls], [(f.case, f.name) for f in frozen.FROZEN_FIXTURES])
        self.assertTrue(all(c[2:] == (Path("/bundle/core"), Path("/bundle/wsp-source")) for c in calls))
        self.assertEqual(report["source"], SOURCE)
        self.assertIs(report["mainnet_allowed"], False)
        self.assertIn("MACOS_FEE3_FROZEN_STAGE=PASS", printed)
        self.assertEqual(frozen.gate(report, cases_dir=Path(frozen.CASES_DIR), **GATE_KWARGS), [])

    def test_one_failing_case_makes_the_report_fail_and_the_gate_reject_it(self):
        def fake(fixture, app, adapter, core, source, result, actor=None):
            result.update(passing_fields(fixture))
            if fixture.name == "three-inputs":
                result["status"] = "FAIL"
                result["assertions"]["confirmed_debit"] = False
                result["failure_code"] = "F3_PRE_BROADCAST_ASSERTIONS"

        code, report, _ = self.run_shell(fake)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["rows"]["F3-04/three-inputs"]["status"], "FAIL")
        self.assertIn("F3_FROZEN_ROW_NOT_PASS:F3-04/three-inputs",
                      frozen.gate(report, cases_dir=Path(frozen.CASES_DIR), **GATE_KWARGS))

    def test_pass_with_incomplete_case_contract_is_downgraded(self):
        def fake(fixture, app, adapter, core, source, result, actor=None):
            result.update(passing_fields(fixture))
            result["assertions"].pop(next(iter(result["assertions"])))

        code, report, _ = self.run_shell(fake)
        self.assertEqual(code, 2)
        self.assertTrue(all(report["rows"][name]["failure_code"] == "F3_REPORT_CONTRACT_INCOMPLETE"
                            for name in frozen.REQUIRED_ROWS))

    def test_setup_failure_blocks_every_row_and_never_runs_a_case(self):
        def fake(*_args, **_kwargs):
            raise AssertionError("no case may run after a setup failure")

        code, report, printed = self.run_shell(fake, setup_error=ValueError("Q05_FROZEN_RUNTIME_REQUIRED"))
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "BLOCKED")
        self.assertEqual(report["setup_failure_code"], "Q05_FROZEN_RUNTIME_REQUIRED")
        self.assertTrue(all(report["rows"][name]["status"] == "BLOCKED" for name in frozen.REQUIRED_ROWS))
        for name, (status, _reason) in frozen.NON_FROZEN_ROWS.items():
            self.assertEqual(report["rows"][name]["status"], status)
        self.assertIn("MACOS_FEE3_FROZEN_STAGE=SETUP_DENIED", printed)

    def test_unverified_owner_shutdown_stops_every_later_case(self):
        calls = []

        def fake(fixture, app, adapter, core, source, result, actor=None):
            calls.append(fixture.name)
            result.update(passing_fields(fixture))
            result.update(status="FAIL", failure_code="F3_SHUTDOWN_UNCERTAIN")
            result["cleanup"]["verified_original_owner_shutdown"] = False

        code, report, _ = self.run_shell(fake)
        self.assertEqual(code, 2)
        self.assertEqual(calls, [frozen.FROZEN_FIXTURES[0].name])
        self.assertEqual(report["status"], "FAIL")
        later = [report["rows"][name] for name in frozen.REQUIRED_ROWS[1:]]
        self.assertTrue(all(row["status"] == "BLOCKED" for row in later))


class PackageEntryDispatch(unittest.TestCase):
    def _entry(self):
        return runpy.run_path(str(ROOT / "src/wam_regtest/package_entry.py"))["main"]

    def _call(self, argv, qt_platform):
        main = self._entry()
        err = io.StringIO()
        env = {"QT_QPA_PLATFORM": qt_platform} if qt_platform else {}
        with patch.dict(main.__globals__, {"_check_bundle": lambda: (ROOT / "core", ROOT / "wsp")}), \
                patch("wam_regtest.qualification.fee_regtest_frozen.run", return_value=0) as run, \
                patch.object(sys, "argv", ["wallet", *argv]), \
                patch.dict(os.environ, env, clear=False), \
                contextlib.redirect_stderr(err):
            if not qt_platform:
                os.environ.pop("QT_QPA_PLATFORM", None)
            code = main()
        return code, run, err.getvalue()

    def test_exact_argv_dispatches_bundled_resources_on_cocoa(self):
        code, run, _ = self._call(["--ci-fee-regtest"], "cocoa")
        self.assertEqual(code, 0)
        run.assert_called_once_with(ROOT / "core", ROOT / "wsp")

    def test_any_extra_or_altered_argument_is_denied(self):
        for argv in (["--ci-fee-regtest", "F3-01"], ["--ci-fee-regtest", "--rate", "5000"],
                     ["--ci-fee-regtest=F3-07"], ["--ci-fee-regtest", "--ci-fee-regtest"],
                     ["--CI-FEE-REGTEST"], ["--ci-fee-regtest "], ["--ci-fee-regtest", ""]):
            code, run, err = self._call(argv, "cocoa")
            self.assertEqual(code, 2, argv)
            run.assert_not_called()
            self.assertIn("WAM_REGTEST_BUNDLE_LAUNCH_DENIED:WAM_BUNDLE_ARGUMENT_DENIED", err, argv)

    def test_native_cocoa_platform_is_required(self):
        for qt_platform in ("offscreen", "minimal", None):
            code, run, err = self._call(["--ci-fee-regtest"], qt_platform)
            self.assertEqual(code, 2, qt_platform)
            run.assert_not_called()
            self.assertIn("WAM_REGTEST_BUNDLE_LAUNCH_DENIED:WAM_BUNDLE_COCOA_PLATFORM_REQUIRED", err)

    def test_dispatch_is_inside_main_with_no_module_level_import(self):
        entry = (ROOT / "src/wam_regtest/package_entry.py").read_text()
        self.assertIn('sys.argv[1:] == ["--ci-fee-regtest"]', entry)
        tree = ast.parse(entry)
        module_imports = [ast.dump(node) for node in tree.body
                          if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any("fee_regtest" in item for item in module_imports))


class ProductionRefusal(unittest.TestCase):
    def test_production_entry_refuses_with_64_before_resources(self):
        for argv in (["--ci-fee-regtest"], ["--ci-fee-regtest", "F3-01"], ["--check-bundle", "--ci-fee-regtest"]):
            with self.subTest(argv=argv), patch.object(sys, "argv", ["wallet", *argv]), \
                    patch.dict(os.environ, {"CI": "true", "WAM_QUALIFICATION": "1",
                                            "GITHUB_ACTIONS": "true", "WAM_Q06_CI_SPEND_QUALIFY": "1",
                                            "QT_QPA_PLATFORM": "cocoa"}), \
                    patch.object(production_entry, "checked_resources") as check:
                self.assertEqual(production_entry.main(), 64)
                check.assert_not_called()

    def test_flag_is_in_every_production_negative_list(self):
        self.assertIn(["--ci-fee-regtest"], [list(group) for group in policy.DEVELOPER_ARGV])
        self.assertIn("'--ci-fee-regtest'", (ROOT / "scripts/build_macos_production.py").read_text())


class ProvenanceRegistration(unittest.TestCase):
    MODULES = ("qualification.fee_regtest", "qualification.fee_regtest_runner",
               "qualification.fee_regtest_frozen")

    def test_qualification_bundle_imports_the_modules_and_production_excludes_them(self):
        text = (ROOT / "scripts/build_macos_bundle.sh").read_text()
        names = policy.wallet_module_names(ROOT)
        for module in self.MODULES:
            self.assertIn("--hidden-import wam_regtest." + module, text)
            self.assertIn(module, names)
            for platform_name in ("macos", "windows", "linux-desktop"):
                self.assertNotIn(module, policy.runtime_modules(platform_name))
                args = policy.arguments(ROOT, platform_name)
                hidden = {args[i + 1] for i in range(0, len(args), 2) if args[i] == "--hidden-import"}
                excluded = {args[i + 1] for i in range(0, len(args), 2) if args[i] == "--exclude-module"}
                self.assertNotIn("wam_regtest." + module, hidden)
                self.assertIn("wam_regtest." + module, excluded)

    def test_build_stage_runs_after_q06_fix_and_gates_the_copied_report(self):
        text = (ROOT / "scripts/build_macos_bundle.sh").read_text()
        fix_pass = text.index("MACOS_APP_STAGE=FROZEN_Q06_FIX_SCENARIOS_PASS")
        start = text.index("MACOS_APP_STAGE=FROZEN_FEE3_REGTEST_START")
        passed = text.index("MACOS_APP_STAGE=FROZEN_FEE3_REGTEST_PASS")
        network = text.index("MACOS_APP_STAGE=FROZEN_V1_NET_START")
        self.assertLess(fix_pass, start)
        self.assertLess(start, passed)
        self.assertLess(passed, network)
        window = text[start:passed]
        self.assertIn("'--ci-fee-regtest'", window)
        self.assertIn("env=spend_env", window)
        self.assertIn("fee3_gate(", window)
        self.assertIn("Q05_BUILD_SOURCE.json", window)
        self.assertIn("WAM_BUNDLE_APP", window)
        self.assertLess(window.index("shutil.copyfile(report, out/FEE3_EVIDENCE)"),
                        window.index("assert problems == []"))
        self.assertIn("assert fee3.returncode == 0", window)

    def test_every_build_heredoc_is_valid_python(self):
        import re
        text = (ROOT / "scripts/build_macos_bundle.sh").read_text()
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY\n", text, re.S)
        self.assertGreaterEqual(len(blocks), 4)
        self.assertTrue(any("FROZEN_FEE3_REGTEST_START" in block for block in blocks))
        for index, block in enumerate(blocks):
            compile(block, "build_macos_bundle.sh heredoc %d" % index, "exec")

    def test_frozen_mode_imports_no_developer_test_module_and_no_cli_knobs(self):
        for name in ("fee_regtest_frozen.py", "fee_regtest_runner.py", "fee_regtest.py"):
            tree = ast.parse((ROOT / "src/wam_regtest/qualification" / name).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    imported = [node.module or ""]
                elif isinstance(node, ast.Import):
                    imported = [alias.name for alias in node.names]
                else:
                    continue
                for module in imported:
                    self.assertFalse(module == "tests" or module.startswith(("tests.", "test_")),
                                     (name, module))
        source = (ROOT / "src/wam_regtest/qualification/fee_regtest_frozen.py").read_text()
        for forbidden in ("sys.argv", "argparse", "os.environ", "getenv"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
