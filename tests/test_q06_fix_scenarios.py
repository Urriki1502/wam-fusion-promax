"""Structure and marker contract for the frozen Q06 fix-scenario stage.

The real Core/cocoa scenarios run only inside the frozen app. These tests
drive the evidence shell with fakes and check the wiring that keeps the
module out of the production wallet.
"""
import ast
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

from wam_regtest.foundation import diagnostics
from wam_regtest.qualification import q06_fix_scenarios as stage

ROOT = Path(__file__).resolve().parents[1]


def _policy():
    spec = importlib.util.spec_from_file_location(
        "packaging_policy_q06_fix", ROOT / "scripts/production_packaging.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _passing(report):
    report["s1"] = {
        "same_txid_shown": True, "pending_matches": True, "confirm_enabled": True,
        "status_awaiting_confirmation": True, "reservation_held": True,
        "tx_in_verified_history": True, "balance_arithmetic_exact": True,
        "send_page_confirmed": True, "second_reopen_no_pending": True,
        "second_reopen_no_spurious": True, "funded_atoms": 500_000_000,
        "payment_atoms": 100_000_000, "fee_atoms": 10_000, "change_atoms": 390_000_000,
        "confirmed_atoms": 390_000_000, "available_atoms": 390_000_000,
        "txid_sha256": "ab" * 32, "mnemonic_once": "abandon " * 12,
    }


class FixScenarioArithmetic(unittest.TestCase):
    def test_confirmed_balance_identity(self):
        funded, payment, fee = 500_000_000, 100_000_000, 10_000
        change = funded - payment - fee
        history = (
            {"txid": "aa" * 32, "atoms": funded},
            {"txid": "bb" * 32, "atoms": -(payment + fee)},
        )
        self.assertTrue(stage.exact_confirmed_balance(
            funded, payment, fee, change, change, change, history, "bb" * 32))
        self.assertFalse(stage.exact_confirmed_balance(
            funded, payment, fee, change, funded, change, history, "bb" * 32))
        self.assertTrue(stage.reservation_still_held(funded, funded, 0, 1, 0))
        self.assertFalse(stage.reservation_still_held(funded, funded, funded, 1, 0))

    def test_stay_default_and_verified_ack_are_public_booleans_only(self):
        self.assertTrue(stage.stay_is_default(True, False, False))
        self.assertFalse(stage.stay_is_default(True, True, False))
        mac = "cd" * 32
        raw = json.dumps({
            "version": 1, "acknowledged": True, "deferred": False,
            "seed_id": "not-a-phrase", "mac": mac,
        }).encode()
        self.assertTrue(stage.ack_is_verified(raw))
        downgraded = json.dumps({
            "version": 1, "acknowledged": False, "deferred": True, "seed_id": "x",
        }).encode()
        self.assertFalse(stage.ack_is_verified(downgraded))
        forged = json.dumps({
            "version": 1, "acknowledged": True, "deferred": False,
            "seed_id": "not-a-phrase", "mac": "00" * 32,
        }).encode()
        self.assertTrue(stage.ack_is_verified(forged))
        self.assertFalse(stage.ack_is_verified(forged[:-2]))


class FixScenarioEvidence(unittest.TestCase):
    def test_public_evidence_drops_secrets_and_passes_only_when_all_scenarios_pass(self):
        raw = stage.public_evidence({
            "status": "PASS",
            "scenarios": {"S1": "PASS", "S2": "PASS", "S3": "PASS"},
            "frozen": True,
            "source_sha": "a" * 40,
            "mnemonic_once": "abandon abandon",
            "s1": {"same_txid_shown": True, "mnemonic_once": "abandon abandon",
                   "txid_sha256": "ab" * 32, "funded_atoms": -1},
            "password": "public-disposable-must-not-be-copied",
        })
        encoded = json.dumps(raw)
        self.assertNotIn("abandon", encoded)
        self.assertNotIn("mnemonic", encoded)
        self.assertEqual(raw["status"], "PASS")
        self.assertEqual(raw["s1"]["txid_sha256"], "ab" * 32)
        self.assertNotIn("funded_atoms", raw["s1"])
        self.assertNotIn("diagnostics", raw)
        refused = stage.public_evidence({
            "status": "PASS",
            "scenarios": {"S1": "PASS", "S2": "FAIL", "S3": "NOT_RUN"},
            "failure_code": "seed words are not a code",
            "diagnostics": [{"stage": "CONFIRM_PENDING", "category": "ValueError",
                             "open_stage": None},
                            {"stage": "bad stage", "category": "INTERNAL", "open_stage": "NOPE"}],
        })
        self.assertEqual(refused["status"], "FAIL")
        self.assertEqual(refused["failure_code"], "INTERNAL")
        self.assertNotIn("failure_exception", refused)
        self.assertEqual(refused["diagnostics"], [
            {"stage": "CONFIRM_PENDING", "category": "ValueError", "open_stage": None}])

        with_valid_exc = stage.public_evidence({
            "status": "FAIL",
            "scenarios": {"S1": "FAIL", "S2": "NOT_RUN", "S3": "NOT_RUN"},
            "failure_code": "INTERNAL",
            "failure_exception": "BrokenPipeError",
        })
        self.assertEqual(with_valid_exc["failure_exception"], "BrokenPipeError")

        with_null_exc = stage.public_evidence({
            "status": "FAIL",
            "scenarios": {"S1": "FAIL", "S2": "NOT_RUN", "S3": "NOT_RUN"},
            "failure_code": "INTERNAL",
            "failure_exception": None,
        })
        self.assertNotIn("failure_exception", with_null_exc)

        for bad_exc in ("/Users/alice/secret", "1Bad", "A" * 65, "Err\n", 123):
            sanitized = stage.public_evidence({
                "status": "FAIL",
                "scenarios": {"S1": "FAIL", "S2": "NOT_RUN", "S3": "NOT_RUN"},
                "failure_code": "INTERNAL",
                "failure_exception": bad_exc,
            })
            self.assertNotIn("failure_exception", sanitized)

    def test_drive_prints_pass_markers_and_writes_public_evidence(self):
        def s1(report):
            _passing(report)

        def s2(report):
            report["s2"] = {"stay_default": True, "stay_keeps_display": True,
                            "leave_clears_phrase": True, "verified_ack": True,
                            "defer_preserves_ack": True, "reopen_still_verified": True}

        def s3(report):
            report["s3"] = {"welcome_visible": True, "not_modal": True,
                            "quit_menu_enabled": True, "command_q_quit": True,
                            "wallet_route_called": False}

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / stage.EVIDENCE_NAME
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = stage.drive(
                    (("S1", s1), ("S2", s2), ("S3", s3)),
                    {"frozen": False, "source_sha": "b" * 40, "network": "regtest",
                     "mainnet_allowed": False},
                    evidence_path=path)
            text = buffer.getvalue()
            self.assertEqual(code, 0)
            for marker in ("START", "S1_PASS", "S2_PASS", "S3_PASS", "ALL_PASS"):
                self.assertIn("MACOS_Q06_FIX_STAGE=" + marker, text)
            self.assertNotIn("MACOS_Q06_FIX_STAGE=DENIED", text)
            evidence = json.loads(path.read_text())
            self.assertEqual(evidence["status"], "PASS")
            self.assertEqual(evidence["scenarios"], {"S1": "PASS", "S2": "PASS", "S3": "PASS"})
            self.assertNotIn("diagnostics", evidence)
            self.assertNotIn("abandon", path.read_text())

    def test_drive_failure_exits_2_and_keeps_diagnostic_tokens(self):
        def s1(report):
            diagnostics.record("CONFIRM_PENDING", ValueError("Q06_CONFIRM_EXACT_PENDING_TX_REQUIRED"))
            report["mnemonic_once"] = "abandon abandon abandon"
            raise ValueError("Q06_FIX_S1_REOPEN_PENDING_DENIED")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / stage.EVIDENCE_NAME
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = stage.drive((("S1", s1),), evidence_path=path)
            evidence = json.loads(path.read_text())
            self.assertEqual(code, 2)
            self.assertIn("MACOS_Q06_FIX_STAGE=DENIED", buffer.getvalue())
            self.assertNotIn("ALL_PASS", buffer.getvalue())
            self.assertEqual(evidence["scenarios"], {"S1": "FAIL", "S2": "NOT_RUN", "S3": "NOT_RUN"})
            self.assertEqual(evidence["failure_code"], "Q06_FIX_S1_REOPEN_PENDING_DENIED")
            self.assertNotIn("failure_exception", evidence)
            self.assertEqual(evidence["diagnostics"][0]["stage"], "CONFIRM_PENDING")
            self.assertEqual(evidence["diagnostics"][0]["category"],
                             "Q06_CONFIRM_EXACT_PENDING_TX_REQUIRED")
            self.assertNotIn("abandon", path.read_text())

    def test_drive_generic_fallback_records_class_name_without_secret_message(self):
        def s1(_report):
            raise BrokenPipeError(32, "/Users/alice/secret_mnemonic_phrase")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / stage.EVIDENCE_NAME
            with redirect_stdout(io.StringIO()):
                code = stage.drive((("S1", s1),), evidence_path=path)
            raw_text = path.read_text()
            evidence = json.loads(raw_text)
            self.assertEqual(code, 2)
            self.assertEqual(evidence["failure_code"], "INTERNAL")
            self.assertEqual(evidence["failure_exception"], "BrokenPipeError")
            self.assertNotIn("/Users/alice", raw_text)
            self.assertNotIn("secret_mnemonic_phrase", raw_text)


class FixScenarioWiring(unittest.TestCase):
    def test_real_scenario_source_declares_fixed_markers_and_the_command_q_event(self):
        text = Path(stage.__file__).read_text()
        for marker in (
                "S1_CREATE_PASS", "S1_BACKUP_PASS", "S1_FUND_PASS", "S1_ENABLE_PASS",
                "S1_BROADCAST_PASS", "S1_QUIT_BEFORE_CONFIRM_PASS",
                "S1_REOPEN_PENDING_PASS", "S1_CONFIRM_PASS", "S1_NO_STALE_RESERVATION_DISPLAY_PASS",
                "S1_SECOND_REOPEN_PASS",
                "S2_STAY_DEFAULT_PASS", "S2_STAY_KEEPS_DISPLAY_PASS",
                "S2_LEAVE_CLEARS_PHRASE_PASS", "S2_VERIFIED_BACKUP_PASS",
                "S2_DEFER_PRESERVES_ACK_PASS", "S2_REOPEN_VERIFIED_PASS",
                "S3_WELCOME_VISIBLE_PASS", "S3_QUIT_MENU_ENABLED_PASS",
                "S3_COMMAND_Q_NO_ROUTE_PASS", "ALL_PASS", "DENIED"):
            self.assertIn(marker, text)
        self.assertIn("keyEventWithType:location:modifierFlags:timestamp:windowNumber:context:", text)
        self.assertIn("sendEvent:", text)
        self.assertIn("q05-disposable.keychain-db", text)
        self.assertIn(".wam-regtest-temp", text)
        self.assertNotIn("sys.path", text)

    def test_package_entry_dispatches_only_inside_main_and_production_refuses_the_flag(self):
        entry = (ROOT / "src/wam_regtest/package_entry.py").read_text()
        self.assertIn('"--ci-q06-fix-scenarios"', entry)
        self.assertIn("wam_regtest.qualification.q06_fix_scenarios", entry)
        tree = ast.parse(entry)
        module_imports = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module_imports.append(ast.dump(node))
        self.assertFalse(any("q06_fix_scenarios" in item for item in module_imports))
        policy = _policy()
        self.assertIn(["--ci-q06-fix-scenarios"], [list(group) for group in policy.DEVELOPER_ARGV])
        names = policy.wallet_module_names(ROOT)
        self.assertIn("qualification.q06_fix_scenarios", names)
        self.assertNotIn("qualification.q06_fix_scenarios", policy.runtime_modules("macos"))
        args = policy.arguments(ROOT, "macos")
        hidden = {args[index + 1] for index in range(0, len(args), 2) if args[index] == "--hidden-import"}
        excluded = {args[index + 1] for index in range(0, len(args), 2) if args[index] == "--exclude-module"}
        self.assertNotIn("wam_regtest.qualification.q06_fix_scenarios", hidden)
        self.assertIn("wam_regtest.qualification.q06_fix_scenarios", excluded)

    def test_frozen_bundle_runs_the_stage_after_spend_with_the_same_timeout(self):
        text = (ROOT / "scripts/build_macos_bundle.sh").read_text()
        start = text.index("MACOS_APP_STAGE=FROZEN_Q06_FIX_SCENARIOS_START")
        spend = text.index("MACOS_APP_STAGE=FROZEN_Q06_BIP39_SPEND_PASS")
        passed = text.index("MACOS_APP_STAGE=FROZEN_Q06_FIX_SCENARIOS_PASS")
        network = text.index("MACOS_APP_STAGE=FROZEN_V1_NET_START")
        self.assertLess(spend, start)
        self.assertLess(passed, network)
        window = text[start:passed]
        self.assertIn("'--ci-q06-fix-scenarios'", window)
        self.assertIn("env=spend_env", window)
        self.assertIn("timeout=600", window)
        self.assertIn("q06-fix-scenarios-evidence.json", window)
        self.assertIn("--hidden-import wam_regtest.qualification.q06_fix_scenarios", text)
        production = (ROOT / "scripts/build_macos_production.py").read_text()
        self.assertIn("'--ci-q06-fix-scenarios'", production)


class BoundedShutdown(unittest.TestCase):
    def test_busy_cancel_finishes_before_quit_is_submitted(self):
        import threading
        from types import SimpleNamespace
        from wam_regtest.wallet_executor import WalletExecutor
        started, release = threading.Event(), threading.Event()
        class Backend:
            def execute(self, action, args, kwargs):
                if action == "cancel":
                    started.set()
                    release.wait(2)
            def public_state(self):
                return {"core_alive": False}
        executor = WalletExecutor(Backend)
        executor.submit("cancel")
        self.assertTrue(started.wait(1))
        state = {"executor": executor, "app": SimpleNamespace(processEvents=release.set)}
        try:
            self.assertFalse(stage._shutdown(state, timeout=1))
            self.assertTrue(executor.closed)
            self.assertTrue(executor.join(0))
        finally:
            release.set()
            if not executor.closed:
                import time
                deadline = time.monotonic() + 2
                while executor.busy and time.monotonic() < deadline:
                    time.sleep(.001)
                executor.request("quit", timeout=2)
            executor.join(2)

    def test_stuck_shutdown_is_bounded_and_fail_closed(self):
        import time
        from concurrent.futures import Future
        from types import SimpleNamespace
        # Quit is accepted but never acknowledged. No real owner/process.
        executors = (
            SimpleNamespace(closed=False, busy=False, submit=lambda action: Future()),
            SimpleNamespace(closed=False, busy=True),
            SimpleNamespace(closed=True, join=lambda timeout: False),
        )
        for executor in executors:
            with self.subTest(executor=executor):
                state = {"executor": executor}
                start = time.monotonic()
                self.assertTrue(stage._shutdown(state, timeout=.03))
                self.assertLess(time.monotonic() - start, .3)
                self.assertEqual(state["shutdown_failure_code"], "Q06_FIX_SHUTDOWN_TIMEOUT")


if __name__ == "__main__":
    unittest.main()
