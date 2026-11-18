"""Pure unit contracts for the Q05 genuine D-QUIT-1 qualification harness."""
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from wam_regtest.qualification import q05_dquit1_runner as runner
from wam_regtest.wallet_executor import WalletExecutorError
from wam_regtest.wallet_session import WalletSessionError


def _valid_scenario(scenario_id, name):
    return {
        "scenario_id": scenario_id,
        "name": name,
        "profile_fixture_id": "wam-fusion-core-" + "a" * 16,
        "status": "PASS",
        "stage": "COMPLETED",
        "failure_code": None,
        "test_layer": "FAULT_INJECTED_REAL_CORE",
        "fault_boundary": runner.FAULT_BOUNDARIES[scenario_id],
        "one_quit": True,
        "quit_count": 1,
        "orphan_free": True,
        "observed_exit": 0,
        "reopen_observed_exit": 0,
        "core_stopped": True,
        "lease_released_only_after_notice": True,
        "assertions": {"check_one": True},
        "events": ["ACTION_QUIT", "PUBLISH_NOTICE", "OWNER_RELEASE", "OWNER_CLOSE"],
    }


def _valid_report():
    return {
        "schema": runner.SCHEMA,
        "status": "PASS",
        "checkout_sha": "a" * 40,
        "source_unchanged": True,
        "core_sha256": {"wamd": "b" * 64, "wam-cli": "c" * 64},
        "one_quit": True,
        "orphan_free": True,
        "accepted": False,
        "mainnet_allowed": False,
        "exit_code": 0,
        "scenarios": {
            "S-Q05-A": _valid_scenario("S-Q05-A", "faulted-then-reopen"),
            "S-Q05-B": _valid_scenario("S-Q05-B", "uncertain-checkpoint-quit"),
        },
    }


class Q05DQuit1HarnessPureContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_refusal_mapping_preserves_public_codes_and_redacts_arbitrary_text(self):
        self.assertEqual(
            runner.map_refusal_code(WalletExecutorError("QUIT_NOTICE_REVIEW_REQUIRED")),
            "QUIT_NOTICE_REVIEW_REQUIRED",
        )
        self.assertEqual(
            runner.map_refusal_code(WalletSessionError("WALLET_MANAGED_OPEN_DENIED")),
            "WALLET_MANAGED_OPEN_DENIED",
        )
        self.assertEqual(
            runner.map_refusal_code(ValueError("Q05_DQUIT1_CONSENT_REQUIRED")),
            "Q05_DQUIT1_CONSENT_REQUIRED",
        )
        self.assertEqual(
            runner.map_refusal_code(RuntimeError("/Users/secret/path leaked text")),
            "INTERNAL",
        )
        self.assertEqual(
            runner.map_refusal_code(ValueError("CODE_WITH_" + "a" * 16)),
            "INTERNAL",
        )

    def test_report_schema_accepts_valid_pass_and_rejects_broken_invariants(self):
        good = _valid_report()
        self.assertTrue(runner.validate_run_report(good))

        for mutate in (
            lambda r: r.update(accepted=True),
            lambda r: r.update(mainnet_allowed=True),
            lambda r: r.update(source_unchanged=False),
            lambda r: r.update(exit_code=2),
            lambda r: r.update(checkout_sha="bad"),
            lambda r: r.update(core_sha256={"wamd": "b" * 64}),
            lambda r: r["scenarios"]["S-Q05-A"].update(one_quit=False),
            lambda r: r["scenarios"]["S-Q05-A"].update(quit_count=2),
            lambda r: r["scenarios"]["S-Q05-A"].update(orphan_free=False),
            lambda r: r["scenarios"]["S-Q05-A"].update(observed_exit=None),
            lambda r: r["scenarios"]["S-Q05-B"].update(lease_released_only_after_notice=False),
            lambda r: r["scenarios"]["S-Q05-B"].update(assertions={"check_one": False}),
            lambda r: r["scenarios"]["S-Q05-B"].update(test_layer="MOCK"),
        ):
            bad = _valid_report()
            mutate(bad)
            self.assertFalse(runner.validate_run_report(bad))

    def test_aggregate_status_and_blocked_report_validation(self):
        s_a = _valid_scenario("S-Q05-A", "faulted-then-reopen")
        s_b = _valid_scenario("S-Q05-B", "uncertain-checkpoint-quit")
        self.assertEqual(runner.aggregate_run_status({"S-Q05-A": s_a, "S-Q05-B": s_b}), "PASS")
        self.assertEqual(
            runner.aggregate_run_status({"S-Q05-A": s_a, "S-Q05-B": s_b}, source_unchanged=False),
            "FAIL",
        )
        blocked_b = dict(s_b, status="BLOCKED", failure_code="Q05_DQUIT1_NATIVE_MACOS_ARM64_REQUIRED")
        self.assertEqual(
            runner.aggregate_run_status({"S-Q05-A": s_a, "S-Q05-B": blocked_b}),
            "BLOCKED",
        )
        failed_a = dict(s_a, status="FAIL", failure_code="Q05_DQUIT1_FAULTED_QUIT_INVARIANT_FAILED")
        self.assertEqual(
            runner.aggregate_run_status({"S-Q05-A": failed_a, "S-Q05-B": blocked_b}),
            "FAIL",
        )
        blocked_report = _valid_report()
        blocked_report["status"] = "BLOCKED"
        blocked_report["exit_code"] = 2
        blocked_report["scenarios"]["S-Q05-B"] = blocked_b
        self.assertTrue(runner.validate_run_report(blocked_report))

    def test_pid_and_popen_stop_checks(self):
        self.assertFalse(runner.pid_is_alive(0))
        self.assertFalse(runner.pid_is_alive(-5))
        with patch.object(runner.os, "kill", side_effect=ProcessLookupError):
            self.assertFalse(runner.pid_is_alive(4242))
            stopped, code, orphan_free = runner.check_popen_stopped(
                SimpleNamespace(poll=lambda: 0, pid=4242)
            )
            self.assertEqual((stopped, code, orphan_free), (True, 0, True))
        with patch.object(runner.os, "kill", side_effect=PermissionError):
            self.assertTrue(runner.pid_is_alive(4242))
            stopped, code, orphan_free = runner.check_popen_stopped(
                SimpleNamespace(poll=lambda: 0, pid=4242)
            )
            self.assertEqual((stopped, code, orphan_free), (True, 0, False))
        still_running = SimpleNamespace(poll=lambda: None, pid=4242)
        self.assertEqual(runner.check_popen_stopped(still_running), (False, None, False))

    def test_lease_order_requires_publish_before_release_and_close(self):
        backend = Mock()
        backend.events = ["ACTION_QUIT", "PUBLISH_NOTICE", "OWNER_RELEASE", "OWNER_CLOSE"]
        backend.lease_checks = [{"lease_held_before": True, "lease_held_after": True}]
        self.assertTrue(runner._lease_order_holds(backend))

        backend.events = ["ACTION_QUIT", "OWNER_RELEASE", "PUBLISH_NOTICE", "OWNER_CLOSE"]
        self.assertFalse(runner._lease_order_holds(backend))

        backend.events = ["ACTION_QUIT", "PUBLISH_NOTICE", "OWNER_RELEASE", "OWNER_CLOSE"]
        backend.lease_checks = [{"lease_held_before": False, "lease_held_after": False}]
        self.assertFalse(runner._lease_order_holds(backend))

    def test_cli_scope_guards_refuse_before_touching_core_or_output(self):
        checkout = Path(__file__).resolve().parents[1]
        base_args = [
            "--core", str(self.root / "core"),
            "--core-archive", str(self.root / "archive.tar.gz"),
            "--signed-manifest-dir", str(self.root / "manifest"),
            "--wsp-source", str(self.root / "wsp"),
            "--output", str(self.root / "out"),
        ]
        with self.assertRaisesRegex(SystemExit, "Q05_DQUIT1_CONSENT_REQUIRED"):
            runner.main(base_args)
        self.assertFalse((self.root / "out").exists())

        existing = self.root / "existing"
        existing.mkdir()
        with self.assertRaisesRegex(SystemExit, "Q05_DQUIT1_NEW_OUTPUT_REQUIRED"):
            runner.main([
                *base_args[:-2], "--output", str(existing), "--confirm-disposable-regtest",
            ])

        with self.assertRaisesRegex(SystemExit, "Q05_DQUIT1_EXTERNAL_OUTPUT_REQUIRED"):
            runner.main([
                *base_args[:-2], "--output", str(checkout / "bad-out"), "--confirm-disposable-regtest",
            ])

        with patch.object(sys, "frozen", True, create=True):
            with self.assertRaisesRegex(SystemExit, "Q05_DQUIT1_SOURCE_ONLY_DENIED"):
                runner.main([*base_args, "--confirm-disposable-regtest"])


if __name__ == "__main__":
    unittest.main()
