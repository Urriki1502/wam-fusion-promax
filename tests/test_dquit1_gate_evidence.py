"""Pure unit contracts for PM-075 D-QUIT-1 gate evidence helpers and validators."""
from hashlib import sha256
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from wam_regtest.core_supervisor import STOP_EXIT_BUDGET
from wam_regtest.qualification import dquit1_gate_evidence as gates


def _valid_t1_samples(count=10, reply_to_exit_s=0.25):
    return [
        {
            "sample_index": idx + 1,
            "stop_path": "shutdown" if idx < 6 else "recover_stop",
            "fixture_state": "fresh" if idx < 3 else "blocks_101_mempool_tx",
            "profile_fixture_id": f"wam-fusion-core-{idx:016x}",
            "stop_rpc_reply_s": 0.01,
            "reply_to_exit_s": reply_to_exit_s + (idx * 0.01),
            "total_stop_s": 0.26 + (idx * 0.01),
            "stop_exit_budget_s": STOP_EXIT_BUDGET,
            "observed_exit_code": 0,
            "fits_budget": True,
            "orphan_free": True,
            "status": "PASS",
        }
        for idx in range(count)
    ]


def _valid_crash_case(case_id):
    return {
        "case_id": case_id,
        "boundary": "before_link" if "R-n1" in case_id else "before_unlink",
        "action_kind": "ack" if case_id == "R-n2-ACK" else "notice",
        "session_kind": "Q06" if "Q06" in case_id else "Q05",
        "filesystem": "apfs",
        "signal_sent": "SIGKILL",
        "observed_returncode": -9,
        "assertions": {"ok": True},
        "status": "PASS",
    }


def _valid_crash_receipt():
    return {
        "schema": gates.CRASH_SCHEMA,
        "status": "PASS",
        "checkout_sha": "a" * 40,
        "source_unchanged": True,
        "accepted": False,
        "mainnet_allowed": False,
        "exit_code": 0,
        "cases": {cid: _valid_crash_case(cid) for cid in gates.REQUIRED_CRASH_CASES},
    }


def _valid_t1_receipt():
    samples = _valid_t1_samples(10)
    summary = gates.summarize_exit_samples(samples, STOP_EXIT_BUDGET)
    return {
        "schema": gates.T1_SCHEMA,
        "status": "PASS",
        "checkout_sha": "a" * 40,
        "source_unchanged": True,
        "core_sha256": {"wamd": "b" * 64, "wam-cli": "c" * 64},
        "stop_exit_budget_s": STOP_EXIT_BUDGET,
        "summary": summary,
        "samples": samples,
        "accepted": False,
        "mainnet_allowed": False,
        "exit_code": 0,
    }


def _valid_t2_receipt():
    return {
        "schema": gates.T2_SCHEMA,
        "status": "PASS",
        "checkout_sha": "a" * 40,
        "source_unchanged": True,
        "core_sha256": {"wamd": "b" * 64, "wam-cli": "c" * 64},
        "accepted": False,
        "mainnet_allowed": False,
        "exit_code": 0,
        "scenarios": {
            "F3-14/crypto-failure": {
                "scenario": "F3-14/crypto-failure",
                "status": "PASS",
                "one_quit": True,
                "quit_count": 1,
                "orphan_free": True,
                "observed_exit": 0,
                "runtime_preserved": True,
                "wsp_sqlite_file_count": 1,
                "payment_evidence_file_count": 0,
                "across_stop": {"byte_identical": True, "changed_files": []},
            },
            "F3-14/lost-send-response": {
                "scenario": "F3-14/lost-send-response",
                "status": "PASS",
                "one_quit": True,
                "quit_count": 1,
                "orphan_free": True,
                "observed_exit": 0,
                "runtime_preserved": True,
                "wsp_sqlite_file_count": 1,
                "payment_evidence_file_count": 2,
                "across_stop": {"byte_identical": True, "changed_files": []},
            },
        },
    }


class DQuit1GateEvidencePureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_summarize_exit_samples_stats_and_budget_enforcement(self):
        samples = [
            {"reply_to_exit_s": 0.2, "observed_exit_code": 0, "orphan_free": True},
            {"reply_to_exit_s": 0.4, "observed_exit_code": 0, "orphan_free": True},
            {"reply_to_exit_s": 0.6, "observed_exit_code": 0, "orphan_free": True},
            {"reply_to_exit_s": 0.8, "observed_exit_code": 0, "orphan_free": True},
            {"reply_to_exit_s": 1.0, "observed_exit_code": 0, "orphan_free": True},
            {"reply_to_exit_s": 1.2, "observed_exit_code": 0, "orphan_free": True},
            {"reply_to_exit_s": 1.4, "observed_exit_code": 0, "orphan_free": True},
            {"reply_to_exit_s": 1.6, "observed_exit_code": 0, "orphan_free": True},
            {"reply_to_exit_s": 1.8, "observed_exit_code": 0, "orphan_free": True},
            {"reply_to_exit_s": 2.0, "observed_exit_code": 0, "orphan_free": True},
        ]
        summary = gates.summarize_exit_samples(samples, 20)
        self.assertEqual(summary["sample_count"], 10)
        self.assertEqual(summary["min_reply_to_exit_s"], 0.2)
        self.assertEqual(summary["median_reply_to_exit_s"], 1.1)
        self.assertEqual(summary["max_reply_to_exit_s"], 2.0)
        self.assertEqual(summary["mean_reply_to_exit_s"], 1.1)
        self.assertTrue(summary["all_samples_fit_budget"])
        self.assertTrue(summary["all_exit_zero"])
        self.assertTrue(summary["all_orphan_free"])

        over_budget = gates.summarize_exit_samples(samples, 1.5)
        self.assertFalse(over_budget["all_samples_fit_budget"])

        with self.assertRaisesRegex(ValueError, "DQUIT1_GATE_INSUFFICIENT_SAMPLES"):
            gates.summarize_exit_samples(samples[:9], 20)

        bad_sample = list(samples)
        bad_sample[0] = {"reply_to_exit_s": -0.1, "observed_exit_code": 0, "orphan_free": True}
        with self.assertRaisesRegex(ValueError, "DQUIT1_GATE_INVALID_SAMPLE"):
            gates.summarize_exit_samples(bad_sample, 20)

    def test_snapshot_and_compare_wallet_files_detects_identical_and_changed_bytes(self):
        chain = self.root / "chain"
        chain.mkdir(mode=0o700)
        sqlite_file = chain / "wallet-runtime-recovery-0123456789abcdef.sqlite"
        sqlite_file.write_bytes(b"sqlite-payload-v1")
        scan_lock = chain / "wallet-runtime-recovery-0123456789abcdef.sqlite.scan.lock"
        scan_lock.write_bytes(b"")
        ev_dir = chain / "q06-payment-evidence"
        ev_dir.mkdir(mode=0o700)
        ev_signed = ev_dir / ("a" * 32 + "-signed.enc")
        ev_signed.write_bytes(b"sealed-signed-v1")
        cp_dir = chain / ("bip39-12-scan-" + "a" * 32)
        cp_dir.mkdir(mode=0o700)
        (cp_dir / "snapshot-000001.enc").write_bytes(b"checkpoint-v1")

        before = gates.snapshot_wallet_files(chain)
        self.assertEqual(len(before["wsp_sqlite"]), 2)
        self.assertEqual(len(before["payment_evidence"]), 1)
        self.assertEqual(len(before["native_checkpoint"]), 1)
        self.assertEqual(
            before["wsp_sqlite"][0]["sha256"],
            sha256(b"sqlite-payload-v1").hexdigest(),
        )

        after_same = gates.snapshot_wallet_files(chain)
        same_diff = gates.compare_file_snapshots(before, after_same)
        self.assertTrue(same_diff["byte_identical"])
        self.assertEqual(same_diff["changed_files"], [])
        self.assertEqual(same_diff["before_count"], 3)
        self.assertEqual(same_diff["after_count"], 3)

        # Modify evidence file and remove scan lock -> exact diff reported.
        ev_signed.write_bytes(b"sealed-signed-mutated")
        scan_lock.unlink()
        (ev_dir / ("a" * 32 + "-uncertain.enc")).write_bytes(b"new-uncertain")
        after_diff = gates.snapshot_wallet_files(chain)
        diff = gates.compare_file_snapshots(
            before,
            after_diff,
            expected_reasons={scan_lock.name: "lock_removed"},
        )
        self.assertFalse(diff["byte_identical"])
        by_path = {item["path"]: item for item in diff["changed_files"]}
        self.assertEqual(by_path[scan_lock.name]["change_kind"], "removed")
        self.assertEqual(by_path[scan_lock.name]["expected_reason"], "lock_removed")
        self.assertEqual(
            by_path["q06-payment-evidence/" + ev_signed.name]["change_kind"],
            "modified",
        )
        self.assertEqual(
            by_path["q06-payment-evidence/" + "a" * 32 + "-uncertain.enc"]["change_kind"],
            "added",
        )

        # Symlink inside chain dir is refused fail-closed.
        symlink_ev = ev_dir / "bad-link.enc"
        symlink_ev.symlink_to(ev_signed)
        with self.assertRaisesRegex(ValueError, "DQUIT1_GATE_SYMLINK_DENIED"):
            gates.snapshot_wallet_files(chain)

    def test_receipt_validators_enforce_invariants(self):
        self.assertTrue(gates.validate_crash_receipt(_valid_crash_receipt()))
        for mutate in (
            lambda r: r.update(accepted=True),
            lambda r: r.update(source_unchanged=False),
            lambda r: r["cases"].pop("R-n2-ACK"),
            lambda r: r["cases"]["R-n1-Q06"].update(observed_returncode=0),
            lambda r: r["cases"]["R-n2-Q05"].update(assertions={"ok": False}),
        ):
            bad = _valid_crash_receipt()
            mutate(bad)
            self.assertFalse(gates.validate_crash_receipt(bad))

        self.assertTrue(gates.validate_t1_receipt(_valid_t1_receipt()))
        for mutate in (
            lambda r: r.update(accepted=True),
            lambda r: r.update(samples=_valid_t1_samples(9)),
            lambda r: r["summary"].update(all_samples_fit_budget=False),
            lambda r: r["summary"].update(all_orphan_free=False),
            lambda r: r["summary"].update(max_reply_to_exit_s=25.0),
        ):
            bad = _valid_t1_receipt()
            mutate(bad)
            self.assertFalse(gates.validate_t1_receipt(bad))

        self.assertTrue(gates.validate_t2_receipt(_valid_t2_receipt()))
        for mutate in (
            lambda r: r.update(mainnet_allowed=True),
            lambda r: r["scenarios"].pop("F3-14/crypto-failure"),
            lambda r: r["scenarios"]["F3-14/crypto-failure"].update(quit_count=2),
            lambda r: r["scenarios"]["F3-14/crypto-failure"].update(wsp_sqlite_file_count=0),
            lambda r: r["scenarios"]["F3-14/crypto-failure"]["across_stop"].update(byte_identical=False),
            lambda r: r["scenarios"]["F3-14/lost-send-response"].update(payment_evidence_file_count=1),
        ):
            bad = _valid_t2_receipt()
            mutate(bad)
            self.assertFalse(gates.validate_t2_receipt(bad))

    def test_cli_scope_guards_and_apfs_check(self):
        checkout = Path(__file__).resolve().parents[1]
        with self.assertRaisesRegex(SystemExit, "DQUIT1_GATE_CONSENT_REQUIRED"):
            gates.main(["--mode", "crash", "--output", str(self.root / "out1")])
        with self.assertRaisesRegex(SystemExit, "DQUIT1_GATE_EXTERNAL_OUTPUT_REQUIRED"):
            gates.main([
                "--mode", "crash",
                "--output", str(checkout / "bad-out"),
                "--confirm-disposable-regtest",
            ])
        with self.assertRaisesRegex(SystemExit, "DQUIT1_GATE_CORE_INPUTS_REQUIRED"):
            gates.main([
                "--mode", "t1",
                "--output", str(self.root / "out2"),
                "--confirm-disposable-regtest",
            ])
        with self.assertRaisesRegex(SystemExit, "DQUIT1_GATE_T1_MIN_SAMPLES_REQUIRED"):
            gates.main([
                "--mode", "t1",
                "--t1-samples", "9",
                "--output", str(self.root / "out3"),
                "--confirm-disposable-regtest",
            ])
        with patch.object(sys, "frozen", True, create=True):
            with self.assertRaisesRegex(SystemExit, "DQUIT1_GATE_SOURCE_ONLY_DENIED"):
                gates.main([
                    "--mode", "crash",
                    "--output", str(self.root / "out4"),
                    "--confirm-disposable-regtest",
                ])
        if sys.platform == "darwin":
            self.assertEqual(gates.require_apfs_filesystem(self.root), "apfs")


if __name__ == "__main__":
    unittest.main()
