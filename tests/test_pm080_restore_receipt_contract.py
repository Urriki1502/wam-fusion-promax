"""PM-080 PROBE-FLAG-01: probe reservation predicate and consumer receipt contracts."""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import textwrap
import unittest
from unittest.mock import patch

from wam_regtest import q06_same_chain_restore_probe as restore_probe
from wam_regtest import q06_spend_probe as spend_probe
from wam_regtest.wallet_executor import WalletExecutorError

ROOT = Path(__file__).resolve().parents[1]
_SENTINEL = object()


def _valid_nested_restore():
    return {
        "status": "FRESH_PROFILE_SAME_CHAIN_HISTORY_RESTORE_PASS",
        "all_original_owners_shutdown_verified": True,
        "mnemonic_does_not_restore_signed_reservations": True,
        "uncertain_fixture": restore_probe.UNCERTAIN_FIXTURE_STATUS,
    }


def _valid_spend_receipt():
    return {
        "status": "Q06_NATIVE_BIP39_SEND_CONFIRM_REOPEN_PASS",
        "mainnet_allowed": False,
        "q06_bip39_spend_confirmed": True,
        "q06_bip39_same_owner_reopen_reserved": True,
        "q06_bip39_same_chain_seed_history_recovery": True,
        "fresh_same_chain_profile_full_history_recovered": True,
        "q06_post_reopen_txid_readonly_reconciliation": True,
        "q06_bip39_fresh_mnemonic_full_history_recovery": False,
        "source_sha": "a" * 40,
        "fresh_profile_same_chain_history": _valid_nested_restore(),
    }


def _extract_bundle_receipt_check():
    text = (ROOT / "scripts/build_macos_bundle.sh").read_text()
    match = re.search(
        r"# PM-080-SPEND-RECEIPT-CHECK-START\n(.*?)\n[ \t]*# PM-080-SPEND-RECEIPT-CHECK-END",
        text,
        re.S,
    )
    if match is None:
        raise AssertionError("missing PM-080-SPEND-RECEIPT-CHECK markers in build_macos_bundle.sh")
    return textwrap.dedent(match.group(1))


class SpendProbeConsumerContractTests(unittest.TestCase):
    def _run_with_nested(self, nested_value):
        base_receipt = _valid_spend_receipt()
        base_receipt.pop("fresh_profile_same_chain_history", None)
        base_receipt["fresh_same_chain_profile_full_history_recovered"] = False
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = Path.cwd()
            os.chdir(tmp)
            try:
                with (
                    patch.object(spend_probe, "qualify", return_value=dict(base_receipt)),
                    patch.object(
                        restore_probe,
                        "qualify",
                        return_value=nested_value,
                    ),
                    patch.object(
                        spend_probe,
                        "_qualify_recovered_unsigned_cancel",
                        return_value={"status": "PASS", "owner_shutdown_verified": True},
                    ),
                    patch("wam_regtest.q05_platforms.DarwinArm64Adapter", return_value=SimpleNamespace()),
                ):
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout):
                        rc = spend_probe.run(Path("/tmp/core"), Path("/tmp/wsp"))
                evidence_exists = (Path(tmp) / "q06-frozen-spend-evidence.json").exists()
                return rc, stdout.getvalue(), evidence_exists
            finally:
                os.chdir(old_cwd)

    def test_accepts_strict_true_nested_claim(self):
        rc, out, evidence_exists = self._run_with_nested(_valid_nested_restore())
        self.assertEqual(rc, 0)
        self.assertEqual(out, "MACOS_Q06_NATIVE_BIP39_SEND_CONFIRM_REOPEN_PASS\n")
        self.assertTrue(evidence_exists)

    def test_refuses_missing_false_string_and_int_nested_claim(self):
        cases = (
            ("missing", _SENTINEL),
            ("false", False),
            ("string-true", "true"),
            ("int-1", 1),
        )
        for label, value in cases:
            with self.subTest(label=label):
                nested = _valid_nested_restore()
                if value is _SENTINEL:
                    nested.pop("mnemonic_does_not_restore_signed_reservations")
                else:
                    nested["mnemonic_does_not_restore_signed_reservations"] = value
                rc, out, evidence_exists = self._run_with_nested(nested)
                self.assertEqual(rc, 2)
                self.assertEqual(
                    out,
                    "MACOS_Q06_NATIVE_BIP39_SEND_CONFIRM_REOPEN_DENIED "
                    "code=Q06_MAC_FRESH_SAME_CHAIN_RESTORE_DENIED\n",
                )
                self.assertFalse(evidence_exists)

    def test_refuses_missing_or_non_dict_nested_object(self):
        for value in (None, [], "true", 1):
            with self.subTest(value=value):
                rc, out, evidence_exists = self._run_with_nested(value)
                self.assertEqual(rc, 2)
                self.assertIn("code=Q06_MAC_FRESH_SAME_CHAIN_RESTORE_DENIED", out)
                self.assertFalse(evidence_exists)

    def test_validate_restore_reservation_claim_strict_boolean(self):
        spend_probe.validate_restore_reservation_claim(_valid_nested_restore())
        for valid_exc in (None, "BrokenPipeError", "_Custom_1", "A" * 64):
            nested = _valid_nested_restore()
            nested["failure_exception"] = valid_exc
            spend_probe.validate_restore_reservation_claim(nested)
        for bad in (_SENTINEL, False, "true", 1, None):
            nested = _valid_nested_restore()
            if bad is _SENTINEL:
                nested.pop("mnemonic_does_not_restore_signed_reservations")
            else:
                nested["mnemonic_does_not_restore_signed_reservations"] = bad
            with self.assertRaisesRegex(ValueError, "^Q06_MAC_FRESH_SAME_CHAIN_RESTORE_DENIED$"):
                spend_probe.validate_restore_reservation_claim(nested)
        for bad_exc in ("/tmp/secret", "1BadName", "A" * 65, "BrokenPipeError\n", "", 123, True):
            nested = _valid_nested_restore()
            nested["failure_exception"] = bad_exc
            with self.assertRaisesRegex(ValueError, "^Q06_MAC_FRESH_SAME_CHAIN_RESTORE_DENIED$"):
                spend_probe.validate_restore_reservation_claim(nested)


class MacosBundleConsumerContractTests(unittest.TestCase):
    def _run_bundle_check_via_bash(self, receipt_payload):
        snippet = _extract_bundle_receipt_check()
        compile(snippet, "build_macos_bundle.sh PM-080 check", "exec")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clean = root / "clean"
            out = root / "out"
            clean.mkdir()
            out.mkdir()
            (clean / "q06-frozen-spend-evidence.json").write_text(json.dumps(receipt_payload))
            script = (
                "set -euo pipefail\n"
                f'"{sys.executable}" -I - <<\'PY\'\n'
                "import shutil\n"
                "from json import loads\n"
                "from pathlib import Path\n"
                f"clean = {str(clean)!r}\n"
                f"out = Path({str(out)!r})\n"
                f"{textwrap.indent(snippet, '')}\n"
                "PY\n"
            )
            proc = subprocess.run(
                ["bash", "-c", script],
                capture_output=True,
                text=True,
                timeout=30,
            )
            published = (out / "q06-frozen-spend-evidence.json").exists()
            return proc.returncode, proc.stderr, published

    def test_bundle_builder_accepts_strict_true_and_publishes_receipt(self):
        rc, stderr, published = self._run_bundle_check_via_bash(_valid_spend_receipt())
        self.assertEqual(rc, 0, stderr)
        self.assertTrue(published)

    def test_bundle_builder_refuses_missing_false_string_and_int_nested_claim(self):
        cases = (
            ("missing", _SENTINEL),
            ("false", False),
            ("string-true", "true"),
            ("int-1", 1),
        )
        for label, value in cases:
            with self.subTest(label=label):
                payload = _valid_spend_receipt()
                nested = payload["fresh_profile_same_chain_history"]
                if value is _SENTINEL:
                    nested.pop("mnemonic_does_not_restore_signed_reservations")
                else:
                    nested["mnemonic_does_not_restore_signed_reservations"] = value
                rc, _, published = self._run_bundle_check_via_bash(payload)
                self.assertNotEqual(rc, 0)
                self.assertFalse(published)

    def test_bundle_builder_refuses_missing_nested_section_or_bad_outer_flag(self):
        missing_nested = _valid_spend_receipt()
        missing_nested.pop("fresh_profile_same_chain_history")
        rc, _, published = self._run_bundle_check_via_bash(missing_nested)
        self.assertNotEqual(rc, 0)
        self.assertFalse(published)

        bad_outer = _valid_spend_receipt()
        bad_outer["q06_bip39_spend_confirmed"] = False
        rc, _, published = self._run_bundle_check_via_bash(bad_outer)
        self.assertNotEqual(rc, 0)
        self.assertFalse(published)

    def test_bundle_builder_accepts_null_or_valid_failure_exception_and_rejects_bad(self):
        for valid_exc in (None, "BrokenPipeError", "_Custom_1"):
            payload = _valid_spend_receipt()
            payload["failure_exception"] = valid_exc
            payload["fresh_profile_same_chain_history"]["failure_exception"] = valid_exc
            rc, stderr, published = self._run_bundle_check_via_bash(payload)
            self.assertEqual(rc, 0, stderr)
            self.assertTrue(published)
        for target_nested in (False, True):
            for bad_exc in ("/tmp/secret", "1Bad", "A" * 65, 123):
                payload = _valid_spend_receipt()
                if target_nested:
                    payload["fresh_profile_same_chain_history"]["failure_exception"] = bad_exc
                else:
                    payload["failure_exception"] = bad_exc
                rc, _, published = self._run_bundle_check_via_bash(payload)
                self.assertNotEqual(rc, 0)
                self.assertFalse(published)


class RestoreProbePredicateTests(unittest.TestCase):
    def _sample_maps(self):
        broadcast_coin = ("aa" * 32, 0)
        signed_coin = ("bb" * 32, 1)
        signed_token = "11" * 16
        broadcast_token = "22" * 16
        before_map = {
            broadcast_coin: (broadcast_token, "broadcast", 100),
            signed_coin: (signed_token, "signed", 200),
        }
        intents = [
            {
                "token": signed_token,
                "state": "signed",
                "classification": "SIGNED_NOT_SUBMITTED_RESUMABLE",
                "txid": "cc" * 32,
            }
        ]
        return before_map, (signed_coin,), signed_token, intents

    def test_verify_contract_accepts_valid_maps_and_signed_fixture(self):
        before_map, signed_outpoints, signed_token, intents = self._sample_maps()
        restore_probe.verify_restore_reservation_contract(
            before_original_map=before_map,
            after_original_map=dict(before_map),
            restored_map={},
            signed_outpoints=signed_outpoints,
            signed_token=signed_token,
            before_intents=intents,
            after_intents=list(intents),
        )

    def test_verify_contract_rejects_non_empty_restored_map(self):
        before_map, signed_outpoints, signed_token, intents = self._sample_maps()
        with self.assertRaisesRegex(ValueError, "^Q06_SAME_CHAIN_RESTORE_RESERVATION_DENIED$"):
            restore_probe.verify_restore_reservation_contract(
                before_original_map=before_map,
                after_original_map=dict(before_map),
                restored_map={signed_outpoints[0]: (signed_token, "signed", 200)},
                signed_outpoints=signed_outpoints,
                signed_token=signed_token,
                before_intents=intents,
                after_intents=list(intents),
            )

    def test_verify_contract_rejects_changed_original_map(self):
        before_map, signed_outpoints, signed_token, intents = self._sample_maps()
        mutations = (
            {},
            {k: v for k, v in before_map.items() if v[1] != "signed"},
            {
                **before_map,
                signed_outpoints[0]: (signed_token, "broadcast", 200),
            },
            {
                **before_map,
                signed_outpoints[0]: ("ff" * 16, "signed", 200),
            },
            {
                **before_map,
                ("dd" * 32, 0): ("ee" * 16, "draft", 300),
            },
        )
        for mutated in mutations:
            with self.subTest(mutated=mutated):
                with self.assertRaisesRegex(ValueError, "^Q06_SAME_CHAIN_RESTORE_RESERVATION_DENIED$"):
                    restore_probe.verify_restore_reservation_contract(
                        before_original_map=before_map,
                        after_original_map=mutated,
                        restored_map={},
                        signed_outpoints=signed_outpoints,
                        signed_token=signed_token,
                        before_intents=intents,
                        after_intents=list(intents),
                    )

    def test_verify_contract_rejects_missing_signed_fixture(self):
        before_map, signed_outpoints, signed_token, intents = self._sample_maps()
        only_broadcast = {k: v for k, v in before_map.items() if v[1] == "broadcast"}
        with self.assertRaisesRegex(ValueError, "^Q06_SAME_CHAIN_RESTORE_RESERVATION_DENIED$"):
            restore_probe.verify_restore_reservation_contract(
                before_original_map=only_broadcast,
                after_original_map=dict(only_broadcast),
                restored_map={},
                signed_outpoints=signed_outpoints,
                signed_token=signed_token,
                before_intents=intents,
                after_intents=list(intents),
            )
        with self.assertRaisesRegex(ValueError, "^Q06_SAME_CHAIN_RESTORE_RESERVATION_DENIED$"):
            restore_probe.verify_restore_reservation_contract(
                before_original_map=before_map,
                after_original_map=dict(before_map),
                restored_map={},
                signed_outpoints=signed_outpoints,
                signed_token=signed_token,
                before_intents=[],
                after_intents=[],
            )

    def test_rows_to_reservation_map_accepts_sqlite_row_factory(self):
        before_map, signed_outpoints, signed_token, intents = self._sample_maps()
        conn = sqlite3.connect(":memory:")
        try:
            conn.row_factory = sqlite3.Row
            conn.execute(
                "CREATE TABLE reservations("
                "txid TEXT, vout INTEGER, token TEXT, state TEXT, created INTEGER, "
                "PRIMARY KEY(txid, vout))"
            )
            for (txid, vout), (token, state, created) in before_map.items():
                conn.execute(
                    "INSERT INTO reservations VALUES(?,?,?,?,?)",
                    (txid, vout, token, state, created),
                )
            rows = conn.execute(
                "SELECT txid,vout,token,state,created FROM reservations ORDER BY txid,vout"
            ).fetchall()
            self.assertEqual(len(rows), 2)
            self.assertIs(type(rows[0]), sqlite3.Row)
            parsed = restore_probe._rows_to_reservation_map(rows)
            self.assertEqual(parsed, before_map)
            restore_probe.verify_restore_reservation_contract(
                before_original_map=parsed,
                after_original_map=restore_probe._rows_to_reservation_map(rows),
                restored_map=restore_probe._rows_to_reservation_map([]),
                signed_outpoints=signed_outpoints,
                signed_token=signed_token,
                before_intents=intents,
                after_intents=list(intents),
            )
            short_rows = conn.execute(
                "SELECT txid,vout,token,state FROM reservations ORDER BY txid,vout"
            ).fetchall()
            with self.assertRaisesRegex(ValueError, "^Q06_SAME_CHAIN_RESTORE_RESERVATION_DENIED$"):
                restore_probe._rows_to_reservation_map(short_rows)
        finally:
            conn.close()
        with self.assertRaisesRegex(ValueError, "^Q06_SAME_CHAIN_RESTORE_RESERVATION_DENIED$"):
            restore_probe._rows_to_reservation_map([{"txid": "aa" * 32}])


class FakeRestoreProbeFlowTests(unittest.TestCase):
    def _drive_probe(
        self,
        *,
        restore_backup_status="verified",
        restored_map_override=None,
        after_original_map_override=None,
        drop_signed_fixture=False,
        reopen_map_override=None,
    ):
        phrase = " ".join(["abandon"] * 11 + ["about"])
        receive_code = "wamrtsp1fake"
        account_id = "acct-1"
        confirmed_txid = "10" * 32
        signed_txid = "20" * 32
        tip_hash = "30" * 32
        broadcast_coin = ("01" * 32, 0)
        signed_coin = ("02" * 32, 1)
        broadcast_token = "aa" * 16
        signed_token = "bb" * 16
        challenge_calls = []

        class FakeWorker:
            def __init__(self, index):
                self.index = index
                self.closed = False
                self.busy = False
                self.mode = None
                self.tip = tip_hash
                self.reservations = {}
                self.signed_commitment = None
                self.snapshot_calls = 0
                self.active_challenge = None

            def join(self, timeout=15):
                return True

            def request(self, action, *args, timeout=90):
                if action == "open":
                    _, mode, _ = args
                    self.mode = mode
                    if mode == "restore":
                        self.tip = tip_hash
                        status = restore_backup_status
                    elif mode == "reopen":
                        status = "verified"
                    else:
                        status = "required"
                    return {
                        "receive_code": receive_code,
                        "account_id": account_id,
                        "mnemonic_once": phrase if mode == "create" else "",
                        "seed_folder": "/tmp/seed",
                        "signer_allowed": False,
                        "backup_status": status,
                    }
                if action == "acknowledge_create_pending":
                    return None
                if action == "backup_challenge":
                    cid = "c" * 64
                    self.active_challenge = cid
                    challenge_calls.append((self.index, self.mode))
                    return {"challenge_id": cid, "positions": (1, 2, 3)}
                if action == "backup_verify":
                    cid, answers = args
                    if cid == "wrong":
                        raise WalletExecutorError("Q06_GUI_BACKUP_CHALLENGE_INVALID")
                    if cid != self.active_challenge:
                        raise WalletExecutorError("Q06_GUI_BACKUP_CHALLENGE_STALE")
                    if tuple(answers) == ("wrong", "wrong", "wrong"):
                        self.active_challenge = None
                        return False
                    if len(answers) != 3:
                        self.active_challenge = None
                        raise WalletExecutorError("Q06_GUI_BACKUP_VERIFY_INPUT_DENIED")
                    self.active_challenge = None
                    return True
                if action == "backup_challenge_cancel":
                    self.active_challenge = None
                    return None
                if action == "lock":
                    self.active_challenge = None
                    return None
                if action == "network_status":
                    return {
                        "connected": True,
                        "peers": [{"subver": "/WAM:0.1.13/", "version": 70016}],
                        "tip": self.tip,
                    }
                if action == "mine":
                    if self.index != 0:
                        raise WalletExecutorError("SHARED_SINGLE_COORDINATOR_REQUIRED")
                    return {"atoms": 5_000_000_000}
                if action == "activate":
                    return {"signer_allowed": True}
                if action == "prepare":
                    _, atoms, _ = args
                    commit = "d1" * 32 if atoms == 50_000 else "d2" * 32
                    return SimpleNamespace(commitment=commit)
                if action == "sign":
                    commit = args[0]
                    if commit == "d1" * 32:
                        self.reservations[broadcast_coin] = (broadcast_token, "signed", 10)
                    else:
                        if not drop_signed_fixture:
                            self.reservations[signed_coin] = (signed_token, "signed", 20)
                        self.signed_commitment = commit
                    return SimpleNamespace(commitment=commit)
                if action == "broadcast":
                    self.reservations[broadcast_coin] = (broadcast_token, "broadcast", 10)
                    return confirmed_txid
                if action == "confirm":
                    return {"txid": confirmed_txid}
                if action == "intent_status":
                    items = []
                    for entry in self.reservations.values():
                        if entry[1] == "signed":
                            items.append({
                                "token": entry[0],
                                "state": "signed",
                                "classification": "SIGNED_NOT_SUBMITTED_RESUMABLE",
                                "txid": signed_txid,
                            })
                    return {"status": "Q06_SIGNED_INTENT_STATUS", "intents": items}
                if action == "snapshot":
                    self.snapshot_calls += 1
                    res_map = dict(self.reservations)
                    if self.index == 0 and self.snapshot_calls >= 3 and after_original_map_override is not None:
                        res_map = dict(after_original_map_override)
                    if self.index == 2 and self.mode == "restore" and restored_map_override is not None:
                        res_map = dict(restored_map_override)
                    if self.index == 2 and self.mode == "reopen" and reopen_map_override is not None:
                        res_map = dict(reopen_map_override)
                    return {
                        "height": 103,
                        "tip": tip_hash,
                        "receive_code": receive_code,
                        "confirmed_atoms": 4_999_949_000,
                        "available_atoms": 0 if self.index == 0 and self.signed_commitment else 4_999_949_000,
                        "history_count_shown": 2,
                        "history": ({"txid": "00" * 32}, {"txid": confirmed_txid}),
                        "reservation_count": len(res_map),
                        "payment_signed": self.signed_commitment is not None,
                        "signer_allowed": self.index == 0,
                        "reservation_map": res_map,
                    }
                if action == "quit":
                    self.closed = True
                    return None
                raise AssertionError(f"unexpected action {action}")

        created_indices = []
        def make_executor(factory):
            idx = len(created_indices)
            if idx >= 3:
                idx = 2
            created_indices.append(idx)
            return FakeWorker(idx)

        fake_adapter = SimpleNamespace(
            platform_id="macos-arm64",
            make_anchor=lambda root: None,
            reopen_anchor=lambda root: None,
        )
        fake_payee = SimpleNamespace(public_metadata=lambda: {"receive_code": "wamrtsp1payee"})
        fake_payee_ctx = contextlib.nullcontext(fake_payee)

        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            parent.chmod(0o700)
            with (
                patch.object(restore_probe, "WalletExecutor", side_effect=make_executor),
                patch("wam_regtest.bip39_12.Bip39Regtest12Keys", return_value=fake_payee_ctx),
                patch("wam_regtest.shared_regtest.reserve_ports", return_value=contextlib.nullcontext()),
            ):
                report = restore_probe.qualify(
                    Path("/tmp/core"),
                    Path("/tmp/wsp"),
                    parent,
                    fake_adapter,
                )
        return report, challenge_calls

    def test_qualify_passes_for_verified_and_deferred_restore_statuses(self):
        for status, expect_restore_challenge in (("verified", False), ("deferred", True)):
            with self.subTest(restore_backup_status=status):
                report, challenges = self._drive_probe(restore_backup_status=status)
                self.assertEqual(report["status"], "FRESH_PROFILE_SAME_CHAIN_HISTORY_RESTORE_PASS")
                self.assertIs(report["mnemonic_does_not_restore_signed_reservations"], True)
                self.assertIs(report["signed_unsubmitted_fixture_verified"], True)
                self.assertTrue(report["uncertain_fixture"].startswith("UNREACHABLE: "))
                self.assertNotIn("PASS", report["uncertain_fixture"])
                restore_challenges = [c for c in challenges if c == (2, "restore")]
                self.assertEqual(bool(restore_challenges), expect_restore_challenge)

    def test_qualify_fails_on_non_empty_restored_map(self):
        report, _ = self._drive_probe(
            restored_map_override={("02" * 32, 1): ("bb" * 16, "signed", 20)},
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_code"], "Q06_SAME_CHAIN_RESTORE_RESERVATION_DENIED")
        self.assertIs(report["mnemonic_does_not_restore_signed_reservations"], False)

    def test_qualify_fails_on_changed_original_map(self):
        report, _ = self._drive_probe(
            after_original_map_override={
                ("01" * 32, 0): ("aa" * 16, "broadcast", 10),
                ("02" * 32, 1): ("bb" * 16, "broadcast", 20),
            },
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_code"], "Q06_SAME_CHAIN_RESTORE_RESERVATION_DENIED")
        self.assertIs(report["mnemonic_does_not_restore_signed_reservations"], False)

    def test_qualify_fails_on_missing_signed_fixture(self):
        report, _ = self._drive_probe(drop_signed_fixture=True)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_code"], "Q06_SAME_CHAIN_RESTORE_RESERVATION_DENIED")
        self.assertIs(report["mnemonic_does_not_restore_signed_reservations"], False)

    def test_qualify_fails_on_non_empty_reopen_map(self):
        report, _ = self._drive_probe(
            reopen_map_override={("02" * 32, 1): ("bb" * 16, "signed", 20)},
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_code"], "Q06_SAME_CHAIN_RESTORE_RESERVATION_DENIED")
        self.assertNotIn("failure_exception", report)
        self.assertIs(report["mnemonic_does_not_restore_signed_reservations"], False)

    def test_qualify_generic_fallback_records_class_name_without_message_or_secret(self):
        secret_msg = "/Users/alice/.wam/secret-mnemonic-word-abandon"
        fake_adapter = SimpleNamespace(
            platform_id="macos-arm64",
            make_anchor=lambda root: None,
            reopen_anchor=lambda root: None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            parent.chmod(0o700)
            with (
                patch.object(
                    restore_probe,
                    "WalletExecutor",
                    side_effect=BrokenPipeError(32, secret_msg),
                ),
                patch("wam_regtest.shared_regtest.reserve_ports", return_value=contextlib.nullcontext()),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                report = restore_probe.qualify(
                    Path("/tmp/core"),
                    Path("/tmp/wsp"),
                    parent,
                    fake_adapter,
                )
            evidence_files = list(parent.glob("*/public-evidence.json"))
            self.assertEqual(len(evidence_files), 1)
            written = evidence_files[0].read_text()
            loaded = json.loads(written)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_code"], "Q06_SAME_CHAIN_RESTORE_DENIED")
        self.assertEqual(report["failure_exception"], "BrokenPipeError")
        self.assertEqual(loaded["failure_exception"], "BrokenPipeError")
        self.assertNotIn("secret-mnemonic-word-abandon", written)
        self.assertNotIn("/Users/alice", written)
        self.assertNotIn("Broken pipe", written)

    def test_qualify_specific_code_omits_failure_exception(self):
        fake_adapter = SimpleNamespace(
            platform_id="macos-arm64",
            make_anchor=lambda root: None,
            reopen_anchor=lambda root: None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            parent.chmod(0o700)
            with (
                patch.object(
                    restore_probe,
                    "WalletExecutor",
                    side_effect=WalletExecutorError("Q06_SPECIFIC_TEST_CODE"),
                ),
                patch("wam_regtest.shared_regtest.reserve_ports", return_value=contextlib.nullcontext()),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                report = restore_probe.qualify(
                    Path("/tmp/core"),
                    Path("/tmp/wsp"),
                    parent,
                    fake_adapter,
                )
            evidence_files = list(parent.glob("*/public-evidence.json"))
            self.assertEqual(len(evidence_files), 1)
            loaded = json.loads(evidence_files[0].read_text())
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_code"], "Q06_SPECIFIC_TEST_CODE")
        self.assertNotIn("failure_exception", report)
        self.assertNotIn("failure_exception", loaded)


if __name__ == "__main__":
    unittest.main()
