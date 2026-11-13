"""Pure FEE-3 evidence/oracle tests. No daemon, profile or native anchor."""
from decimal import Decimal, localcontext
import json
from pathlib import Path
import tempfile
import unittest

from wam_regtest.qualification.fee_regtest import (
    FIXTURES, assertions_pass, assert_tma, json_capture, write_artifact,
    proposal_trace_holds, aggregate_status, exact_atoms,
    required_assertions, valid_pass_result,
)
from wam_regtest.qualification.fee_regtest_runner import plain, quote_checks
from types import SimpleNamespace


class Evidence(unittest.TestCase):
    def passing_result(self):
        fixture = FIXTURES[0]
        return {
            "fixture": fixture.name, "case_id": fixture.case, "schema": "wam-fee3-source/v1",
            "status": "PASS", "test_layer": "REAL_CORE", "network": "regtest",
            "mainnet_allowed": False, "exit_code": 0,
            "started_utc": "2026-11-13T00:00:00+00:00", "ended_utc": "2026-11-13T00:00:01+00:00",
            "command": ["python", "qualification"], "source": {
                "sha": "a"*40, "tree": "b"*40, "inventory_sha256": "c"*64, "dirty_inventory": []},
            "core": {"signature_verified_now": True, "archive_sha256": "d"*64,
                     "members": {"wamd": "e"*64, "wam-cli": "f"*64}},
            "core_runtime": {"version": 113, "peers": 0, "genesis": "a"*64, "chain": "regtest"},
            "os": {"qt_platform": "cocoa", "arch": "arm64"},
            "wsp_source_commit": "ac55f13423620252bdbf848c7e8a280c3b84721e",
            "safe_startup_flags": [], "profile_fixture_id": "b"*64,
            "baseline": {"quote": {"floor_atoms_per_kvb": 1000}},
            "assertions": {key: True for key in required_assertions(fixture)},
            "cleanup": {"verified_original_owner_shutdown": True, "profile_retained": True},
            "artifacts": {key: "c"*64 for key in ("policy.json", "events.json", "tma.json")},
        }

    def test_pass_contract_requires_all_evidence_and_assertions(self):
        self.assertTrue(valid_pass_result(self.passing_result()))
        for key in self.passing_result():
            result = self.passing_result()
            del result[key]
            self.assertFalse(valid_pass_result(result), key)
        result = self.passing_result()
        result["assertions"].pop(next(iter(result["assertions"])))
        self.assertFalse(valid_pass_result(result))
        result = self.passing_result()
        result["cleanup"]["verified_original_owner_shutdown"] = False
        self.assertFalse(valid_pass_result(result))
        result = self.passing_result()
        result["core"]["archive_sha256"] = "abcd"
        self.assertFalse(valid_pass_result(result))

    def test_executor_container_copy_does_not_mutate_original(self):
        from wam_regtest.wallet_executor import immutable
        frozen = immutable({"coins": [1, 2], "nested": {"ok": True}})
        copied = plain(frozen)
        self.assertEqual(copied, {"coins": [1, 2], "nested": {"ok": True}})
        copied["coins"].append(3)
        self.assertEqual(frozen["coins"], (1, 2))

    def test_original_number_types_and_decimal_lexemes_survive(self):
        capture = json_capture([{"allowed": True, "vsize": 155,
                                 "fees": {"base": Decimal("0.000001550")}}])
        self.assertEqual(capture["schema"], [{"allowed": "boolean", "vsize": "integer",
                                             "fees": {"base": "number"}}])
        self.assertEqual(capture["decimals"], {"/0/fees/base": "0.000001550"})
        self.assertEqual(len(capture["sha256"]), 64)

    def test_unknown_rpc_fields_cannot_leak_secret_text(self):
        self.assertNotIn("secret words here", json.dumps(json_capture({"unknown": "secret words here"})))
        for value in ({"password": "secret"},
                      {"raw": b"secret"}, {"number": float("nan")}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                json_capture(value)

    def test_artifacts_are_create_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "result.json"
            digest = write_artifact(path, {"status": "BLOCKED"})
            self.assertEqual(len(digest), 64)
            with self.assertRaises(FileExistsError):
                write_artifact(path, {"status": "PASS"})
            self.assertEqual(json.loads(path.read_text())["status"], "BLOCKED")

    def test_missing_empty_or_nonboolean_assertions_never_pass(self):
        for checks in ({}, {"a": 1}, {"a": None}, {"a": False}):
            self.assertFalse(assertions_pass(checks))
        self.assertTrue(assertions_pass({"a": True}))
        self.assertEqual(aggregate_status({}), "BLOCKED")
        complete = {fixture.name: "PASS" for fixture in FIXTURES}
        self.assertEqual(aggregate_status(complete), "PASS")
        complete.pop(next(iter(complete)))
        self.assertEqual(aggregate_status(complete), "BLOCKED")
        complete["unrecognized"] = "PASS"
        self.assertEqual(aggregate_status(complete), "BLOCKED")

    def test_exact_atoms_independent_of_decimal_precision(self):
        with localcontext() as ctx:
            ctx.prec = 2
            self.assertEqual(exact_atoms(Decimal("0.00000155")), 155)
        for value in (True, "0.00000155", 0.00000155, Decimal("0.000000001")):
            with self.assertRaises(ValueError):
                exact_atoms(value)


class Oracles(unittest.TestCase):
    def test_quote_oracle_detects_floor_arithmetic_and_structure_mismatches(self):
        review = SimpleNamespace(
            fee_quote=SimpleNamespace(estimator="UNAVAILABLE", source="NETWORK_FLOOR",
                rate_atoms_per_kvb=1000, floor_atoms_per_kvb=1000),
            vsize=155, rate_atoms_per_kvb=1000, available_after=0, input_count=1,
            atoms=100_000, fee=155, overpay_atoms=0, change_atoms=899_845,
            available_before=1_000_000, total_debit=100_155)
        observations = {"proposals": [155], "releases": [], "policy": [
            {"method": "getnetworkinfo", "result": json_capture({"relayfee": Decimal("0.00001000")})},
            {"method": "getmempoolinfo", "result": json_capture({"mempoolminfee": Decimal("0.00001000"),
                                                              "minrelaytxfee": Decimal("0.00001000")})},
            *[{"method": "estimatesmartfee", "result": json_capture({"errors": ["Insufficient data"]})}]*3,
        ]}
        self.assertTrue(assertions_pass(quote_checks(review, FIXTURES[0], observations)))
        review.change_atoms -= 1
        self.assertFalse(assertions_pass(quote_checks(review, FIXTURES[0], observations)))

    def response(self):
        return [{"allowed": True, "txid": "a" * 64, "wtxid": "b" * 64,
                 "vsize": 155, "fees": {"base": Decimal("0.00000155"),
                   "effective-feerate": Decimal("0.00001000"),
                   "effective-includes": ["b" * 64]}}]

    def test_tma_requires_every_identity_and_amount_field(self):
        response = self.response()
        self.assertTrue(assertions_pass(assert_tma(response, 155, 155, "a"*64, "b"*64)))
        for key, bad in (("allowed", 1), ("vsize", True), ("txid", "c"*64),
                         ("wtxid", "c"*64), ("fees", {"base": "0.00000155"})):
            changed = self.response()
            changed[0][key] = bad
            self.assertFalse(assertions_pass(assert_tma(changed, 155, 155, "a"*64, "b"*64)))
        self.assertFalse(assertions_pass(assert_tma([], 155, 155, "a"*64, "b"*64)))

    def test_bounded_downward_attempt_matches_reviewed_fee2(self):
        for trace in ([155], [155, 270], [155, 112, 155], [155, 112]):
            self.assertTrue(proposal_trace_holds(trace))
        for trace in ([], [True], [155]*7, [155, 112, 100], [155, 112, 156],
                      [155, 200, 150, 200, 140]):
            self.assertFalse(proposal_trace_holds(trace))


if __name__ == "__main__":
    unittest.main()
