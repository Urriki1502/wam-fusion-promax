"""Pure FEE-3 evidence/oracle tests. No daemon, profile or native anchor."""
import copy
from decimal import Decimal, localcontext
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wam_regtest.qualification.fee_regtest import (
    CHARACTERIZATION_PENDING_STATUS, FIXTURES, OUTSIDE_STEP,
    TMA_FLOAT_CONVERSION_NOTE, aggregate_status, assertions_pass, assert_tma,
    confirmed_debit_holds, exact_atoms, json_capture, proposal_trace_holds,
    reopen_clean_holds, required_assertions, sign_order_holds, tma_capture,
    valid_characterization_result, valid_pass_result, write_artifact,
)
from wam_regtest.qualification.fee_regtest_runner import (
    QUALIFICATION_COMMANDS, QualificationFeeExecutor, approve_payment,
    backend_type, no_manual_fee_controls, plain, quote_checks,
    reopen_verified_owner, resolve_actor, run_fixture,
)
from wam_regtest.wallet_executor import COMMANDS, WalletExecutor, WalletExecutorError


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
        for value in (
            {"password": "secret"},
            {"raw": b"secret"},
            {"estimaterawfee": {"short": {"raw": 1}}},
            {"estimaterawfee": {"short": {"seed": "word"}}},
            {"nested": {"SEED": "word"}},
            {"nested": {"Raw": "hex"}},
            {"mnemonic": "words"},
            {"key": "priv"},
            {"psbt": "cHNidP8="},
            {"config": {}},
            {"number": float("nan")},
        ):
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
        complete = {
            fixture.name: (CHARACTERIZATION_PENDING_STATUS if fixture.characterization else "PASS")
            for fixture in FIXTURES
        }
        self.assertEqual(aggregate_status(complete), "PASS")
        bad_pass = dict(complete)
        bad_pass["subdust-sweep-characterization"] = "PASS"
        self.assertEqual(aggregate_status(bad_pass), "BLOCKED")
        complete.pop(next(iter(complete)))
        self.assertEqual(aggregate_status(complete), "BLOCKED")
        complete["unrecognized"] = "PASS"
        self.assertEqual(aggregate_status(complete), "BLOCKED")

    def test_d_fee2_2_characterization_never_reports_pass(self):
        fixture = next(f for f in FIXTURES if f.case == "D-FEE2-2")
        self.assertTrue(fixture.characterization)
        self.assertTrue(fixture.refusal)
        self.assertEqual(fixture.coins, (100_200,))
        self.assertEqual(fixture.amount, 100_000)
        result = self.passing_result()
        result["fixture"] = fixture.name
        result["case_id"] = fixture.case
        result["assertions"] = {key: True for key in required_assertions(fixture)}
        self.assertFalse(valid_pass_result(result))
        self.assertFalse(valid_characterization_result(result))
        result["status"] = CHARACTERIZATION_PENDING_STATUS
        self.assertFalse(valid_pass_result(result))
        self.assertTrue(valid_characterization_result(result))

    def test_f3_01_requires_gui_sign_review_and_cancel_assertions(self):
        f301 = next(f for f in FIXTURES if f.case == "F3-01")
        req = required_assertions(f301)
        self.assertTrue(
            {"gui_sign_review", "gui_sign_cancel_default", "gui_no_manual_fee_field", "unsigned_cancel_releases"}
            <= req
        )

    def test_outside_step_lists_f3_11_through_f3_14_and_contextual_actor(self):
        for case_id in ("F3-07", "F3-08", "F3-09-low-fee", "F3-10", "F3-11", "F3-12", "F3-13", "F3-14",
                        "frozen", "Windows/Linux"):
            self.assertIn(case_id, OUTSIDE_STEP)
            self.assertTrue(OUTSIDE_STEP[case_id].startswith("BLOCKED_"), case_id)
        self.assertIn("UNCONFIRMED_RESTART", OUTSIDE_STEP["F3-12"])
        self.assertIn("CANCEL_BEFORE_SIGN", OUTSIDE_STEP["F3-13"])
        self.assertIn("SIGN_BROADCAST_SAFETY_INVARIANTS", OUTSIDE_STEP["F3-14"])
        with patch.dict(os.environ, {"WAM_QUALIFICATION_ACTOR": "verifier-agent"}, clear=False):
            self.assertEqual(resolve_actor(), "verifier-agent")
            self.assertEqual(resolve_actor("explicit-actor"), "explicit-actor")
            self.assertNotEqual(resolve_actor(), "Cursor")

    def test_exact_atoms_independent_of_decimal_precision(self):
        with localcontext() as ctx:
            ctx.prec = 2
            self.assertEqual(exact_atoms(Decimal("0.00000155")), 155)
        for value in (True, "0.00000155", 0.00000155, Decimal("0.000000001")):
            with self.assertRaises(ValueError):
                exact_atoms(value)


class Oracles(unittest.TestCase):
    def _empty_smart_policy(self, *, blocks=0, reads=1, targets=(2, 6, 25)):
        smart_entries = [
            {
                "method": "estimatesmartfee",
                "target": target,
                "result": json_capture({"errors": ["Insufficient data or no feerate found"], "blocks": blocks}),
            }
            for target in targets
        ]
        one_read = [
            {"method": "getnetworkinfo", "result": json_capture({"relayfee": Decimal("0.00001000")})},
            {"method": "getmempoolinfo", "result": json_capture({"mempoolminfee": Decimal("0.00001000"),
                                                              "minrelaytxfee": Decimal("0.00001000")})},
            *smart_entries,
        ]
        return one_read * reads

    def _prepare_events(self):
        return ["ACTION_PREPARE_AUTO", *(["POLICY_READ"] * 6), "PROPOSE", "SAVE"]

    def _prepare_and_sign_events(self):
        return [
            "ACTION_PREPARE_AUTO", *(["POLICY_READ"] * 6), "PROPOSE", "SAVE",
            "ACTION_SIGN", *(["POLICY_READ"] * 6), "MARK_SIGNED", "SAVE", "SIGN",
        ]

    def test_quote_oracle_detects_floor_arithmetic_and_structure_mismatches(self):
        review = SimpleNamespace(
            fee_quote=SimpleNamespace(estimator="UNAVAILABLE", source="NETWORK_FLOOR",
                rate_atoms_per_kvb=1000, floor_atoms_per_kvb=1000),
            vsize=155, rate_atoms_per_kvb=1000, available_after=0, input_count=1,
            atoms=100_000, fee=155, overpay_atoms=0, change_atoms=899_845,
            available_before=1_000_000, total_debit=100_155)
        observations = {
            "proposals": [155],
            "releases": [],
            "events": self._prepare_events(),
            "policy": self._empty_smart_policy(),
        }
        self.assertTrue(assertions_pass(quote_checks(review, FIXTURES[0], observations)))
        review.change_atoms -= 1
        self.assertFalse(assertions_pass(quote_checks(review, FIXTURES[0], observations)))

    def test_unavailable_smart_matches_policy_read_count_and_blocks_target_bound(self):
        review = SimpleNamespace(
            fee_quote=SimpleNamespace(estimator="UNAVAILABLE", source="NETWORK_FLOOR",
                rate_atoms_per_kvb=1000, floor_atoms_per_kvb=1000),
            vsize=155, rate_atoms_per_kvb=1000, available_after=0, input_count=1,
            atoms=100_000, fee=155, overpay_atoms=0, change_atoms=899_845,
            available_before=1_000_000, total_debit=100_155)

        # 1 policy read -> 3 captures (blocks=0 and blocks=1 <= target) pass.
        for blocks in (0, 1, 2):
            with self.subTest(reads=1, blocks=blocks):
                checks = quote_checks(review, FIXTURES[0], {
                    "proposals": [155],
                    "releases": [],
                    "events": self._prepare_events(),
                    "policy": self._empty_smart_policy(blocks=blocks, reads=1),
                })
                self.assertTrue(checks["unavailable_smart"])
                self.assertTrue(checks["floor_quote"])

        # 2 policy reads (prepare + sign re-read) -> 6 captures (blocks=0 and blocks=1) pass.
        for blocks in (0, 1):
            with self.subTest(reads=2, blocks=blocks):
                checks = quote_checks(review, FIXTURES[1], {
                    "proposals": [155],
                    "releases": [],
                    "events": self._prepare_and_sign_events(),
                    "policy": self._empty_smart_policy(blocks=blocks, reads=2),
                })
                self.assertTrue(checks["unavailable_smart"])
                self.assertTrue(checks["floor_quote"])

        # Count mismatches, missing targets, blocks > target, bad blocks, or non-unavailable replies fail.
        base_policy = self._empty_smart_policy()[:2]
        def smart(target, blocks=0, errors=None, extra=None):
            payload = {"errors": errors if errors is not None else ["Insufficient data or no feerate found"]}
            if blocks is not None:
                payload["blocks"] = blocks
            if extra:
                payload.update(extra)
            return {"method": "estimatesmartfee", "target": target, "result": json_capture(payload)}

        bad_cases = (
            ("wrong_error_text", self._prepare_events(), [*base_policy, *[smart(t, 0, ["Insufficient data"]) for t in (2, 6, 25)]]),
            ("blocks_exceeds_target_2", self._prepare_events(), [*base_policy, smart(2, 3), smart(6, 1), smart(25, 1)]),
            ("blocks_exceeds_target_6", self._prepare_events(), [*base_policy, smart(2, 1), smart(6, 7), smart(25, 1)]),
            ("blocks_negative", self._prepare_events(), [*base_policy, smart(2, -1), smart(6, 0), smart(25, 0)]),
            ("blocks_bool", self._prepare_events(), [*base_policy, smart(2, True), smart(6, 0), smart(25, 0)]),
            ("blocks_missing", self._prepare_events(), [*base_policy, *[smart(t, None) for t in (2, 6, 25)]]),
            ("feerate_present", self._prepare_events(), [*base_policy, smart(2, 0, extra={"feerate": Decimal("0.00020000")}), smart(6, 0), smart(25, 0)]),
            ("missing_target", self._prepare_events(), [*base_policy, *[{"method": "estimatesmartfee", "result": json_capture({"errors": ["Insufficient data or no feerate found"], "blocks": 0})}] * 3]),
            ("too_few_for_1_read", self._prepare_events(), [*base_policy, smart(2, 0), smart(6, 0)]),
            ("6_captures_for_1_read_trace", self._prepare_events(), self._empty_smart_policy(blocks=0, reads=2)),
            ("3_captures_for_2_read_trace", self._prepare_and_sign_events(), self._empty_smart_policy(blocks=0, reads=1)),
            ("sign_missing_policy_read", ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE", "ACTION_SIGN", "MARK_SIGNED", "SAVE", "SIGN"], self._empty_smart_policy(blocks=0, reads=1)),
            ("empty_events", [], self._empty_smart_policy(blocks=0, reads=1)),
        )
        for label, events, policy in bad_cases:
            with self.subTest(label=label):
                checks = quote_checks(review, FIXTURES[0], {
                    "proposals": [155],
                    "releases": [],
                    "events": events,
                    "policy": policy,
                })
                self.assertFalse(checks["unavailable_smart"], label)

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

    def test_tma_capture_converts_known_float_fields_and_refuses_all_others(self):
        float_reply = [{
            "allowed": True,
            "txid": "a" * 64,
            "wtxid": "b" * 64,
            "vsize": 155,
            "fees": {
                "base": 1.55e-06,
                "effective-feerate": 1e-05,
                "effective-includes": ["b" * 64],
            },
        }]
        # json_capture itself remains strict and refuses floats everywhere.
        with self.assertRaisesRegex(ValueError, "F3_RPC_TYPE_DENIED"):
            json_capture(float_reply)

        with localcontext() as ctx:
            ctx.prec = 2
            captured = tma_capture(float_reply)
            checks = assert_tma(float_reply, 155, 155, "a" * 64, "b" * 64)
        self.assertTrue(assertions_pass(checks))
        self.assertEqual(captured["decimals"], {
            "/0/fees/base": "0.00000155",
            "/0/fees/effective-feerate": "0.00001",
        })
        self.assertEqual(captured["float_decoded_fields"], {
            "/0/fees/base": TMA_FLOAT_CONVERSION_NOTE,
            "/0/fees/effective-feerate": TMA_FLOAT_CONVERSION_NOTE,
        })
        # Original float_reply was not mutated.
        self.assertIs(type(float_reply[0]["fees"]["base"]), float)

        # F3-03/exact realistic Core reply: 112 vB, 155 atoms, effective-feerate 1383 atoms/kvB.
        exact_reply = [{
            "allowed": True,
            "txid": "a" * 64,
            "wtxid": "b" * 64,
            "vsize": 112,
            "fees": {
                "base": 1.55e-06,
                "effective-feerate": 1.383e-05,
                "effective-includes": ["b" * 64],
            },
        }]
        self.assertTrue(assertions_pass(assert_tma(exact_reply, 112, 155, "a" * 64, "b" * 64)))

        # Fractional-atom fees.base is refused.
        for bad_base in (1.551e-06, 1e-09, 0.1 + 0.2, -1.55e-06, -0.0):
            bad_reply = copy.deepcopy(float_reply)
            bad_reply[0]["fees"]["base"] = bad_base
            with self.subTest(bad_base=bad_base):
                with self.assertRaisesRegex(ValueError, "F3_AMOUNT_PRECISION"):
                    tma_capture(bad_reply)
                self.assertFalse(assert_tma(bad_reply, 155, 155, "a" * 64, "b" * 64)["base_fee"])

        # Non-finite floats in known TMA fields are refused.
        for nonfinite in (float("nan"), float("inf"), float("-inf")):
            bad_reply = copy.deepcopy(float_reply)
            bad_reply[0]["fees"]["base"] = nonfinite
            with self.subTest(nonfinite=nonfinite):
                with self.assertRaisesRegex(ValueError, "F3_RPC_TYPE_DENIED"):
                    tma_capture(bad_reply)
                self.assertFalse(assert_tma(bad_reply, 155, 155, "a" * 64, "b" * 64)["base_fee"])

        # Non-round-trip conversion (e.g. repr mismatch) is refused.
        with patch("builtins.repr", return_value="0.0000015500000000000002"):
            with self.assertRaisesRegex(ValueError, "F3_TMA_FLOAT_ROUNDTRIP"):
                tma_capture(float_reply)
            self.assertFalse(assert_tma(float_reply, 155, 155, "a" * 64, "b" * 64)["base_fee"])

        # Any float in any other field (or non-list shape) still raises F3_RPC_TYPE_DENIED.
        other_float_cases = (
            [{"allowed": True, "txid": "a" * 64, "wtxid": "b" * 64, "vsize": 155.0,
              "fees": {"base": 1.55e-06, "effective-feerate": 1e-05, "effective-includes": ["b" * 64]}}],
            [{"allowed": True, "txid": "a" * 64, "wtxid": "b" * 64, "vsize": 155,
              "fees": {"base": 1.55e-06, "effective-feerate": 1e-05, "ancestor": 1.55e-06, "effective-includes": ["b" * 64]}}],
            [{"allowed": True, "txid": "a" * 64, "wtxid": "b" * 64, "vsize": 155,
              "fees": {"base": 1.55e-06, "effective-feerate": 1e-05, "effective-includes": [1.0]}}],
            [{"allowed": True, "txid": "a" * 64, "wtxid": "b" * 64, "vsize": 155, "extra": 0.5,
              "fees": {"base": 1.55e-06, "effective-feerate": 1e-05, "effective-includes": ["b" * 64]}}],
            {"fees": {"base": 1.55e-06}},
        )
        for bad_shape in other_float_cases:
            with self.subTest(bad_shape=bad_shape), self.assertRaisesRegex(ValueError, "F3_RPC_TYPE_DENIED"):
                tma_capture(bad_shape)

    def test_bounded_downward_attempt_matches_reviewed_fee2(self):
        refused_112 = {"fee": 112, "refused": True, "code": "WALLET_INPUT_FUNDS_UNAVAILABLE"}
        for trace in (
            [155], [155, 270], [155, 112, 155], [155, 112],
            [155, refused_112, 155],
            [155, 270, {"fee": 150, "refused": True, "code": "WALLET_INPUT_FUNDS_UNAVAILABLE"}, 270],
        ):
            self.assertTrue(proposal_trace_holds(trace), trace)
        for trace in (
            [], [True], [155]*7, [155, 112, 100], [155, 112, 156],
            [155, 200, 150, 200, 140],
            [refused_112, 155],
            [155, refused_112],
            [155, refused_112, 156],
            [155, refused_112, 155, 155],
            [155, {"fee": 155, "refused": True, "code": "WALLET_INPUT_FUNDS_UNAVAILABLE"}, 155],
            [155, {"fee": 200, "refused": True, "code": "WALLET_INPUT_FUNDS_UNAVAILABLE"}, 155],
            [155, {"fee": 112, "refused": True, "code": "OTHER_CODE"}, 155],
            [155, refused_112, refused_112, 155],
        ):
            self.assertFalse(proposal_trace_holds(trace), trace)

    def test_f3_03_exact_refused_lower_proposal_and_cancel_release_counting(self):
        exact_fixture = next(f for f in FIXTURES if f.case == "F3-03" and f.name == "exact")
        exact_review = SimpleNamespace(
            fee_quote=SimpleNamespace(estimator="UNAVAILABLE", source="NETWORK_FLOOR",
                rate_atoms_per_kvb=1000, floor_atoms_per_kvb=1000),
            vsize=112, rate_atoms_per_kvb=1000, available_after=0, input_count=1,
            atoms=100_000, fee=155, overpay_atoms=43, change_atoms=0,
            available_before=100_155, total_debit=100_155)
        refused = {"fee": 112, "refused": True, "code": "WALLET_INPUT_FUNDS_UNAVAILABLE"}
        checks = quote_checks(exact_review, exact_fixture, {
            "proposals": [155, refused, 155],
            "releases": ["r1"],
            "events": self._prepare_events(),
            "policy": self._empty_smart_policy(),
        })
        self.assertTrue(assertions_pass(checks))
        bad_releases = quote_checks(exact_review, exact_fixture, {
            "proposals": [155, refused, 155],
            "releases": ["r1", "r2"],
            "events": self._prepare_events(),
            "policy": self._empty_smart_policy(),
        })
        self.assertFalse(bad_releases["released_unsaved_drafts"])

        floor_review = SimpleNamespace(
            fee_quote=SimpleNamespace(estimator="UNAVAILABLE", source="NETWORK_FLOOR",
                rate_atoms_per_kvb=1000, floor_atoms_per_kvb=1000),
            vsize=155, rate_atoms_per_kvb=1000, available_after=0, input_count=1,
            atoms=100_000, fee=155, overpay_atoms=0, change_atoms=899_845,
            available_before=1_000_000, total_debit=100_155)
        f301_checks = quote_checks(floor_review, FIXTURES[0], {
            "proposals": [155],
            "releases": ["cancel-release"],
            "events": ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE", "ACTION_CANCEL", "RELEASE_DRAFT", "SAVE"],
            "policy": self._empty_smart_policy(),
        })
        self.assertTrue(f301_checks["released_unsaved_drafts"])

    def test_sign_order_requires_save_mark_signed_save_sign(self):
        valid = [
            "ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
            "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
            "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE",
            "TESTMEMPOOLACCEPT", "SENDRAWTRANSACTION", "SAVE",
        ]
        self.assertTrue(sign_order_holds(valid))
        full_trace = [
            "ACTION_PREPARE_AUTO", *(["POLICY_READ"] * 6), "PROPOSE", "SAVE",
            "ACTION_SIGN", *(["POLICY_READ"] * 6), "MARK_SIGNED", "SAVE", "SIGN",
            "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE",
            "TESTMEMPOOLACCEPT", "SENDRAWTRANSACTION", "SAVE",
            "ACTION_SNAPSHOT", "ACTION_INSPECT_CONFIRMED", "ACTION_CONFIRM", "SAVE",
            "ACTION_SNAPSHOT", "ACTION_SNAPSHOT", "ACTION_QUIT",
        ]
        self.assertTrue(sign_order_holds(full_trace))
        for bad in (
            [e for e in valid if e != "SAVE"],
            # Sign-window violations (unchanged rules).
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE",
             "TESTMEMPOOLACCEPT", "SENDRAWTRANSACTION", "SAVE"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SIGN", "SAVE",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE",
             "TESTMEMPOOLACCEPT", "SENDRAWTRANSACTION", "SAVE"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "MARK_SIGNED", "POLICY_READ", "SAVE", "SIGN",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE",
             "TESTMEMPOOLACCEPT", "SENDRAWTRANSACTION", "SAVE"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "SAVE", "MARK_SIGNED", "SIGN",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE",
             "TESTMEMPOOLACCEPT", "SENDRAWTRANSACTION", "SAVE"],
            # Missing preflight or missing Wallet.broadcast TMA.
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
             "ACTION_BROADCAST", "SAVE", "TESTMEMPOOLACCEPT", "SENDRAWTRANSACTION", "SAVE"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE", "SENDRAWTRANSACTION", "SAVE"],
            # Reordered broadcast window.
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "TESTMEMPOOLACCEPT",
             "SAVE", "SENDRAWTRANSACTION", "SAVE"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
             "ACTION_BROADCAST", "SAVE", "TESTMEMPOOLACCEPT",
             "TESTMEMPOOLACCEPT", "SENDRAWTRANSACTION", "SAVE"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE",
             "SENDRAWTRANSACTION", "TESTMEMPOOLACCEPT", "SAVE"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE",
             "TESTMEMPOOLACCEPT", "SAVE", "SENDRAWTRANSACTION"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE",
             "TESTMEMPOOLACCEPT", "SENDRAWTRANSACTION"],
            # Double-send inside broadcast window or later in trace, and send before approval.
            [*valid[:-1], "SENDRAWTRANSACTION", "SAVE"],
            [*full_trace, "SENDRAWTRANSACTION"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
             "SENDRAWTRANSACTION",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE",
             "TESTMEMPOOLACCEPT", "SENDRAWTRANSACTION", "SAVE"],
        ):
            self.assertFalse(sign_order_holds(bad), bad)

    def test_confirmed_debit_and_reopen_clean_oracles(self):
        selected = [{"txid": "11" * 32, "vout": 0, "atoms": 1_000_000}]
        # WSP leaves confirmed payment rows in state 'broadcast'.
        self.assertTrue(confirmed_debit_holds(
            pre_confirmed_atoms=1_000_000,
            post_confirmed_atoms=899_845,
            post_available_atoms=899_845,
            amount=100_000,
            fee=155,
            selected_inputs=selected,
            reservation_rows=[{"txid": "11" * 32, "vout": 0, "state": "broadcast"}],
        ))
        # PM-036 debt (Cursor PEER-120 nit): a signed/broadcast payment with NO
        # matching reservation row must FAIL. all([]) used to pass vacuously.
        for rows in ([], [{"txid": "99" * 32, "vout": 0, "state": "broadcast"}],
                     [{"txid": "11" * 32, "vout": 1, "state": "broadcast"}]):
            self.assertFalse(confirmed_debit_holds(
                pre_confirmed_atoms=1_000_000,
                post_confirmed_atoms=899_845,
                post_available_atoms=899_845,
                amount=100_000,
                fee=155,
                selected_inputs=selected,
                reservation_rows=rows,
            ), rows)
        multi_inputs = [
            {"txid": "11" * 32, "vout": 0, "atoms": 100_000},
            {"txid": "22" * 32, "vout": 1, "atoms": 100_000},
            {"txid": "33" * 32, "vout": 2, "atoms": 100_000},
        ]
        self.assertTrue(confirmed_debit_holds(
            pre_confirmed_atoms=300_000,
            post_confirmed_atoms=49_730,
            post_available_atoms=49_730,
            amount=250_000,
            fee=270,
            selected_inputs=multi_inputs,
            reservation_rows=[
                {"txid": c["txid"], "vout": c["vout"], "state": "broadcast"}
                for c in multi_inputs
            ],
        ))
        # Every selected input needs its own row: one missing row of three fails,
        # as does a duplicated row or a duplicated selected input.
        for rows, inputs in (
            ([{"txid": c["txid"], "vout": c["vout"], "state": "broadcast"} for c in multi_inputs[:2]],
             multi_inputs),
            ([{"txid": c["txid"], "vout": c["vout"], "state": "broadcast"}
              for c in multi_inputs + multi_inputs[:1]], multi_inputs),
            ([{"txid": c["txid"], "vout": c["vout"], "state": "broadcast"} for c in multi_inputs],
             multi_inputs + multi_inputs[:1]),
        ):
            self.assertFalse(confirmed_debit_holds(
                pre_confirmed_atoms=300_000,
                post_confirmed_atoms=49_730,
                post_available_atoms=49_730,
                amount=250_000,
                fee=270,
                selected_inputs=inputs,
                reservation_rows=rows,
            ))
        # Fails with draft, signed, or uncertain row for this payment, or wrong balance delta.
        for bad_state in ("draft", "signed", "uncertain"):
            self.assertFalse(confirmed_debit_holds(
                pre_confirmed_atoms=1_000_000,
                post_confirmed_atoms=899_845,
                post_available_atoms=899_845,
                amount=100_000,
                fee=155,
                selected_inputs=selected,
                reservation_rows=[{"txid": "11" * 32, "vout": 0, "state": bad_state}],
            ), bad_state)
        self.assertFalse(confirmed_debit_holds(
            pre_confirmed_atoms=1_000_000,
            post_confirmed_atoms=899_846,
            post_available_atoms=899_846,
            amount=100_000,
            fee=155,
            selected_inputs=selected,
            reservation_rows=[{"txid": "11" * 32, "vout": 0, "state": "broadcast"}],
        ))
        self.assertFalse(confirmed_debit_holds(
            pre_confirmed_atoms=1_000_000,
            post_confirmed_atoms=899_845,
            post_available_atoms=0,
            amount=100_000,
            fee=155,
            selected_inputs=selected,
            reservation_rows=[{"txid": "11" * 32, "vout": 0, "state": "broadcast"}],
        ))

        reopened = {
            "confirmed_atoms": 899_845,
            "available_atoms": 899_845,
            "reservation_count": 1,
            "reservation_states": ["broadcast"],
            "reservation_state_counts": [["broadcast", 1]],
            "pending_confirm_txid": None,
            "payment_review": None,
            "payment_signed": False,
            "recovered_unsigned_cancel_available": False,
        }
        self.assertTrue(reopen_clean_holds(
            reopened, expected_confirmed_atoms=899_845, expected_reservation_count=1,
        ))
        for bad_patch in (
            {"reservation_states": ["signed"], "reservation_state_counts": [["signed", 1]]},
            {"reservation_states": ["draft"], "reservation_state_counts": [["draft", 1]]},
            {"reservation_count": 0},
            {"pending_confirm_txid": "aa" * 32},
            {"payment_signed": True},
        ):
            bad_reopened = {**reopened, **bad_patch}
            self.assertFalse(reopen_clean_holds(
                bad_reopened, expected_confirmed_atoms=899_845, expected_reservation_count=1,
            ), bad_patch)

        # Positive spend pass contract requires explicit pre/post confirmed_atoms.
        f302 = next(f for f in FIXTURES if f.case == "F3-02")
        spend_pass = Evidence().passing_result()
        spend_pass["fixture"] = f302.name
        spend_pass["case_id"] = f302.case
        spend_pass["assertions"] = {key: True for key in required_assertions(f302)}
        self.assertFalse(valid_pass_result(spend_pass))
        spend_pass["confirmed_atoms"] = {"pre": 1_000_000, "post": 899_845}
        self.assertTrue(valid_pass_result(spend_pass))


class ExecutorAndGuiBoundary(unittest.TestCase):
    def _fake_backend_factory(self, calls, *, gate=None, reenter_holder=None):
        class FakeBackend:
            def execute(self, action, args, kwargs):
                calls.append((action, threading.current_thread().name, args))
                if gate is not None and action == "fee_inspect":
                    gate.set()
                    threading.Event().wait(0.15)
                if reenter_holder is not None and action == "fee_observe":
                    executor = reenter_holder["executor"]
                    exc = executor.submit("fee_inspect").exception(timeout=2)
                    return {"error_type": type(exc).__name__, "args": exc.args}
                return {"action": action, "thread": threading.current_thread().name}

            def public_state(self):
                return {"locked": False, "faulted": False, "core_alive": False}

            def close(self):
                return None

        return FakeBackend

    def test_qualification_executor_admits_only_five_fee_actions_while_production_refuses(self):
        self.assertTrue(QUALIFICATION_COMMANDS.isdisjoint(COMMANDS))
        self.assertEqual(
            set(QUALIFICATION_COMMANDS),
            {"fee_fixture", "fee_inspect", "fee_baseline", "fee_observe", "fee_preflight"},
        )

        # Production WalletExecutor must still refuse all five actions with the exact code.
        prod_calls = []
        prod = WalletExecutor(self._fake_backend_factory(prod_calls))
        try:
            for action in sorted(QUALIFICATION_COMMANDS):
                with self.assertRaises(WalletExecutorError) as err:
                    prod.request(action, timeout=5)
                self.assertEqual(err.exception.args, ("WALLET_EXECUTOR_BUSY_OR_CLOSED",))
            self.assertEqual(prod_calls, [])
            self.assertEqual(prod.request("snapshot", timeout=5)["action"], "snapshot")
            self.assertEqual([c[0] for c in prod_calls], ["snapshot"])
        finally:
            prod.request("quit", timeout=5)
            prod.join(timeout=5)

        # QualificationFeeExecutor admits all five on the WAM-wallet-owner thread.
        qual_calls = []
        gate = threading.Event()
        holder = {}
        qual = QualificationFeeExecutor(self._fake_backend_factory(qual_calls, gate=gate, reenter_holder=holder))
        holder["executor"] = qual
        try:
            for action in ("fee_fixture", "fee_baseline", "fee_preflight", "snapshot"):
                res = qual.request(action, "arg", timeout=5)
                self.assertEqual(res["action"], action)
                self.assertEqual(res["thread"], "WAM-wallet-owner")

            # Reentrancy on the owner thread must fail with WALLET_EXECUTOR_BUSY_OR_CLOSED.
            reentrant = qual.request("fee_observe", timeout=5)
            self.assertEqual(reentrant["error_type"], "WalletExecutorError")
            self.assertEqual(reentrant["args"], ("WALLET_EXECUTOR_BUSY_OR_CLOSED",))

            # Single-pending constraint applies to qualification actions too.
            slow = qual.submit("fee_inspect")
            self.assertTrue(gate.wait(timeout=2))
            with self.assertRaises(WalletExecutorError) as busy_err:
                qual.request("fee_fixture", timeout=5)
            self.assertEqual(busy_err.exception.args, ("WALLET_EXECUTOR_BUSY_OR_CLOSED",))
            self.assertEqual(slow.result(timeout=5)["action"], "fee_inspect")

            # Unknown actions still fail even on QualificationFeeExecutor.
            with self.assertRaises(WalletExecutorError) as unknown_err:
                qual.request("fee_unknown", timeout=5)
            self.assertEqual(unknown_err.exception.args, ("WALLET_EXECUTOR_BUSY_OR_CLOSED",))
        finally:
            qual.request("quit", timeout=5)
            qual.join(timeout=5)

        with self.assertRaises(WalletExecutorError) as closed_err:
            qual.request("fee_fixture", timeout=5)
        self.assertEqual(closed_err.exception.args, ("WALLET_EXECUTOR_BUSY_OR_CLOSED",))

    def test_fee_backend_records_refused_lower_proposal_without_release(self):
        from wam_sp.wallet import Signer, Wallet
        from wam_regtest.wallet_session import WalletCoreCli

        observations = {}
        FeeBackend = backend_type()
        backend = FeeBackend.__new__(FeeBackend)
        backend.observations = observations
        backend._spend_session = None
        backend.execute("fee_observe", (), {})

        def fake_super_execute(_self, _action, _args, _kwargs):
            Wallet.propose(None, "wam1dest", 155)
            Wallet.release_draft(None, "tok1")
            try:
                Wallet.propose(None, "wam1dest", 112)
            except ValueError:
                pass
            Wallet.propose(None, "wam1dest", 155)
            return "ok"

        with (
            patch.object(Wallet, "propose", side_effect=[None, ValueError("INSUFFICIENT_SINGLE_CLUSTER_FUNDS"), None]),
            patch.object(Wallet, "release_draft", return_value=None),
            patch.object(Wallet, "mark_signed", return_value=None),
            patch.object(Signer, "sign", return_value=None),
            patch.object(WalletCoreCli, "call", return_value={}),
            patch("wam_regtest.bip39_owner_backend.Bip39ReadOnlyBackend.execute", fake_super_execute),
        ):
            self.assertEqual(backend.execute("prepare_auto", (), {}), "ok")
        self.assertFalse(observations.get("observer_errors"))
        self.assertEqual(
            observations["proposals"],
            [155, {"fee": 112, "refused": True, "code": "WALLET_INPUT_FUNDS_UNAVAILABLE"}, 155],
        )
        self.assertEqual(len(observations["releases"]), 1)
        self.assertTrue(proposal_trace_holds(observations["proposals"]))

    @staticmethod
    def _load_actual_v013():
        root = Path(__file__).resolve().parents[1]
        number_re = re.compile(r"-?\d+(\.\d+)?(E[+-]?\d+)?\Z", re.I)

        def decimalize(value, key=None):
            if isinstance(value, dict):
                return {k: decimalize(v, k) for k, v in value.items()}
            if isinstance(value, list):
                return [decimalize(v) for v in value]
            if isinstance(value, str) and key not in ("subversion",) and number_re.match(value):
                return Decimal(value)
            return value

        return decimalize(json.loads((root / "tests/fixtures/fee_rpc_regtest_v013_empty.json").read_text()))

    def test_fee_baseline_captures_realistic_v013_replies_and_refuses_nested_secret_keys(self):
        actual = self._load_actual_v013()
        FeeBackend = backend_type()

        def run_baseline(raw_reply):
            class FakeRpc:
                verified_network = "regtest"

                def attest(self):
                    return None

                def call(self, method, params=None):
                    if method == "getnetworkinfo":
                        return copy.deepcopy(actual["getnetworkinfo"])
                    if method == "getmempoolinfo":
                        return copy.deepcopy(actual["getmempoolinfo"])
                    if method == "estimatesmartfee":
                        return copy.deepcopy(actual[f"estimatesmartfee_{params[0]}_conservative"])
                    if method == "estimaterawfee":
                        return copy.deepcopy(raw_reply)
                    raise AssertionError(f"unexpected RPC {method}")

            backend = FeeBackend.__new__(FeeBackend)
            backend.observations = {}
            backend._spend_session = SimpleNamespace(_rpc=lambda: FakeRpc())
            return backend.execute("fee_baseline", (), {})

        with tempfile.TemporaryDirectory() as folder:
            baseline = run_baseline(actual["estimaterawfee_6"])
            self.assertEqual(baseline["quote"]["floor_atoms_per_kvb"], 1000)
            self.assertEqual(baseline["quote"]["estimator"], "UNAVAILABLE")
            response = baseline["rpc"]["response"]
            self.assertIn("estimaterawfee", response)
            self.assertNotIn("raw", response)
            self.assertEqual(response["estimaterawfee"]["short"]["decay"], "0.962")
            digest = write_artifact(Path(folder) / "baseline.json", baseline)
            self.assertEqual(len(digest), 64)
            loaded = json.loads((Path(folder) / "baseline.json").read_text())
            self.assertIn("estimaterawfee", loaded["rpc"]["response"])

            # Non-empty estimaterawfee reply with pass bucket is also accepted and serialized.
            populated_raw = copy.deepcopy(actual["estimaterawfee_6"])
            populated_raw["short"]["pass"] = {
                "startrange": Decimal("0.00001000"),
                "endrange": Decimal("0.00002000"),
                "withintarget": Decimal("12.5"),
                "totalconfirmed": Decimal("12.5"),
                "inmempool": 0,
                "leftmempool": 0,
            }
            populated = run_baseline(populated_raw)
            self.assertIn("pass", populated["rpc"]["response"]["estimaterawfee"]["short"])
            write_artifact(Path(folder) / "baseline-populated.json", populated)

        # Nested denylisted keys inside RPC replies must still be refused.
        for bad_key in ("raw", "seed"):
            bad_reply = copy.deepcopy(actual["estimaterawfee_6"])
            bad_reply["short"][bad_key] = "nested-secret"
            with self.subTest(bad_key=bad_key), self.assertRaisesRegex(ValueError, "F3_PUBLIC_RPC_KEYS_DENIED"):
                run_baseline(bad_reply)

    def test_every_evidence_action_serializes_realistic_replies(self):
        from hashlib import sha256
        from wam_regtest.wallet_session import WalletCoreCli
        from wam_sp.psbt import PSBT, Tx
        from wam_sp.transaction import p2wpkh
        from wam_sp.wallet import Signer, Wallet

        actual = self._load_actual_v013()
        FeeBackend = backend_type()

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)

            # 1. fee_fixture
            owner_dir = root / "owner"
            owner_dir.mkdir()
            coinbase_txid = "11" * 32
            funding_txid = "22" * 32
            genesis_hash = "00" * 32
            block1_hash = "33" * 32
            heights = iter([0, 101, 102])

            def fake_call(_self, method, params=None):
                if method == "getblockcount":
                    return next(heights)
                if method == "getblockhash":
                    return genesis_hash if params == [0] else block1_hash
                if method == "getnetworkinfo":
                    return copy.deepcopy(actual["getnetworkinfo"])
                raise AssertionError(f"unexpected call {method}")

            def fake_raw_call(_self, method, params=None):
                if method == "generatetoaddress":
                    return [block1_hash] * int(params[0])
                if method == "getblock":
                    return {
                        "hash": block1_hash,
                        "tx": [{
                            "txid": coinbase_txid,
                            "vout": [{"n": 0, "value": Decimal("50.00000000"),
                                      "scriptPubKey": {"hex": p2wpkh(31).hex()}}],
                        }],
                    }
                if method == "sendrawtransaction":
                    return funding_txid
                raise AssertionError(f"unexpected _call {method}")

            fixture_backend = FeeBackend.__new__(FeeBackend)
            fixture_backend.observations = {}
            fixture_backend.source = root / "wsp-source"
            fixture_backend._secret = b"secret"
            fixture_backend._seed_folder = owner_dir / "bip39-12-id1"
            fixture_backend._spend_session = None
            fixture_backend._public = {"receive_code": "wam1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"}
            fixture_backend._core = lambda: SimpleNamespace(cli=root / "wam-cli", directory=owner_dir)
            with (
                patch("wam_regtest.managed_wallet_checkpoint._owned", return_value=None),
                patch("wam_regtest.wsp_live.public_regtest_mining_address", return_value="wamrt1qaddr"),
                patch.object(WalletCoreCli, "attest", return_value=None),
                patch.object(WalletCoreCli, "call", fake_call),
                patch.object(WalletCoreCli, "_call", fake_raw_call),
                patch("wam_sp.core.send", return_value=(bytes(32),)),
                patch("wam_sp.transaction.signed_single_input", return_value="00" * 80),
            ):
                fixture_ev = fixture_backend.execute("fee_fixture", ((1_000_000,),), {})
            write_artifact(root / "fee_fixture.json", fixture_ev)

            # 2. fee_inspect
            db = sqlite3.connect(":memory:")
            db.execute("CREATE TABLE reservations (txid TEXT, vout INT, token TEXT, state TEXT, created INT)")
            db.execute("INSERT INTO reservations VALUES (?, ?, ?, ?, ?)", (funding_txid, 0, "tok1", "reserved", 1))
            coins = [{"txid": funding_txid, "vout": 0, "atoms": 1_000_000, "account": 0, "label": "main"}]
            inspect_rpc = SimpleNamespace(
                attest=lambda: None,
                _call=lambda method, params=None: [funding_txid] if method == "getrawmempool" else None,
                call=lambda method, params=None: (
                    copy.deepcopy(actual["getmempoolinfo"]) if method == "getmempoolinfo" else None
                ),
            )
            inspect_backend = FeeBackend.__new__(FeeBackend)
            inspect_backend.observations = {}
            inspect_backend._spend_session = SimpleNamespace(
                _rpc=lambda: inspect_rpc,
                scanner=SimpleNamespace(coins=lambda: coins, store=SimpleNamespace(db=db)),
                vault=SimpleNamespace(anchor=SimpleNamespace(read=lambda: {"seq": 1})),
                faulted=False,
                _prepared=None,
                _signed=None,
            )
            with patch.object(Wallet, "balance", return_value={
                "confirmed_atoms": 1_000_000, "available_atoms": 1_000_000,
                "reserved_atoms": 0, "unconfirmed_atoms": 0, "pending_spent_atoms": 0,
            }):
                inspect_ev = inspect_backend.execute("fee_inspect", (), {})
            write_artifact(root / "fee_inspect.json", inspect_ev)

            # 3. fee_preflight (realistic product-transport float-decoded TMA reply)
            script = b"\x51\x20" + bytes(32)
            tx = Tx((("11" * 32, 0),), ((100_000, script), (899_845, script)))
            raw_tx = tx.serialize([(bytes(65),)])
            txid = sha256(sha256(tx.serialize()).digest()).digest()[::-1].hex()
            wtxid = sha256(sha256(raw_tx).digest()).digest()[::-1].hex()
            tma_reply = [{
                "allowed": True,
                "txid": txid,
                "wtxid": wtxid,
                "vsize": 155,
                "fees": {
                    "base": 1.55e-06,
                    "effective-feerate": 1e-05,
                    "effective-includes": [wtxid],
                },
            }]
            mempool_calls = iter([[], []])
            preflight_rpc = SimpleNamespace(
                _call=lambda method, params=None: next(mempool_calls) if method == "getrawmempool" else None,
                call=lambda method, params=None: (
                    copy.deepcopy(tma_reply) if method == "testmempoolaccept" else None
                ),
            )
            fake_psbt = SimpleNamespace(
                finalize=lambda: raw_tx,
                txid=lambda: txid,
                tx=tx,
                signatures=[bytes(65)],
            )
            preflight_backend = FeeBackend.__new__(FeeBackend)
            preflight_backend.observations = {}
            preflight_backend._spend_session = SimpleNamespace(
                _signed=b"psbt-bytes",
                _rpc=lambda: preflight_rpc,
                _prepared=SimpleNamespace(proposal=SimpleNamespace(coins=coins)),
                _review=SimpleNamespace(vsize=155, fee=155),
            )
            with patch.object(PSBT, "decode", return_value=fake_psbt):
                preflight_ev = preflight_backend.execute("fee_preflight", (), {})
            self.assertTrue(all(preflight_ev["checks"].values()))
            self.assertEqual(preflight_ev["capture"]["float_decoded_fields"], {
                "/0/fees/base": TMA_FLOAT_CONVERSION_NOTE,
                "/0/fees/effective-feerate": TMA_FLOAT_CONVERSION_NOTE,
            })
            write_artifact(root / "tma.json", preflight_ev)

            # 4. fee_observe + observed FEE_POLICY_READS
            obs = {}
            obs_backend = FeeBackend.__new__(FeeBackend)
            obs_backend.observations = obs
            obs_backend._spend_session = None
            obs_backend.execute("fee_observe", (), {})

            def observed_execute(_self, _action, _args, _kwargs):
                WalletCoreCli.call(None, "getnetworkinfo", [])
                WalletCoreCli.call(None, "getmempoolinfo", [])
                WalletCoreCli.call(None, "estimatesmartfee", [6, "conservative"])
                WalletCoreCli.call(None, "estimaterawfee", [6])
                return "ok"

            policy_replies = {
                "getnetworkinfo": copy.deepcopy(actual["getnetworkinfo"]),
                "getmempoolinfo": copy.deepcopy(actual["getmempoolinfo"]),
                "estimatesmartfee": copy.deepcopy(actual["estimatesmartfee_6_conservative"]),
                "estimaterawfee": copy.deepcopy(actual["estimaterawfee_6"]),
            }
            with (
                patch.object(Wallet, "propose", return_value=None),
                patch.object(Wallet, "release_draft", return_value=None),
                patch.object(Wallet, "mark_signed", return_value=None),
                patch.object(Signer, "sign", return_value=None),
                patch.object(WalletCoreCli, "call", side_effect=lambda _self, m, _a=None: policy_replies[m]),
                patch("wam_regtest.bip39_owner_backend.Bip39ReadOnlyBackend.execute", observed_execute),
            ):
                self.assertEqual(obs_backend.execute("prepare_auto", (), {}), "ok")
            self.assertFalse(obs.get("observer_errors"))
            self.assertEqual(len(obs["policy"]), 4)
            self.assertEqual(obs["policy"][2]["target"], 6)
            self.assertEqual(obs["policy"][3]["target"], 6)
            write_artifact(root / "policy.json", obs["policy"])
            write_artifact(root / "events.json", {k: v for k, v in obs.items() if k != "policy"})

            for name in ("fee_fixture.json", "fee_inspect.json", "tma.json", "policy.json", "events.json"):
                parsed = json.loads((root / name).read_text())
                self.assertIsNotNone(parsed, name)

    def test_offscreen_f301_dialog_cancel_and_no_fast_normal_slow(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication, QComboBox, QPushButton, QRadioButton
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.bip39_locale import t
        from wam_regtest.fusion_pages import PaymentApproval
        from wam_regtest.wallet_session import PaymentReview
        from wam_regtest.domain.fee_policy import FeeQuote
        from wam_regtest.wallet_executor import ExecutorState

        app = QApplication.instance() or QApplication([])

        class StubExecutor:
            state = ExecutorState()
            busy = False
            closed = False

            def submit(self, action, *args, **kwargs):
                raise AssertionError(f"unexpected submit {action}")

            def join(self, timeout=5):
                return True

        window = Bip39FusionWindow(StubExecutor())
        review = PaymentReview(
            code="wam1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            atoms=100_000,
            fee=155,
            change_atoms=899_845,
            input_count=1,
            commitment="a" * 64,
            rate_atoms_per_kvb=1000,
            rate_source="NETWORK_FLOOR",
            rate_classification="UNAVAILABLE",
            vsize=155,
            total_debit=100_155,
            available_before=1_000_000,
            available_after=0,
            overpay_atoms=0,
            fee_quote=FeeQuote(
                network="regtest",
                rate_atoms_per_kvb=1000,
                floor_atoms_per_kvb=1000,
                source="NETWORK_FLOOR",
                estimator="UNAVAILABLE",
                reasons=("NO_FEERATE_WITHOUT_ERRORS",),
                inputs_digest="0" * 64,
            ),
        )
        dialog = PaymentApproval(review, "sign", window)
        self.assertTrue(no_manual_fee_controls(window, dialog))

        # Adding Fast/Normal/Slow choices in any of the 6 catalog languages must fail.
        send_page = window.stack.widget(3)
        for sample in ("Fast", "Normal", "Slow", "快速", "普通", "Nhanh", "보통", "Cepat", "高速"):
            combo = QComboBox(send_page)
            combo.addItem(sample)
            self.assertFalse(no_manual_fee_controls(window, dialog), sample)
            combo.setParent(None)
            combo.deleteLater()
        btn = QPushButton("Normal", dialog)
        self.assertFalse(no_manual_fee_controls(window, dialog))
        btn.setParent(None)
        btn.deleteLater()
        radio = QRadioButton("Slow", send_page)
        self.assertFalse(no_manual_fee_controls(window, dialog))
        radio.setParent(None)
        radio.deleteLater()

        # Verify approve_payment inspects real visible PaymentApproval text and cancels cleanly.
        window._last_review = review
        checks = {}
        result = {}
        captured = {}
        cancelled_calls = []

        class TriggerButton:
            def click(self_inner):
                dialog.show()

        def wait(pred, _label):
            for _ in range(40):
                app.processEvents()
                if pred():
                    return
                threading.Event().wait(0.05)
            raise AssertionError("wait timed out")

        dialog.rejected.connect(lambda: cancelled_calls.append(True))
        approve_payment(
            app, window, TriggerButton(), t("pages.approve_sign"),
            lambda: bool(cancelled_calls), wait, checks, result, "sign",
            decision="cancel", captured=captured,
        )
        self.assertTrue(checks["gui_sign_review"])
        self.assertTrue(checks["gui_sign_cancel_default"])
        self.assertTrue(checks["gui_no_manual_fee_field"])
        self.assertIs(captured["review"], review)
        self.assertEqual(result["gui"]["sign"]["decision"], "cancel")
        dialog.close()
        window.close()

    def test_reopen_verified_owner_uses_activate_step_with_fakes(self):
        from wam_regtest.qualification.q06_fix_scenarios import _bind

        events = []
        app = SimpleNamespace(processEvents=lambda: None)
        state = {"app": app, "window": None, "executor": None}
        wait_report = {}
        idle, wait, _ = _bind(state, app, wait_report, "fee")

        class FakeWindow:
            def __init__(self):
                self._worker = None
                self._delivering_result = False
                self._last_error_code = None
                self._ready = True
                self._spend_enabled = False
                # Checkpointed reopen leaves _last_verified None until activate.
                self._last_verified = None
                self._pending_confirm_txid = None
                self.confirm = SimpleNamespace(isEnabled=lambda: False)
                self.activate = SimpleNamespace(name="activate_btn")

        def fake_open_owner(st, root, core, source, adapter, mode, keychain=None):
            events.append(("open", mode, keychain))
            win = FakeWindow()
            exe = SimpleNamespace(busy=False, closed=True)
            st["window"] = win
            st["executor"] = exe
            return exe, win

        def fake_approve(button, caption, done, label):
            win = state["window"]
            self.assertIs(button, win.activate)
            self.assertEqual(caption, "Approve")
            self.assertFalse(done())
            self.assertIsNone(win._last_verified)
            events.append(("approve", label))
            win._spend_enabled = True
            win._last_verified = SimpleNamespace(height=105)
            self.assertTrue(done())

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            exe, win = reopen_verified_owner(
                state, root, root / "core", root / "wsp", SimpleNamespace(),
                wait, fake_approve, idle, open_owner=fake_open_owner,
            )
            self.assertIs(exe, state["executor"])
            self.assertIs(win, state["window"])
            self.assertTrue(win._spend_enabled)
            self.assertIsNotNone(win._last_verified)
            self.assertEqual(events, [
                ("open", "reopen", root / "q05-disposable.keychain-db"),
                ("approve", "ENABLE_REOPEN"),
            ])

    def test_run_fixture_preserves_gui_denial_code_on_reopen_failure(self):
        from wam_regtest.domain.fee_policy import FeeQuote
        from wam_regtest.qualification import q06_fix_scenarios
        from wam_regtest.wallet_session import PaymentReview

        app = SimpleNamespace(processEvents=lambda: None)
        fixture = next(f for f in FIXTURES if f.case == "F3-05" and f.name == "recipient-330")
        result = {"assertions": {}}
        txid = "aa" * 32
        funding_txid = "11" * 32
        review = PaymentReview(
            code="wamrtsp1payee",
            atoms=330,
            fee=155,
            change_atoms=999_515,
            input_count=1,
            commitment="cc" * 32,
            rate_atoms_per_kvb=1000,
            rate_source="NETWORK_FLOOR",
            rate_classification="UNAVAILABLE",
            vsize=155,
            total_debit=485,
            available_before=1_000_000,
            available_after=0,
            overpay_atoms=0,
            fee_quote=FeeQuote(
                network="regtest",
                rate_atoms_per_kvb=1000,
                floor_atoms_per_kvb=1000,
                source="NETWORK_FLOOR",
                estimator="UNAVAILABLE",
                reasons=("NO_FEERATE_WITHOUT_ERRORS",),
                inputs_digest="0" * 64,
            ),
        )

        captured_obs = {}
        phase = {"stage": "before"}

        def fake_backend_cls(_root, _core, _source, *, _anchor_factory=None, observations=None):
            captured_obs["obs"] = observations
            return None

        class FakeExecutor:
            def __init__(self, factory):
                factory()
                self.busy = False
                self.closed = False

            def request(self, action, *args, **kwargs):
                if action == "fee_fixture":
                    return {"peers": 0, "funding": [{"txid": funding_txid, "atoms": 1_000_000}]}
                if action == "fee_inspect":
                    stage = phase["stage"]
                    return {
                        "coins": [1_000_000],
                        "cluster_count": 1,
                        "reservations": 0 if stage == "before" else 1,
                        "reservation_states": (
                            [] if stage == "before"
                            else ["signed"] if stage == "signed"
                            else ["broadcast"]
                        ),
                        "reservation_rows": (
                            [] if stage == "before"
                            else [{"txid": funding_txid, "vout": 0, "state": "signed"}] if stage == "signed"
                            else [{"txid": funding_txid, "vout": 0, "state": "broadcast"}]
                        ),
                        "reservation_sha256": "r0" if stage == "before" else "r1",
                        "anchor_sha256": "a0" if stage == "before" else "a1",
                        "balance": {"confirmed_atoms": 1_000_000, "available_atoms": 1_000_000},
                        "inventory": [{"txid": funding_txid, "vout": 0}],
                        "mempool": [txid] if stage == "broadcasted" else [],
                        "mempool_info": {"response": {"loaded": True}},
                        "prepared": stage == "signed",
                        "signed": stage == "signed",
                        "faulted": False,
                    }
                if action == "fee_baseline":
                    return {"quote": {
                        "floor_atoms_per_kvb": 1000,
                        "rate_atoms_per_kvb": 1000,
                        "estimator": "UNAVAILABLE",
                    }}
                if action == "fee_observe":
                    captured_obs["obs"].update(
                        events=[
                            "ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
                        ],
                        proposals=[155],
                        releases=[],
                        policy=[],
                    )
                    return None
                if action == "fee_preflight":
                    return {
                        "checks": {"allowed": True},
                        "final_vsize": 155,
                        "witness_sizes": [65],
                        "outputs": [330, 999_515],
                        "selected_inputs": [{"txid": funding_txid, "vout": 0, "atoms": 1_000_000}],
                        "txid": txid,
                        "mempool_unchanged": True,
                    }
                if action == "snapshot":
                    return {
                        "confirmed_atoms": 999_515,
                        "available_atoms": 999_515,
                        "reservation_count": 1,
                        "reservation_states": ["broadcast"],
                        "reservation_state_counts": [["broadcast", 1]],
                    }
                if action == "quit":
                    self.closed = True
                    return None
                raise AssertionError(f"unexpected action {action}")

            def join(self, _timeout=5):
                return True

        class FakeWindow:
            def __init__(self, _exe):
                self._worker = None
                self._delivering_result = False
                self._last_error_code = None
                self._backup_flow_active = True
                self._spend_enabled = True
                self._signed_ready = True
                self._last_review = review
                self._pending_confirm_txid = None
                self._ready = False
                self._last_verified = None
                self.recipient_input = SimpleNamespace(setText=lambda _v: None)
                self.amount_input = SimpleNamespace(setText=lambda _v: None)
                self.send = SimpleNamespace()
                self.broadcast = SimpleNamespace()
                self.activate = SimpleNamespace()
                self.confirm = SimpleNamespace(isEnabled=lambda: False)
                self.history_page = SimpleNamespace(rows=[
                    SimpleNamespace(txid=txid, credit_atoms=0, debit_atoms=485),
                ])

            def show(self):
                return None

            def start(self, *_args):
                return None

        def fake_approve_payment(_app, win, _btn, _cap, _done, _wait, _checks, _res, kind, **_kw):
            if kind == "sign":
                phase["stage"] = "signed"
                captured_obs["obs"]["events"].extend(
                    ["ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN"]
                )
            elif kind == "broadcast":
                phase["stage"] = "broadcasted"
                win._pending_confirm_txid = txid
                captured_obs["obs"]["events"].extend(
                    [
                        "ACTION_BROADCAST",
                        "TESTMEMPOOLACCEPT",
                        "SAVE",
                        "TESTMEMPOOLACCEPT",
                        "SENDRAWTRANSACTION",
                        "SAVE",
                    ]
                )

        def fake_open_owner(st, *_args, **_kwargs):
            win = FakeWindow(None)
            win._ready = False
            win._last_error_code = "Q06_GUI_BACKUP_ACK_TAMPERED"
            exe = SimpleNamespace(busy=False, closed=True)
            st["window"] = win
            st["executor"] = exe
            return exe, win

        def fake_bind(st, _app, report, section):
            def idle():
                return True

            def wait(predicate, label, timeout=240):
                if predicate():
                    return
                win = st.get("window")
                if win is not None and win._last_error_code is not None:
                    q06_fix_scenarios._note(report, section, gui_denied=win._last_error_code)
                    raise ValueError("Q06_FIX_GUI_DENIED_" + label)
                raise ValueError("Q06_FIX_WAIT_" + label)

            def approve(_btn, _cap, _done, label):
                if label == "CONFIRM":
                    phase["stage"] = "confirmed"
                    st["window"]._pending_confirm_txid = None
                    captured_obs["obs"]["events"].extend(["ACTION_CONFIRM", "SAVE"])

            return idle, wait, approve

        class FakePayee:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def public_metadata(self):
                return {"receive_code": "wamrtsp1payee"}

        with tempfile.TemporaryDirectory() as folder:
            case_dir = Path(folder) / "case"
            case_dir.mkdir()
            profile_dir = case_dir / "profile"
            profile_dir.mkdir()
            with (
                patch("wam_regtest.bip39_fusion_gui.Bip39FusionWindow", FakeWindow),
                patch("wam_regtest.bip39_12.Bip39Regtest12Keys", return_value=FakePayee()),
                patch("wam_regtest.qualification.fee_regtest_runner.QualificationFeeExecutor", FakeExecutor),
                patch("wam_regtest.qualification.fee_regtest_runner.backend_type", return_value=fake_backend_cls),
                patch("wam_regtest.qualification.fee_regtest_runner.approve_payment", fake_approve_payment),
                patch("wam_regtest.qualification.fee_regtest_runner.quote_checks", return_value={}),
                patch.object(q06_fix_scenarios, "_profile", return_value=profile_dir),
                patch.object(q06_fix_scenarios, "_bind", fake_bind),
                patch.object(q06_fix_scenarios, "_finish_backup", lambda *_a: None),
                patch.object(q06_fix_scenarios, "_open_owner", fake_open_owner),
                patch.object(q06_fix_scenarios, "_shutdown", return_value=False),
            ):
                run_fixture(
                    fixture, app, SimpleNamespace(make_anchor=lambda _r: None),
                    Path(folder) / "core", Path(folder) / "wsp", result, actor="test",
                )
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["failure_code"], "Q06_FIX_GUI_DENIED_REOPEN")
        self.assertEqual(result.get("gui_denied"), "Q06_GUI_BACKUP_ACK_TAMPERED")


if __name__ == "__main__":
    unittest.main()
