"""Pure FEE-3 evidence/oracle tests. No daemon, profile or native anchor."""
from decimal import Decimal, localcontext
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wam_regtest.qualification.fee_regtest import (
    CHARACTERIZATION_PENDING_STATUS, FIXTURES, OUTSIDE_STEP,
    aggregate_status, assertions_pass, assert_tma, exact_atoms, json_capture,
    proposal_trace_holds, required_assertions, sign_order_holds,
    valid_characterization_result, valid_pass_result, write_artifact,
)
from wam_regtest.qualification.fee_regtest_runner import (
    QUALIFICATION_COMMANDS, QualificationFeeExecutor, approve_payment,
    backend_type, no_manual_fee_controls, plain, quote_checks, resolve_actor,
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
    def _empty_smart_policy(self):
        return [
            {"method": "getnetworkinfo", "result": json_capture({"relayfee": Decimal("0.00001000")})},
            {"method": "getmempoolinfo", "result": json_capture({"mempoolminfee": Decimal("0.00001000"),
                                                              "minrelaytxfee": Decimal("0.00001000")})},
            *[{"method": "estimatesmartfee",
               "result": json_capture({"errors": ["Insufficient data or no feerate found"], "blocks": 0})}] * 3,
        ]

    def test_quote_oracle_detects_floor_arithmetic_and_structure_mismatches(self):
        review = SimpleNamespace(
            fee_quote=SimpleNamespace(estimator="UNAVAILABLE", source="NETWORK_FLOOR",
                rate_atoms_per_kvb=1000, floor_atoms_per_kvb=1000),
            vsize=155, rate_atoms_per_kvb=1000, available_after=0, input_count=1,
            atoms=100_000, fee=155, overpay_atoms=0, change_atoms=899_845,
            available_before=1_000_000, total_debit=100_155)
        observations = {"proposals": [155], "releases": [], "policy": self._empty_smart_policy()}
        self.assertTrue(assertions_pass(quote_checks(review, FIXTURES[0], observations)))
        review.change_atoms -= 1
        self.assertFalse(assertions_pass(quote_checks(review, FIXTURES[0], observations)))

    def test_unavailable_smart_pins_exact_v013_insufficient_data_structure(self):
        review = SimpleNamespace(
            fee_quote=SimpleNamespace(estimator="UNAVAILABLE", source="NETWORK_FLOOR",
                rate_atoms_per_kvb=1000, floor_atoms_per_kvb=1000),
            vsize=155, rate_atoms_per_kvb=1000, available_after=0, input_count=1,
            atoms=100_000, fee=155, overpay_atoms=0, change_atoms=899_845,
            available_before=1_000_000, total_debit=100_155)
        bad_cases = (
            [{"method": "estimatesmartfee", "result": json_capture({"errors": ["Insufficient data"], "blocks": 0})}] * 3,
            [{"method": "estimatesmartfee", "result": json_capture({"errors": ["Insufficient data or no feerate found"], "blocks": 1})}] * 3,
            [{"method": "estimatesmartfee", "result": json_capture({"errors": ["Insufficient data or no feerate found"]})}] * 3,
            [{"method": "estimatesmartfee", "result": json_capture({"errors": ["Insufficient data or no feerate found"], "blocks": 0})}] * 2,
        )
        base_policy = self._empty_smart_policy()[:2]
        for smart in bad_cases:
            checks = quote_checks(review, FIXTURES[0], {
                "proposals": [155], "releases": [], "policy": [*base_policy, *smart],
            })
            self.assertFalse(checks["unavailable_smart"])

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
            "policy": self._empty_smart_policy(),
        })
        self.assertTrue(assertions_pass(checks))
        bad_releases = quote_checks(exact_review, exact_fixture, {
            "proposals": [155, refused, 155],
            "releases": ["r1", "r2"],
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
            "events": ["ACTION_PREPARE_AUTO", "PROPOSE", "SAVE", "ACTION_CANCEL", "RELEASE_DRAFT", "SAVE"],
            "policy": self._empty_smart_policy(),
        })
        self.assertTrue(f301_checks["released_unsaved_drafts"])

    def test_sign_order_requires_save_mark_signed_save_sign(self):
        valid = [
            "ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
            "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
            "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE", "SENDRAWTRANSACTION", "SAVE",
        ]
        self.assertTrue(sign_order_holds(valid))
        for bad in (
            [e for e in valid if e != "SAVE"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SAVE", "SIGN",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE", "SENDRAWTRANSACTION"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "MARK_SIGNED", "SIGN", "SAVE",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE", "SENDRAWTRANSACTION"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "MARK_SIGNED", "POLICY_READ", "SAVE", "SIGN",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE", "SENDRAWTRANSACTION"],
            ["ACTION_PREPARE_AUTO", "POLICY_READ", "PROPOSE", "SAVE",
             "ACTION_SIGN", "POLICY_READ", "SAVE", "MARK_SIGNED", "SIGN",
             "ACTION_BROADCAST", "TESTMEMPOOLACCEPT", "SAVE", "SENDRAWTRANSACTION"],
        ):
            self.assertFalse(sign_order_holds(bad), bad)


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


if __name__ == "__main__":
    unittest.main()
