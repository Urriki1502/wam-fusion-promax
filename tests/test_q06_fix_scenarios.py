"""Structure and marker contract for the frozen Q06 fix-scenario stage.

The real Core/cocoa scenarios run only inside the frozen app. These tests
drive the evidence shell with fakes and check the wiring that keeps the
module out of the production wallet.
"""
import ast
import importlib.util
import io
import json
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

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


def _s4_passing():
    result = {
        "activation_preserved": True, "payment_signed": True,
        "payment_broadcast": True, "payment_confirmed": True, "nothing_pending": True,
        "payment_confirmed_atoms": 1_399_990_000,
        "fund_button_disabled": True, "backend_refused_exact": True,
        "signed_reservation_count": 1, "owner_retained_after_shutdown": False,
        "fund1_read_only_shape": True,
    }
    for n in (1, 2, 3, 4):
        result.update({
            f"fund{n}_button_enabled": True,
            f"fund{n}_before_atoms": (n - 1) * 500_000_000,
            f"fund{n}_after_atoms": n * 500_000_000,
            f"fund{n}_reservation_count": 0,
            f"fund{n}_raw_reservation_count": 1 if n == 4 else 0,
            f"fund{n}_mainnet_allowed": False,
        })
        if n > 1:
            result.update({f"fund{n}_signer_allowed": True,
                           f"fund{n}_broadcast_allowed": True,
                           f"fund{n}_spend_enabled": True})
    result["fund4_before_atoms"] = 1_399_990_000
    result["fund4_after_atoms"] = 1_899_990_000
    return result


class RepeatFundingOracle(unittest.TestCase):
    def test_complete_s4_oracle_requires_every_fact_and_strict_increases(self):
        good = _s4_passing()
        self.assertTrue(stage.s4_passed(good))
        for key in good:
            with self.subTest(missing=key):
                bad = dict(good)
                bad.pop(key)
                self.assertFalse(stage.s4_passed(bad))
        for key, value in (("fund2_after_atoms", 500_000_000),
                           ("fund3_before_atoms", 0),
                           ("fund4_before_atoms", 1_500_000_000),
                           ("fund4_after_atoms", 1_399_990_000),
                           ("fund4_reservation_count", 1),
                           ("payment_confirmed", False),
                           ("nothing_pending", False),
                           ("fund3_reservation_count", 1),
                           ("fund2_signer_allowed", False),
                           ("backend_refused_exact", False),
                           ("signed_reservation_count", 0),
                           ("owner_retained_after_shutdown", True),
                           ("fund1_after_atoms", True)):
            with self.subTest(key=key):
                self.assertFalse(stage.s4_passed(dict(good, **{key: value})))

    def test_s4_gate_requires_read_only_shape_only_for_preactivation_fund(self):
        good = _s4_passing()
        self.assertTrue(stage.s4_passed(good))
        for key, value in (("fund1_read_only_shape", False),
                           ("fund1_reservation_count", 1),
                           ("fund1_raw_reservation_count", 1),
                           ("fund2_reservation_count", None)):
            with self.subTest(key=key):
                self.assertFalse(stage.s4_passed(dict(good, **{key: value})))

    def test_s4_public_schema_is_only_booleans_and_ints_and_cannot_forge_pass(self):
        good = _s4_passing()
        raw = {"status": "PASS", "scenarios": dict.fromkeys(("S1", "S2", "S3", "S4"), "PASS"),
               "s4": dict(good, receive_code="secret", seed="secret", gui_denied="SECRET_CODE")}
        evidence = stage.public_evidence(raw)
        self.assertEqual(evidence["status"], "PASS")
        self.assertEqual(evidence["s4"], good)
        self.assertTrue(all(type(v) in (bool, int) for v in evidence["s4"].values()))
        raw["s4"]["backend_refused_exact"] = False
        self.assertEqual(stage.public_evidence(raw)["status"], "FAIL")

    def test_drive_rejects_pass_markers_without_complete_s4_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / stage.EVIDENCE_NAME
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = stage.drive(tuple((key, lambda report: None)
                                         for key in ("S1", "S2", "S3", "S4")), evidence_path=path)
            self.assertEqual(code, 2)
            self.assertNotIn("ALL_PASS", buffer.getvalue())
            evidence = json.loads(path.read_text())
            self.assertEqual(evidence["status"], "FAIL")
            self.assertEqual(evidence["failure_code"], "Q06_FIX_S4_EVIDENCE_DENIED")

    def test_drive_refuses_a_missing_s4_and_keeps_its_fixed_failure_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / stage.EVIDENCE_NAME
            with redirect_stdout(io.StringIO()):
                code = stage.drive(tuple((key, lambda report: None) for key in ("S1", "S2", "S3")),
                                   evidence_path=path)
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(path.read_text())["failure_code"], "Q06_FIX_SCENARIOS_INCOMPLETE")
            path.unlink()
            def s4(report):
                report["s4"] = {"backend_refused_exact": False, "seed": "secret"}
                raise ValueError("Q06_FIX_S4_IN_FLIGHT_NOT_REFUSED")
            with redirect_stdout(io.StringIO()):
                code = stage.drive((("S4", s4),), evidence_path=path)
            evidence = json.loads(path.read_text())
            self.assertEqual(code, 2)
            self.assertEqual(evidence["failure_code"], "Q06_FIX_S4_IN_FLIGHT_NOT_REFUSED")
            self.assertEqual(evidence["scenarios"]["S4"], "FAIL")
            self.assertNotIn("secret", path.read_text())


class RepeatFundingScenario(unittest.TestCase):
    """Exercise S4's real orchestration with fake GUI/RPC, never Core/Cocoa."""
    def run_s4(self, fault=None):
        report, approvals = {}, []
        status = {"balance": 0, "funds": 0, "signed": False, "broadcast": False, "confirmed": False}
        window = SimpleNamespace(
            _backup_flow_active=True, _pending_action=None, _spend_enabled=False,
            _signed_ready=False, _pending_confirm_txid=None,
            recipient_input=Mock(), amount_input=Mock(),
            send_result=SimpleNamespace(text=lambda: "Confirmed " + "a" * 64 if status["confirmed"] else ""))
        window.fund = SimpleNamespace(isEnabled=lambda: (
            not status["signed"] and fault != "button"))
        window.activate, window.send, window.broadcast, window.confirm = (object(), object(), object(),
            SimpleNamespace(isEnabled=lambda: status["broadcast"] and not status["confirmed"]))

        def request(action, **kwargs):
            if action == "mine":
                if fault == "backend_allowed":
                    return {}
                raise ValueError("Q06_GUI_WRONG_REFUSAL" if fault == "backend_wrong"
                                 else "Q06_GUI_TEST_FUNDING_IN_FLIGHT")
            self.assertEqual(action, "snapshot")
            active = window._spend_enabled and not (fault == "state" and status["funds"] > 1)
            read_only = ((status["funds"] == 1 and not window._spend_enabled
                          and fault != "reservation")
                         or (fault == "readonly_after_activation" and active))
            summary = ({"read_only": True} if read_only else
                       {"locked_inputs_total": (1 if status["signed"] else
                        int(fault == "reservation" and status["funds"] > 0))})
            raw_reservations = (1 if status["signed"] or status["confirmed"] else
                                int(fault == "reservation" and status["funds"] > 0))
            if read_only and raw_reservations == 0:
                raw_reservations = None
            return {"confirmed_atoms": status["balance"],
                    "reservation_count": raw_reservations,
                    "reservation_lock_summary": summary,
                    "signer_allowed": active, "broadcast_allowed": active,
                    "mainnet_allowed": fault == "mainnet",
                    "payment_signed": status["signed"] and fault != "signed_snapshot",
                    "pending_confirm_txid": window._pending_confirm_txid,
                    "payment_review": None,
                    "recovered_unsigned_cancel_available": False,
                    "height": 1,
                    "history": (
                        [] if not status["confirmed"] or fault == "history" else
                        [{"txid": "a" * 64, "atoms": 0,
                          **({} if fault == "missing_height" else
                             {"height": (0 if fault == "zero_height" else
                                         None if fault == "null_height" else 1)})}
                        ])}

        executor = SimpleNamespace(request=request)
        def open_owner(state, *_args):
            state.update(executor=executor, window=window)
            return executor, window

        def approve(button, caption, done, label):
            approvals.append((label, caption))
            if button is window.fund:
                status["funds"] += 1
                if fault != "balance" and not (fault == "post_fund" and status["funds"] == 4):
                    status["balance"] += 500_000_000
            elif button is window.activate:
                window._spend_enabled = fault != "activation"
            elif button is window.broadcast:
                status["broadcast"] = True
                window._pending_confirm_txid = "a" * 64
            elif button is window.confirm:
                status["signed"] = False
                status["confirmed"] = fault != "confirmed"
                status["balance"] -= 100_010_000
                window._signed_ready = False
                window._pending_confirm_txid = "a" * 64 if fault == "pending" else None
                if fault == "post_button":
                    window.fund.isEnabled = lambda: False
            else:
                window._signed_ready = True
                status["signed"] = fault != "signed"
                if fault == "gui_enabled":
                    window.fund.isEnabled = lambda: True

        def wait_for(predicate, label):
            if fault == "operation":
                raise RuntimeError("secret never copied")
            self.assertTrue(predicate(), label)

        with ExitStack() as stack:
            stack.enter_context(patch.object(stage, "_bind", return_value=(lambda: True, wait_for, approve)))
            stack.enter_context(patch.object(stage, "_open_owner", side_effect=open_owner))
            stack.enter_context(patch.object(stage, "_finish_backup"))
            stack.enter_context(patch.object(stage, "_history_txids", return_value=("a" * 64,)))
            stack.enter_context(patch.object(stage, "_profile", return_value=Path("fake-profile")))
            shutdown = stack.enter_context(patch.object(stage, "_shutdown", return_value=fault == "retained"))
            keys = stack.enter_context(patch("wam_regtest.bip39_12.Bip39Regtest12Keys"))
            keys.return_value.__enter__.return_value.public_metadata.return_value = {"receive_code": "public-fixture"}
            error = None
            with redirect_stdout(io.StringIO()):
                try:
                    stage.scenario_repeat_funding(SimpleNamespace(processEvents=lambda: None),
                                                  object(), Path("core"), Path("wsp"), report)
                except Exception as caught:
                    error = caught
            shutdown.assert_called_once()
        return report, approvals, error

    def test_gui_funding_approvals_activation_sign_and_shutdown_are_required(self):
        report, approvals, error = self.run_s4()
        self.assertIsNone(error)
        self.assertTrue(stage.s4_passed(report["s4"]))
        self.assertTrue(report["s4"]["fund1_read_only_shape"])
        self.assertEqual(report["s4"]["fund1_reservation_count"], 0)
        self.assertEqual(report["s4"]["fund1_raw_reservation_count"], 0)
        self.assertEqual(report["s4"]["fund4_raw_reservation_count"], 1)
        self.assertEqual(report["s4"]["fund4_reservation_count"], 0)
        self.assertGreater(report["s4"]["fund4_after_atoms"], report["s4"]["fund4_before_atoms"])
        self.assertEqual(approvals, [("S4_FUND1", "Approve"), ("S4_ENABLE", "Approve"),
                                    ("S4_FUND2", "Approve"), ("S4_FUND3", "Approve"),
                                    ("S4_SIGN", "Approve Sign"),
                                    ("S4_BROADCAST", "Approve Broadcast"),
                                    ("S4_CONFIRM", "Approve"), ("S4_FUND4", "Approve")])

    def test_specific_s4_failures_always_shutdown_and_never_accept_wrong_refusal(self):
        for fault, code in (
                ("button", "FUND_BUTTON_DISABLED"), ("balance", "BALANCE_NOT_INCREASED"),
                ("mainnet", "MAINNET_DENIED"), ("reservation", "UNEXPECTED_RESERVATION"),
                ("readonly_after_activation", "UNEXPECTED_RESERVATION"),
                ("state", "SPEND_STATE_CHANGED"), ("activation", "ACTIVATION_DENIED"),
                ("gui_enabled", "IN_FLIGHT_NOT_REFUSED"),
                ("backend_allowed", "IN_FLIGHT_NOT_REFUSED"),
                ("backend_wrong", "IN_FLIGHT_NOT_REFUSED"),
                ("signed_snapshot", "SIGNED_PAYMENT_MISSING"),
                ("history", "CONFIRMATION_DENIED"), ("confirmed", "CONFIRMATION_DENIED"),
                ("pending", "CONFIRMATION_DENIED"), ("post_button", "FUND_BUTTON_DISABLED"),
                ("missing_height", "CONFIRMATION_DENIED"),
                ("zero_height", "CONFIRMATION_DENIED"),
                ("null_height", "CONFIRMATION_DENIED"),
                ("post_fund", "BALANCE_NOT_INCREASED"),
                ("retained", "OWNER_RETAINED"), ("operation", "OPERATION_DENIED")):
            with self.subTest(fault=fault):
                report, _, error = self.run_s4(fault)
                self.assertIsNotNone(error)
                self.assertEqual(stage.failure_code(error), "Q06_FIX_S4_" + code)
                self.assertFalse(stage.s4_passed(report.get("s4")))
                if fault == "operation":
                    self.assertNotIn("inner_failure_code", report["s4"])

    def test_frozen_entry_runs_s4_before_final_command_q(self):
        with (patch.object(stage, "_identify"), patch.object(stage, "_require_cocoa"),
              patch("wam_regtest.q05_platforms.DarwinArm64Adapter"),
              patch.object(stage, "scenario_repeat_funding") as s4,
              patch.object(stage, "drive") as drive):
            stage.run(Path("core"), Path("wsp"))
            steps = drive.call_args.args[0]
            self.assertEqual([key for key, _ in steps], ["S1", "S2", "S4", "S3"])
            report = {}
            steps[2][1](report)
            self.assertIs(s4.call_args.args[-1], report)


class FixScenarioArithmetic(unittest.TestCase):
    def test_confirmed_payment_requires_real_history_row_height(self):
        txid = "bb" * 32
        good = [{"txid": txid, "atoms": 100_000_000, "height": 101}]
        self.assertTrue(stage.confirmed_payment_in_history(txid, good, 101))
        self.assertFalse(stage.confirmed_payment_in_history(txid, [], 101))
        self.assertFalse(stage.confirmed_payment_in_history(
            txid, [{"txid": txid, "atoms": 100_000_000}], 101))
        self.assertFalse(stage.confirmed_payment_in_history(
            txid, [{"txid": txid, "atoms": 100_000_000, "height": 0}], 101))
        self.assertFalse(stage.confirmed_payment_in_history(
            txid, [{"txid": txid, "atoms": 100_000_000, "height": None}], 101))
        self.assertFalse(stage.confirmed_payment_in_history(
            txid, [{"txid": txid, "atoms": 100_000_000, "height": 102}], 101))
        self.assertFalse(stage.confirmed_payment_in_history(
            txid, [good[0], good[0]], 101))

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
            "scenarios": {"S1": "PASS", "S2": "PASS", "S3": "PASS", "S4": "PASS"},
            "s4": _s4_passing(),
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
            "scenarios": {"S1": "PASS", "S2": "FAIL", "S3": "NOT_RUN", "S4": "NOT_RUN"},
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
            "scenarios": {"S1": "FAIL", "S2": "NOT_RUN", "S3": "NOT_RUN", "S4": "NOT_RUN"},
            "failure_code": "INTERNAL",
            "failure_exception": "BrokenPipeError",
        })
        self.assertEqual(with_valid_exc["failure_exception"], "BrokenPipeError")

        with_null_exc = stage.public_evidence({
            "status": "FAIL",
            "scenarios": {"S1": "FAIL", "S2": "NOT_RUN", "S3": "NOT_RUN", "S4": "NOT_RUN"},
            "failure_code": "INTERNAL",
            "failure_exception": None,
        })
        self.assertNotIn("failure_exception", with_null_exc)

        for bad_exc in ("/Users/alice/secret", "1Bad", "A" * 65, "Err\n", 123):
            sanitized = stage.public_evidence({
                "status": "FAIL",
                "scenarios": {"S1": "FAIL", "S2": "NOT_RUN", "S3": "NOT_RUN", "S4": "NOT_RUN"},
                "failure_code": "INTERNAL",
                "failure_exception": bad_exc,
            })
            self.assertNotIn("failure_exception", sanitized)

    def test_public_evidence_whitelists_only_code_shaped_inner_diagnostic(self):
        raw = {
            "status": "FAIL",
            "scenarios": {"S1": "PASS", "S2": "PASS", "S3": "PASS", "S4": "FAIL"},
            "s4": dict(_s4_passing(), inner_failure_code="Q06_FIX_S4_CONFIRMATION_DENIED"),
            "failure_code": "Q06_FIX_S4_OPERATION_DENIED",
        }
        evidence = stage.public_evidence(raw)
        self.assertEqual(evidence["s4"]["inner_failure_code"], "Q06_FIX_S4_CONFIRMATION_DENIED")
        raw["s4"]["inner_failure_code"] = "secret never copied"
        evidence = stage.public_evidence(raw)
        self.assertNotIn("inner_failure_code", evidence["s4"])

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
                    (("S1", s1), ("S2", s2), ("S4", lambda report: report.update(s4=_s4_passing())),
                     ("S3", s3)),
                    {"frozen": False, "source_sha": "b" * 40, "network": "regtest",
                     "mainnet_allowed": False},
                    evidence_path=path)
            text = buffer.getvalue()
            self.assertEqual(code, 0)
            for marker in ("START", "S1_PASS", "S2_PASS", "S3_PASS", "S4_PASS", "ALL_PASS"):
                self.assertIn("MACOS_Q06_FIX_STAGE=" + marker, text)
            self.assertNotIn("MACOS_Q06_FIX_STAGE=DENIED", text)
            evidence = json.loads(path.read_text())
            self.assertEqual(evidence["status"], "PASS")
            self.assertEqual(evidence["scenarios"], {"S1": "PASS", "S2": "PASS", "S3": "PASS", "S4": "PASS"})
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
            self.assertEqual(evidence["scenarios"], {"S1": "FAIL", "S2": "NOT_RUN", "S3": "NOT_RUN", "S4": "NOT_RUN"})
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
                "S3_COMMAND_Q_NO_ROUTE_PASS", "S4_CREATE_BACKUP_PASS", "S4_ENABLE_PASS",
                "S4_IN_FLIGHT_REFUSAL_PASS", "S4_SHUTDOWN_PASS", "ALL_PASS", "DENIED"):
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
        self.assertIn("data['scenarios']['S4'] == 'PASS'", window)
        self.assertIn("s4_passed(data.get('s4'))", window)
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
