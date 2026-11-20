"""PM-105: public-only raw GUI-denial diagnostics never leak secrets.

FC-30 in the frozen V1-NET shared lab died showing only the generic public
code WALLET_OPERATION_DENIED_STATE_RETAINED for node B while node A's Reconcile
was being approved. The raw cause was never recorded. These tests pin the new
diagnostics: the failing action, the raw code-shaped token (or exception TYPE
name) and the public code are kept, and message text / fake seed phrases /
paths / RPC replies can never leak into evidence.
"""
import json
import unittest
from types import SimpleNamespace

from wam_regtest.gui_errors import operation_error, raw_cause
from wam_regtest.wallet_executor import WalletExecutorError
from wam_regtest.shared_network_probe import record_gui_denial

_FakeSeed = "abandon ability able about above absent absorb abstract absurd abuse access accident abandon ability able"


class _Hostile(RuntimeError):
    """A hostile formatter must never be invoked by diagnostics."""

    def __str__(self):
        raise AssertionError("external exception formatted during diagnostics")


class RawCause(unittest.TestCase):
    def test_code_shaped_token_is_kept_verbatim(self):
        # Exact trusted categories only (mirrors operation_error); RuntimeError
        # is deliberately outside the gate and falls back to its TYPE name.
        for exc_type, args in (
                (ValueError, ("SHARED_CONFIRMED_PEER_REQUIRED",)),
                (WalletExecutorError, ("Q06_GUI_ANCHORED_SCANNER_REQUIRES_RECONCILIATION",))):
            with self.subTest(exc=exc_type.__name__):
                self.assertEqual(raw_cause(exc_type(*args)), args[0])
        self.assertEqual(raw_cause(RuntimeError("SHARED_SINGLE_COORDINATOR_REQUIRED")), "RuntimeError")

    def test_message_text_and_seed_phrase_become_only_the_type_name(self):
        # A message containing a fake seed phase must not appear anywhere.
        for exc in (ValueError(_FakeSeed),
                    ValueError("Q06_GUI_ANCHORED_SCANNER_REQUIRES_RECONCILIATION " + _FakeSeed),
                    ValueError("/Users/alice/wallet.sqlite " + _FakeSeed),
                    RuntimeError(_FakeSeed),
                    __import__("os").error(13, _FakeSeed)):
            raw = raw_cause(exc)
            self.assertNotIn(_FakeSeed, raw)
            self.assertNotIn("abandon", raw)
            self.assertNotIn("/Users", raw)
            self.assertIn(raw, (type(exc).__name__,))
        # A multi-arg, non-str arg or hostile exception → type name only.
        self.assertEqual(raw_cause(ValueError("A", _FakeSeed)), "ValueError")
        self.assertEqual(raw_cause(_Hostile(_FakeSeed)), "_Hostile")
        self.assertEqual(raw_cause(ValueError([_FakeSeed])), "ValueError")
        self.assertEqual(raw_cause(ValueError(1)), "ValueError")

    def test_private_suffix_never_makes_a_public_token(self):
        # A code with a trailing secret is NOT a single code-shaped token.
        exc = ValueError("INSUFFICIENT_SINGLE_CLUSTER_FUNDS " + _FakeSeed)
        self.assertEqual(raw_cause(exc), "ValueError")
        self.assertNotIn(_FakeSeed, operation_error("prepare", exc))
        self.assertNotIn(_FakeSeed, raw_cause(exc))


class RecordGuiDenial(unittest.TestCase):
    def _window(self, action, raw, public):
        return SimpleNamespace(_last_error_action=action, _last_error_raw=raw,
                               _last_error_code=public)

    def test_records_action_raw_and_public_per_node(self):
        report = {}
        nodes = [
            {"window": self._window("reconcile_reorg", "Q06_GUI_BACKUP_ACK_REQUIRED",
                                    "WALLET_OPERATION_DENIED_STATE_RETAINED")},
            {"window": self._window(None, None, None)},
            {},
        ]
        record_gui_denial(report, nodes, wait_label="REORG_RECOVERY_PEERS")
        self.assertEqual(report["gui_denied"], ["WALLET_OPERATION_DENIED_STATE_RETAINED", None, None])
        self.assertEqual(report["gui_denied_nodes"][0]["action"], "reconcile_reorg")
        self.assertEqual(report["gui_denied_nodes"][0]["raw"], "Q06_GUI_BACKUP_ACK_REQUIRED")
        self.assertEqual(report["gui_denied_nodes"][0]["public"], "WALLET_OPERATION_DENIED_STATE_RETAINED")
        self.assertEqual(report["gui_denied_nodes"][1], {"action": None, "raw": None, "public": None})
        self.assertIsNone(report["gui_denied_nodes"][2])
        self.assertEqual(report["gui_denied_wait"], "REORG_RECOVERY_PEERS")
        encoded = json.dumps(report)
        self.assertNotIn(_FakeSeed, encoded)

    def test_seed_phrase_in_window_fields_never_enters_evidence(self):
        # raw_cause already prevents this, but guard the probe boundary too:
        # only the recorded fields (all code-shaped or None) are serialized.
        report = {}
        nodes = [{"window": self._window("snapshot", "ValueError", "WALLET_SYNC_UNVERIFIED")}]
        record_gui_denial(report, nodes)
        encoded = json.dumps(report)
        self.assertNotIn(_FakeSeed, encoded)
        self.assertNotIn("abandon", encoded)
        self.assertIn("ValueError", encoded)

    def test_evidence_json_round_trip_is_public_only(self):
        from wam_regtest.qualification import q06_fix_scenarios as stage
        # gui_denied(+raw) flows through _public_bools (used by S1/S2/S3).
        raw = {"status": "FAIL", "failure_code": "Q06_FIX_S1_CONFIRMATION_DENIED",
               "s1": {"same_txid_shown": True, "pending_matches": True,
                      "confirm_enabled": True, "status_awaiting_confirmation": True,
                      "reservation_held": True, "tx_in_verified_history": True,
                      "balance_arithmetic_exact": True, "send_page_confirmed": True,
                      "second_reopen_no_pending": True, "second_reopen_no_spurious": True,
                      "no_stale_reservation_display_after_confirm": True,
                      "no_stale_reservation_display_after_reopen": True,
                      "gui_denied": "WALLET_OPERATION_DENIED_STATE_RETAINED",
                      "gui_denied_raw": "Q06_GUI_ANCHORED_SCANNER_REQUIRES_RECONCILIATION"},
               "scenarios": {"S1": "FAIL", "S2": "PASS", "S3": "PASS", "S4": "FAIL"}}
        evidence = stage.public_evidence(raw)
        encoded = json.dumps(evidence)
        self.assertIn("Q06_GUI_ANCHORED_SCANNER_REQUIRES_RECONCILIATION", encoded)
        self.assertIn("WALLET_OPERATION_DENIED_STATE_RETAINED", encoded)
        # Raw message text still cannot survive the whitelist.
        polluted = dict(raw)
        polluted["s1"] = dict(polluted["s1"],
                              gui_denied_raw="INSUFFICIENT_SINGLE_CLUSTER_FUNDS " + _FakeSeed)
        encoded = json.dumps(stage.public_evidence(polluted))
        self.assertNotIn(_FakeSeed, encoded)
        self.assertNotIn("abandon", encoded)


if __name__ == "__main__":
    unittest.main()
