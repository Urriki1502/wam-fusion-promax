"""Pure oracles and public evidence for FEE-3 qualification.

No wallet authority lives here. A schema describes ORIGINAL RPC JSON types;
Decimal strings are storage, never evidence that Core returned a string.
Unrecognized RPC text is hashed, never copied into public evidence.
"""
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re

from . import valid_optional_failure_exception


CHARACTERIZATION_PENDING_STATUS = "OWNER DECISION PENDING (absorb sub-dust remainder vs refuse)"
INSUFFICIENT_DATA_ERROR_SHA256 = sha256(b"Insufficient data or no feerate found").hexdigest()
TMA_FLOAT_CONVERSION_NOTE = (
    "float-decoded by product transport; converted by shortest-repr with round-trip proof"
)
OUTSIDE_STEP = {
    "F3-07": "BLOCKED_STARTUP_SEAM_NOT_IMPLEMENTED",
    "F3-08": "BLOCKED_STARTUP_FILLER_SEAM_NOT_IMPLEMENTED",
    "F3-10": "BLOCKED_FILLER_SEAM_NOT_IMPLEMENTED",
    "F3-09-low-fee": "BLOCKED_OUTSIDE_STEP_POSITIVE_ONLY",
    "F3-14/remaining-authority-publication-duplicates": "BLOCKED_SIGN_BROADCAST_SAFETY_INVARIANTS_ADDITIONAL_SCENARIOS_NOT_IMPLEMENTED",
    # The source run never qualifies frozen bytes; --ci-fee-regtest does, in
    # the separate full macOS build (FROZEN_FEE3_REGTEST stage).
    "frozen": "BLOCKED_SEPARATE_FROZEN_BUILD_STAGE",
    "Windows/Linux": "BLOCKED_NATIVE_ADAPTER_NOT_IMPLEMENTED",
}


@dataclass(frozen=True)
class Fixture:
    case: str
    name: str
    coins: tuple[int, ...]
    amount: int
    refusal: bool = False
    inputs: int = 1
    vsize: int = 155
    change: int | None = None
    characterization: bool = False


# The 310 initial fee is the reviewed FEE-2 contract, NOT a policy override.
# Runtime requires the measured floor to be 1000 for these exact fixtures.
FIXTURES = (
    Fixture("F3-01", "floor", (1_000_000,), 100_000),
    Fixture("F3-02", "change", (1_000_000,), 100_000),
    Fixture("F3-03", "exact", (100_310,), 100_000, vsize=112, change=0),
    Fixture("F3-03", "smaller-diagnostic", (100_224,), 100_000, refusal=True),
    Fixture("F3-04", "three-inputs", (100_000,)*3, 250_000, inputs=3, vsize=270),
    Fixture("F3-05", "recipient-329", (1_000_000,), 329, refusal=True),
    Fixture("F3-05", "recipient-330", (1_000_000,), 330, refusal=True),
    Fixture("F3-05", "recipient-331", (1_000_000,), 331, refusal=True),
    Fixture("F3-05", "change-329", (100_639,), 100_000, refusal=True),
    Fixture("F3-05", "change-330", (100_640,), 100_000, change=330),
    Fixture("F3-05", "change-331", (100_641,), 100_000, change=331),
    Fixture("F3-05", "oscillation", (100_310, 200_000), 100_000, vsize=112, change=0),
    Fixture("F3-06", "fee-unaffordable", (100_000,), 100_000, refusal=True),
    Fixture("F3-06", "affordable-control", (100_000,), 50_000),
    Fixture("F3-09", "positive", (1_000_000,), 100_000),
    Fixture("F3-11", "signed-recovery", (1_000_000,), 100_000),
    Fixture("F3-12", "pending-recovery", (1_000_000,), 100_000),
    Fixture("F3-13", "fresh-cancel", (1_000_000,), 100_000),
    Fixture("F3-13", "recovered-cancel", (1_000_000,), 100_000),
    *(Fixture("F3-14", name, (1_000_000,), 100_000) for name in (
        "tamper-sign", "tamper-broadcast", "dismiss-sign", "close-sign",
        "dismiss-broadcast", "close-broadcast", "separate-approvals",
        "utxo-changed", "stale-quote", "crypto-failure", "lost-send-response")),
    # Owner-approved D-FEE2-2: 90 atoms of change must be refused with the
    # dedicated code, with the same no-side-effects assertions as F3 refusals.
    Fixture("D-FEE2-2", "subdust-sweep-characterization", (100_400,), 100_000,
            refusal=True),
)


def exact_atoms(value):
    """Independent exact numeric oracle; no Decimal context arithmetic."""
    if type(value) not in (int, Decimal):
        raise ValueError("F3_AMOUNT_TYPE")
    numerator, denominator = value.as_integer_ratio()
    atoms, remainder = divmod(numerator * 100_000_000, denominator)
    if remainder or atoms < 0:
        raise ValueError("F3_AMOUNT_PRECISION")
    return atoms


def json_capture(value):
    decimals = {}

    def visit(item, path):
        if item is None:
            return None, "null"
        if type(item) is bool:
            return item, "boolean"
        if type(item) is int:
            return item, "integer"
        if type(item) is Decimal and item.is_finite():
            decimals[path] = str(item)
            return str(item), "number"
        if type(item) is str:
            # Only transaction identities and exact version are public text.
            public = item if re.fullmatch(r"[0-9a-f]{64}|/WAM:0\.1\.13/", item) else {
                "text_sha256": sha256(item.encode()).hexdigest()}
            return public, "string"
        if type(item) is list:
            pairs = [visit(v, path + "/" + str(i)) for i, v in enumerate(item)]
            return [v for v, _ in pairs], [s for _, s in pairs]
        if type(item) is dict:
            if any(type(k) is not str or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", k)
                   or k.lower() in {"password", "seed", "mnemonic", "key", "raw", "psbt", "config"}
                   for k in item):
                raise ValueError("F3_PUBLIC_RPC_KEYS_DENIED")
            pairs = {k: visit(v, path + "/" + k) for k, v in item.items()}
            return {k: v for k, (v, _) in pairs.items()}, {k: s for k, (_, s) in pairs.items()}
        raise ValueError("F3_RPC_TYPE_DENIED")

    data, schema = visit(value, "")
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return {"response": data, "schema": schema, "decimals": decimals,
            "sha256": sha256(encoded.encode()).hexdigest()}


def _tma_float_to_decimal(value, *, require_whole_atoms):
    """Convert a transport-decoded float in a known TMA fee field to exact Decimal."""
    if type(value) is not float or not math.isfinite(value):
        raise ValueError("F3_RPC_TYPE_DENIED")
    if value < 0 or math.copysign(1.0, value) < 0:
        raise ValueError("F3_AMOUNT_PRECISION")
    converted = Decimal(repr(value))
    if not converted.is_finite() or float(converted) != value:
        raise ValueError("F3_TMA_FLOAT_ROUNDTRIP")
    if require_whole_atoms:
        exact_atoms(converted)
    return converted


def tma_capture(response):
    """Capture testmempoolaccept RPC reply, converting only fees.base and fees.effective-feerate floats."""
    converted_fields = {}
    normalized = response
    if type(response) is list:
        normalized = []
        for index, row in enumerate(response):
            if type(row) is dict and type(row.get("fees")) is dict:
                fees = dict(row["fees"])
                for field in ("base", "effective-feerate"):
                    if field in fees and type(fees[field]) is float:
                        fees[field] = _tma_float_to_decimal(
                            fees[field], require_whole_atoms=(field == "base"),
                        )
                        converted_fields[f"/{index}/fees/{field}"] = TMA_FLOAT_CONVERSION_NOTE
                row = {**row, "fees": fees}
            normalized.append(row)
    capture = json_capture(normalized)
    capture["float_decoded_fields"] = converted_fields
    return capture


def write_artifact(path, payload):
    """Create-only, owner-private artifacts, with digest of the exact bytes."""
    data = (json.dumps(payload, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    fd = os.open(Path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return sha256(data).hexdigest()


def assertions_pass(checks):
    return bool(checks) and all(v is True for v in checks.values())


def aggregate_status(results):
    expected = {
        f.name: (CHARACTERIZATION_PENDING_STATUS if f.characterization else "PASS")
        for f in FIXTURES
    }
    if set(results) != set(expected):
        return "BLOCKED"
    if "FAIL" in results.values():
        return "FAIL"
    return "PASS" if all(results[name] == status for name, status in expected.items()) else "BLOCKED"


def proposal_trace_holds(fees):
    """Accept monotone built traces, a single built drop, or one refused lower fee followed by restoration."""
    if not 1 <= len(fees) <= 6:
        return False
    refused = [i for i, item in enumerate(fees) if isinstance(item, dict)]
    if refused:
        if len(refused) != 1:
            return False
        i = refused[0]
        entry = fees[i]
        if (not 1 <= i <= 4 or len(fees) != i + 2
                or set(entry) != {"fee", "refused", "code"}
                or entry["refused"] is not True
                or entry["code"] != "WALLET_INPUT_FUNDS_UNAVAILABLE"
                or type(entry["fee"]) is not int or entry["fee"] <= 0):
            return False
        prefix = fees[:i]
        restored = fees[i + 1]
        if (any(type(f) is not int or f <= 0 for f in prefix)
                or any(prefix[k] < prefix[k - 1] for k in range(1, len(prefix)))
                or entry["fee"] >= prefix[-1]
                or type(restored) is not int or restored != prefix[-1]):
            return False
        return True
    if any(type(f) is not int or f <= 0 for f in fees):
        return False
    drops = [i for i in range(1, len(fees)) if fees[i] < fees[i-1]]
    if not drops:
        return len(fees) <= 4
    i = drops[0]
    return (len(drops) == 1 and 1 <= i <= 4 and len(fees) <= i + 2
            and (len(fees) == i + 1 or fees[-1] == fees[i-1]))


def sign_order_holds(events):
    """Verify durable draft save before sign, POLICY_READ -> MARK_SIGNED -> SAVE -> SIGN, and broadcast.

    Broadcast product path (exact source lines):
    - src/wam_regtest/wallet_session.py:718 -> :752 (WalletSession.broadcast ->
      _preflight_not_submitted): rpc.call("testmempoolaccept", [[raw]]) -> TESTMEMPOOLACCEPT
    - src/wam_regtest/wallet_session.py:724-726 (WalletSession.broadcast):
      mark_reservations_uncertain_before_submission(...) then self._save() -> SAVE
    - wsp-upstream/src/wam_sp/wallet.py:273 (Wallet.broadcast):
      rpc.call("testmempoolaccept", [[raw.hex()]]) -> TESTMEMPOOLACCEPT
    - wsp-upstream/src/wam_sp/wallet.py:277 (Wallet.broadcast):
      rpc.call("sendrawtransaction", [raw.hex()]) -> SENDRAWTRANSACTION
    - src/wam_regtest/wallet_session.py:729 (WalletSession.broadcast):
      self._save() -> SAVE
    """
    if not isinstance(events, list):
        return False
    if events.count("SENDRAWTRANSACTION") != 1:
        return False
    try:
        sign_action = events.index("ACTION_SIGN")
        mark = events.index("MARK_SIGNED")
        sign = events.index("SIGN")
        broadcast_action = events.index("ACTION_BROADCAST")
        tma = events.index("TESTMEMPOOLACCEPT", broadcast_action)
        send = events.index("SENDRAWTRANSACTION")
    except ValueError:
        return False
    if not (sign_action < mark < sign < broadcast_action < tma < send):
        return False
    if "SAVE" not in events[:sign_action]:
        return False
    pre_mark = events[sign_action:mark]
    if "POLICY_READ" not in pre_mark:
        return False
    sign_window = [e for e in events[sign_action:broadcast_action]
                   if e in ("MARK_SIGNED", "SAVE", "SIGN")]
    if sign_window != ["MARK_SIGNED", "SAVE", "SIGN"]:
        return False
    next_action = next(
        (i for i in range(broadcast_action + 1, len(events))
         if isinstance(events[i], str) and events[i].startswith("ACTION_")),
        len(events),
    )
    broadcast_window = [e for e in events[broadcast_action:next_action]
                        if e in ("TESTMEMPOOLACCEPT", "SAVE", "SENDRAWTRANSACTION")]
    return broadcast_window == [
        "TESTMEMPOOLACCEPT",
        "SAVE",
        "TESTMEMPOOLACCEPT",
        "SENDRAWTRANSACTION",
        "SAVE",
    ]


def confirmed_debit_holds(
    *,
    pre_confirmed_atoms,
    post_confirmed_atoms,
    post_available_atoms,
    amount,
    fee,
    selected_inputs,
    reservation_rows,
):
    """Verify post-confirm balance delta and one 'broadcast' row per selected input.

    WSP keeps confirmed payment rows in state 'broadcast' by design
    (wsp-upstream/src/wam_sp/wallet.py:280; src/wam_regtest/domain/payment_state.py:4-6).
    The table is keyed by outpoint (wsp-upstream/src/wam_sp/store.py:21), so
    every signed/broadcast selected input must have exactly that one row. A
    payment with NO matching row fails: the vacuous all([]) never passes.
    """
    if any(type(v) is not int for v in (
        pre_confirmed_atoms, post_confirmed_atoms, post_available_atoms, amount, fee
    )):
        return False
    if amount <= 0 or fee <= 0:
        return False
    if post_confirmed_atoms != pre_confirmed_atoms - amount - fee:
        return False
    if post_available_atoms != post_confirmed_atoms:
        return False
    if not isinstance(selected_inputs, (list, tuple)) or not selected_inputs:
        return False
    if not isinstance(reservation_rows, (list, tuple)):
        return False
    selected_outpoints = set()
    for coin in selected_inputs:
        if not isinstance(coin, dict):
            return False
        txid, vout = coin.get("txid"), coin.get("vout")
        if type(txid) is not str or type(vout) is not int:
            return False
        selected_outpoints.add((txid, vout))
    if len(selected_outpoints) != len(selected_inputs):
        return False
    payment_rows = {}
    for row in reservation_rows:
        if not isinstance(row, dict):
            return False
        outpoint = (row.get("txid"), row.get("vout"))
        if outpoint in selected_outpoints:
            payment_rows.setdefault(outpoint, []).append(row)
    if set(payment_rows) != selected_outpoints:
        return False
    return all(len(rows) == 1 and rows[0].get("state") == "broadcast"
               for rows in payment_rows.values())


def reopen_clean_holds(reopened, *, expected_confirmed_atoms, expected_reservation_count):
    """Verify reopened snapshot matches post-confirm balance with no attention-needing reservations."""
    from ..domain.payment_state import reservations_need_attention, reserved_rows_needing_attention
    if not isinstance(reopened, dict):
        return False
    states = reopened.get("reservation_states")
    state_counts = reopened.get("reservation_state_counts")
    if not isinstance(states, (list, tuple)) or not isinstance(state_counts, (list, tuple)):
        return False
    return (
        reopened.get("confirmed_atoms") == expected_confirmed_atoms
        and reopened.get("available_atoms") == expected_confirmed_atoms
        and reopened.get("reservation_count") == expected_reservation_count
        and not reservations_need_attention(states)
        and reserved_rows_needing_attention(state_counts) == 0
        and reopened.get("pending_confirm_txid") is None
        and reopened.get("payment_review") is None
        and reopened.get("payment_signed") is False
        and reopened.get("recovered_unsigned_cancel_available") is False
    )


def assert_tma(response, vsize, fee, txid, wtxid):
    checks = {"single_response": type(response) is list and len(response) == 1}
    row = response[0] if checks["single_response"] and type(response[0]) is dict else {}
    fees = row.get("fees") if type(row.get("fees")) is dict else {}
    try:
        base_value = fees.get("base")
        if type(base_value) is float:
            base_value = _tma_float_to_decimal(base_value, require_whole_atoms=True)
        base = exact_atoms(base_value)
    except (ValueError, OverflowError):
        base = None
    try:
        rate_value = fees.get("effective-feerate")
        if type(rate_value) is float:
            rate_value = _tma_float_to_decimal(rate_value, require_whole_atoms=False)
        rate = exact_atoms(rate_value)
        # Confirmed by FE-007 on v0.1.13.
        rate_holds = vsize > 0 and rate == (fee * 1000) // vsize
    except (ValueError, OverflowError):
        rate_holds = False
    checks.update(
        allowed=row.get("allowed") is True,
        vsize=type(row.get("vsize")) is int and row["vsize"] == vsize,
        txid=type(txid) is str and row.get("txid") == txid and bool(re.fullmatch(r"[0-9a-f]{64}", txid)),
        wtxid=type(wtxid) is str and row.get("wtxid") == wtxid and bool(re.fullmatch(r"[0-9a-f]{64}", wtxid)),
        base_fee=base == fee,
        effective_rate=rate_holds,
        effective_includes=fees.get("effective-includes") == [wtxid],
    )
    return checks


QUOTE_ASSERTIONS = {
    "unavailable_smart", "floor_quote", "structure", "exact_intent", "fee_covers_quote",
    "bounded_overpay", "bounded_proposals", "released_unsaved_drafts", "exact_change", "debit_available",
}
POSITIVE_ASSERTIONS = {
    "gui_sign_review", "gui_sign_cancel_default", "gui_broadcast_review",
    "gui_broadcast_cancel_default", "gui_no_manual_fee_field",
    "signed_reservations", "no_submission_before_approval", "final_quote_core_vsize",
    "witness_65_bytes", "input_output_fee_identity", "output_structure", "preflight_read_only",
    "exact_broadcast_txid", "broadcast_present", "confirmed_debit", "history_exact_debit",
    "one_sign_one_mark_one_submission", "sign_order", "reopen_clean",
    "tma_single_response", "tma_allowed", "tma_vsize", "tma_txid", "tma_wtxid",
    "tma_base_fee", "tma_effective_rate", "tma_effective_includes",
}


def required_assertions(fixture):
    common = {"confirmed_inventory", "empty_loaded_mempool", "observer_integrity"}
    if fixture.case == "F3-14":
        from .fee_regtest_safety import safety_assertions
        return common | QUOTE_ASSERTIONS | safety_assertions(fixture)
    if fixture.case in ("F3-11", "F3-12", "F3-13"):
        from .fee_regtest_recovery import recovery_assertions
        return common | QUOTE_ASSERTIONS | recovery_assertions(fixture)
    if fixture.refusal:
        return common | {"exact_refusal", "original_refusal", "no_state_change",
                         "no_sign_or_submit", "no_mempool_change"}
    if fixture.case == "F3-01":
        return common | QUOTE_ASSERTIONS | {
            "gui_sign_review", "gui_sign_cancel_default", "gui_no_manual_fee_field",
            "unsigned_cancel_releases", "no_sign_or_submit", "no_mempool_change",
        }
    return common | QUOTE_ASSERTIONS | POSITIVE_ASSERTIONS


FROZEN_RESULT_SCHEMA = "wam-fee3-frozen-case/v1"
FROZEN_TEST_LAYER = "FROZEN_QUALIFICATION"
FROZEN_SOURCE_KEYS = ("candidate_source_sha", "checkout_sha", "build_source_inventory_sha256",
                      "bundled_source_stamp_sha256", "frozen_executable_sha256")


def _digest(value, length=64):
    return type(value) is str and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None


def source_layer(result):
    from .fee_regtest_safety import FAULTS
    if result.get("case_id") == "F3-14" and result.get("fixture") in FAULTS:
        return "FAULT_INJECTED_REAL_CORE"
    return "REAL_CORE"


def _source_identity_holds(result):
    source, core = result["source"], result["core"]
    return (result["schema"] == "wam-fee3-source/v1" and result["test_layer"] == source_layer(result)
            and _digest(source["sha"], 40) and _digest(source["tree"], 40)
            and _digest(source["inventory_sha256"]) and type(source["dirty_inventory"]) is list
            and core["signature_verified_now"] is True and _digest(core["archive_sha256"]))


def _frozen_identity_holds(result):
    """Frozen bytes carry the embedded build stamp, never a git checkout.

    The signed archive is authenticated at build intake and not bundled, so a
    frozen case can only re-verify the bundled receipt and member pins now.
    """
    source, core = result["source"], result["core"]
    return (result["schema"] == FROZEN_RESULT_SCHEMA and result["test_layer"] == FROZEN_TEST_LAYER
            and type(source) is dict and set(source) == set(FROZEN_SOURCE_KEYS)
            and _digest(source["candidate_source_sha"], 40) and _digest(source["checkout_sha"], 40)
            and all(_digest(source[k]) for k in FROZEN_SOURCE_KEYS[2:])
            and core["bundle_receipt_verified_now"] is True
            and core["signature_verified_now"] is False
            and core["trust"] == "official-signed-v0.1.13" and _digest(core["archive_sha256"]))


def safety_layer_holds(fixture, result, layer):
    from .fee_regtest_safety import FAULTS
    if fixture.name in FAULTS:
        return layer == "source" and result.get("fault_boundary") == FAULTS[fixture.name]
    return "fault_boundary" not in result


def _valid_result_with_status(result, expected_status, expect_characterization, layer="source"):
    """Fail-closed report contract, independent of runner control flow."""
    digest = _digest

    try:
        fixture = next(f for f in FIXTURES if f.name == result["fixture"] and f.case == result["case_id"])
        core = result["core"]
        required = required_assertions(fixture)
        identity = {"source": _source_identity_holds, "frozen": _frozen_identity_holds}[layer]
        from datetime import datetime
        start, end = (datetime.fromisoformat(result[k]) for k in ("started_utc", "ended_utc"))
        return (fixture.characterization is expect_characterization
            and identity(result)
            and (fixture.case != "F3-14" or safety_layer_holds(fixture, result, layer))
            and result["status"] == expected_status
            and result["network"] == "regtest"
            and result["mainnet_allowed"] is False and result["exit_code"] == 0
            and start.tzinfo is not None and end.tzinfo is not None and end >= start
            and type(result["command"]) is list and bool(result["command"])
            and set(core["members"]) == {"wamd", "wam-cli"}
            and all(digest(v) for v in core["members"].values())
            and result["core_runtime"]["version"] == 113
            and result["core_runtime"]["peers"] == 0 and digest(result["core_runtime"]["genesis"])
            and result["core_runtime"]["chain"] == "regtest"
            and result["os"]["qt_platform"] == "cocoa" and result["os"]["arch"].lower() == "arm64"
            and result["wsp_source_commit"] == "ac55f13423620252bdbf848c7e8a280c3b84721e"
            and result["safe_startup_flags"] == [] and digest(result["profile_fixture_id"])
            and result["baseline"]["quote"]["floor_atoms_per_kvb"] == 1000
            and required <= set(result["assertions"]) and assertions_pass(result["assertions"])
            and (fixture.refusal or fixture.case in ("F3-01", "F3-13", "F3-14") or (
                type(result.get("confirmed_atoms")) is dict
                and set(result["confirmed_atoms"]) == {"pre", "post"}
                and type(result["confirmed_atoms"]["pre"]) is int
                and type(result["confirmed_atoms"]["post"]) is int
            ))
            and result["cleanup"]["verified_original_owner_shutdown"] is True
            and result["cleanup"]["profile_retained"] is True
            and set(result["artifacts"]) == {"policy.json", "events.json", "tma.json"}
            and all(digest(v) for v in result["artifacts"].values())
            and valid_optional_failure_exception(result))
    except (KeyError, TypeError, ValueError, AttributeError, StopIteration):
        return False


def valid_pass_result(result):
    """Fail-closed PASS report contract, rejecting characterization fixtures."""
    return _valid_result_with_status(result, "PASS", False)


def valid_characterization_result(result):
    """Fail-closed characterization contract, never allowing PASS."""
    return _valid_result_with_status(result, CHARACTERIZATION_PENDING_STATUS, True)


def valid_frozen_pass_result(result):
    """Same PASS contract as source, bound to the frozen build stamp instead of git."""
    return _valid_result_with_status(result, "PASS", False, layer="frozen")
