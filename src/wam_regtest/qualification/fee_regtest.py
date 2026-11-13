"""Pure oracles and public evidence for source-only FEE-3 qualification.

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
    "F3-11": "BLOCKED_OUTSIDE_STEP_RESTART_LOCK_SEAM_NOT_IMPLEMENTED",
    "F3-12": "BLOCKED_OUTSIDE_STEP_BROADCAST_UNCONFIRMED_RESTART_AND_CONFIRMATION",
    "F3-13": "BLOCKED_OUTSIDE_STEP_CANCEL_BEFORE_SIGN_AND_RECOVERED_UNSIGNED_CANCEL",
    "F3-14": "BLOCKED_OUTSIDE_STEP_UNCHANGED_SIGN_BROADCAST_SAFETY_INVARIANTS",
    "frozen": "BLOCKED_NO_FROZEN_MODE",
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


# The 155 initial fee is the reviewed FEE-2 contract, NOT a policy override.
# Runtime requires the measured floor to be 1000 for these exact fixtures.
FIXTURES = (
    Fixture("F3-01", "floor", (1_000_000,), 100_000),
    Fixture("F3-02", "change", (1_000_000,), 100_000),
    Fixture("F3-03", "exact", (100_155,), 100_000, vsize=112, change=0),
    Fixture("F3-03", "smaller-diagnostic", (100_112,), 100_000, refusal=True),
    Fixture("F3-04", "three-inputs", (100_000,)*3, 250_000, inputs=3, vsize=270),
    Fixture("F3-05", "recipient-329", (1_000_000,), 329, refusal=True),
    Fixture("F3-05", "recipient-330", (1_000_000,), 330),
    Fixture("F3-05", "recipient-331", (1_000_000,), 331),
    Fixture("F3-05", "change-329", (100_484,), 100_000, refusal=True),
    Fixture("F3-05", "change-330", (100_485,), 100_000, change=330),
    Fixture("F3-05", "change-331", (100_486,), 100_000, change=331),
    Fixture("F3-05", "oscillation", (100_155, 200_000), 100_000, vsize=112, change=0),
    Fixture("F3-06", "fee-unaffordable", (100_000,), 100_000, refusal=True),
    Fixture("F3-06", "affordable-control", (100_000,), 50_000),
    Fixture("F3-09", "positive", (1_000_000,), 100_000),
    # D-FEE2-2 characterization: 100_000 + 155 < 100_200 < 100_000 + 155 + 330
    # and no exact-remainder fee. Manifest must report OWNER DECISION PENDING, never PASS.
    Fixture("D-FEE2-2", "subdust-sweep-characterization", (100_200,), 100_000,
            refusal=True, characterization=True),
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
    """Verify durable draft save before sign, POLICY_READ -> MARK_SIGNED -> SAVE -> SIGN, and broadcast."""
    if not isinstance(events, list):
        return False
    try:
        sign_action = events.index("ACTION_SIGN")
        mark = events.index("MARK_SIGNED")
        sign = events.index("SIGN")
        broadcast_action = events.index("ACTION_BROADCAST")
        tma = events.index("TESTMEMPOOLACCEPT")
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
    broadcast_window = [e for e in events[broadcast_action:]
                        if e in ("TESTMEMPOOLACCEPT", "SAVE", "SENDRAWTRANSACTION")]
    return broadcast_window[:3] == ["TESTMEMPOOLACCEPT", "SAVE", "SENDRAWTRANSACTION"]


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
        # Core reports coin/kvB at atom precision. Permit only the adjacent
        # integer rounding of fee*1000/vsize, never a float tolerance.
        rate_holds = vsize > 0 and abs(rate*vsize - fee*1000) < vsize
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
    if fixture.refusal:
        return common | {"exact_refusal", "original_refusal", "no_state_change",
                         "no_sign_or_submit", "no_mempool_change"}
    if fixture.case == "F3-01":
        return common | QUOTE_ASSERTIONS | {
            "gui_sign_review", "gui_sign_cancel_default", "gui_no_manual_fee_field",
            "unsigned_cancel_releases", "no_sign_or_submit", "no_mempool_change",
        }
    return common | QUOTE_ASSERTIONS | POSITIVE_ASSERTIONS


def _valid_result_with_status(result, expected_status, expect_characterization):
    """Fail-closed report contract, independent of runner control flow."""
    def digest(value, length=64):
        return type(value) is str and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None

    try:
        fixture = next(f for f in FIXTURES if f.name == result["fixture"] and f.case == result["case_id"])
        source, core = result["source"], result["core"]
        required = required_assertions(fixture)
        from datetime import datetime
        start, end = (datetime.fromisoformat(result[k]) for k in ("started_utc", "ended_utc"))
        return (fixture.characterization is expect_characterization
            and result["schema"] == "wam-fee3-source/v1" and result["status"] == expected_status
            and result["test_layer"] == "REAL_CORE" and result["network"] == "regtest"
            and result["mainnet_allowed"] is False and result["exit_code"] == 0
            and start.tzinfo is not None and end.tzinfo is not None and end >= start
            and type(result["command"]) is list and bool(result["command"])
            and digest(source["sha"], 40) and digest(source["tree"], 40)
            and digest(source["inventory_sha256"]) and type(source["dirty_inventory"]) is list
            and core["signature_verified_now"] is True and digest(core["archive_sha256"])
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
            and result["cleanup"]["verified_original_owner_shutdown"] is True
            and result["cleanup"]["profile_retained"] is True
            and set(result["artifacts"]) == {"policy.json", "events.json", "tma.json"}
            and all(digest(v) for v in result["artifacts"].values()))
    except (KeyError, TypeError, ValueError, AttributeError, StopIteration):
        return False


def valid_pass_result(result):
    """Fail-closed PASS report contract, rejecting characterization fixtures."""
    return _valid_result_with_status(result, "PASS", False)


def valid_characterization_result(result):
    """Fail-closed characterization contract, never allowing PASS."""
    return _valid_result_with_status(result, CHARACTERIZATION_PENDING_STATUS, True)
