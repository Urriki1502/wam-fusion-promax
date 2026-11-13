"""Pure oracles and public evidence for source-only FEE-3 qualification.

No wallet authority lives here. A schema describes ORIGINAL RPC JSON types;
Decimal strings are storage, never evidence that Core returned a string.
Unrecognized RPC text is hashed, never copied into public evidence.
"""
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
import re


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
    if set(results) != {f.name for f in FIXTURES}:
        return "BLOCKED"
    if "FAIL" in results.values():
        return "FAIL"
    return "PASS" if all(v == "PASS" for v in results.values()) else "BLOCKED"


def proposal_trace_holds(fees):
    if not 1 <= len(fees) <= 6 or any(type(f) is not int or f <= 0 for f in fees):
        return False
    drops = [i for i in range(1, len(fees)) if fees[i] < fees[i-1]]
    if not drops:
        return len(fees) <= 4
    i = drops[0]
    return (len(drops) == 1 and i <= 4 and len(fees) <= i + 2
            and (len(fees) == i + 1 or fees[-1] == fees[i-1]))


def assert_tma(response, vsize, fee, txid, wtxid):
    checks = {"single_response": type(response) is list and len(response) == 1}
    row = response[0] if checks["single_response"] and type(response[0]) is dict else {}
    fees = row.get("fees") if type(row.get("fees")) is dict else {}
    try:
        base = exact_atoms(fees.get("base"))
    except (ValueError, OverflowError):
        base = None
    try:
        rate = exact_atoms(fees.get("effective-feerate"))
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
        return common | QUOTE_ASSERTIONS | {"unsigned_cancel_releases", "no_sign_or_submit", "no_mempool_change"}
    return common | QUOTE_ASSERTIONS | POSITIVE_ASSERTIONS


def valid_pass_result(result):
    """Fail-closed PASS report contract, independent of runner control flow."""
    def digest(value, length=64):
        return type(value) is str and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None

    try:
        fixture = next(f for f in FIXTURES if f.name == result["fixture"] and f.case == result["case_id"])
        source, core = result["source"], result["core"]
        required = required_assertions(fixture)
        from datetime import datetime
        start, end = (datetime.fromisoformat(result[k]) for k in ("started_utc", "ended_utc"))
        return (result["schema"] == "wam-fee3-source/v1" and result["status"] == "PASS"
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
