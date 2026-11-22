"""Network-aware automatic fee policy: a pure decision component.

Owner directive (2026-11-13, REGTEST now; network-neutral):
docs/product/AUTOMATIC-FEE-DIRECTIVE.md and FEE-0-AUDIT-AND-POLICY-SPEC.md.

This module has no RPC, no Qt, no wallet state and no binary floating point.
It receives the already-fetched Core policy responses (JSON numbers as
Decimal, exactly as both RPC clients parse them), validates them and returns
either a FeeQuote or a typed refusal (FeePolicyError). The selected network
supplies every value; nothing here is a market constant.

Rules:
  * Rates are integers in atoms per 1000 virtual bytes (atoms/kvB).
    1 coin = 100,000,000 atoms. A Core rate in coin/kvB must convert
    exactly (at most 8 decimals) or the input is refused.
  * Floor = max(mempoolminfee, minrelaytxfee, relayfee). incrementalfee is
    replacement/eviction policy and is NOT added to new transactions.
    relayfee is an extra input beyond the maintainer's two-floor rule; it
    equals minrelaytxfee on v0.1.13 and can only raise the effective floor.
  * The estimator (estimatesmartfee, with estimaterawfee as diagnostic
    evidence) is classified UNAVAILABLE, UNVALIDATED or USABLE from all
    the evidence together. An empty mempool alone does not decide it.
    Exact rules (classify_estimator): UNAVAILABLE when no target in
    ESTIMATE_TARGETS has a feerate without errors. Otherwise UNVALIDATED if
    any of: some target unavailable; all available targets report one
    identical rate; a rate equals Core's default fallback; estimaterawfee for
    QUOTE_TARGET is missing; its short horizon is missing, has errors or has
    no 'pass' bucket; the largest pass.totalconfirmed among error-free
    horizons of QUOTE_TARGET is below ESTIMATOR_MIN_CONFIRMED_SAMPLES.
    Only QUOTE_TARGET's raw evidence is read (target 25 legitimately has
    no short horizon). Else USABLE.
  * Selected rate: exactly 2 * effective floor, with no margin. Estimator
    classification, reasons and digest remain evidence only by default.
    Allowing a USABLE estimator to raise this rate is an owner decision;
    ALLOW_USABLE_ESTIMATOR_TO_RAISE_RATE is OFF.
  * fee_atoms = ceil(vsize * rate / 1000), integer arithmetic only.
  * Anything missing, mistyped, contradictory or unverifiable fails closed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal

ATOMS_PER_COIN = 100_000_000
# Core rejects maxfeerate above 1 coin/kvB; no sane policy rate can exceed it.
MAX_RATE_ATOMS_PER_KVB = ATOMS_PER_COIN
# WSP refuses any absolute fee outside 1..1,000,000 atoms (wam_sp wallet.propose).
MAX_FEE_ATOMS = 1_000_000
ESTIMATE_TARGETS = (2, 6, 25)
QUOTE_TARGET = 6
# Core v0.1.13 DEFAULT_FALLBACK_FEE as reported by the WAM maintainer (a code
# constant, not a market measurement). An estimate equal to it is not evidence.
CORE_DEFAULT_FALLBACK_FEE_ATOMS_PER_KVB = 20_000

# --- Owner decisions pending (FEE-0 section 8); conservative provisional values.
# FE-002: exact integer multiplier; no additive or hidden margin.
FLOOR_MULTIPLIER = 2
# OFF pending owner authorization. Estimator evidence never lowers the target.
ALLOW_USABLE_ESTIMATOR_TO_RAISE_RATE = False
# Minimum confirmed samples in the horizon used before an estimate can count as
# USABLE. The maintainer observed about 43.93 medium-horizon samples, largely
# self-referential pool payouts; this threshold keeps such evidence UNVALIDATED.
ESTIMATOR_MIN_CONFIRMED_SAMPLES = Decimal(100)
# Proportional limit (PEER-098 #6): a fee above the amount itself is refused;
# otherwise a fee above max(10% of the amount, the floor fee for this exact size)
# is refused. The floor fee is the network minimum, so it is never "excess".
DISPROPORTIONATE_PERCENT = 10

UNAVAILABLE = 'UNAVAILABLE'
UNVALIDATED = 'UNVALIDATED'
USABLE = 'USABLE'
SOURCE_FLOOR_2X = 'NETWORK_FLOOR_2X'
SOURCE_ESTIMATOR = 'ESTIMATOR'


class FeePolicyError(ValueError):
    """Typed refusal; args[0] is a public code token."""


def _refuse(code):
    raise FeePolicyError(code)


def coin_rate_to_atoms_per_kvb(value):
    """Exact Decimal/int coin-per-kvB rate to integer atoms/kvB, or refuse.

    Pure integer arithmetic on the Decimal's sign, digits and exponent, so the
    result never depends on the active decimal context (precision, rounding,
    traps): PEER-099. Special values, negative non-zero values,
    fractional atoms and out-of-range values are typed refusals.
    """
    if type(value) is bool or not isinstance(value, (Decimal, int)):
        _refuse('FEE_POLICY_RATE_TYPE')  # floats and strings are never accepted
    if type(value) is int:
        if value < 0:
            _refuse('FEE_POLICY_RATE_RANGE')
        if value > MAX_RATE_ATOMS_PER_KVB // ATOMS_PER_COIN:
            _refuse('FEE_POLICY_RATE_RANGE')
        return value * ATOMS_PER_COIN
    sign, digits, exponent = value.as_tuple()
    if type(exponent) is not int:  # 'n' (NaN), 'N' (sNaN), 'F' (Infinity)
        _refuse('FEE_POLICY_RATE_PRECISION')
    coefficient = 0
    for digit in digits:
        coefficient = coefficient * 10 + digit
    if coefficient == 0:
        return 0  # any zero, including -0 and 0E-999999999
    if sign:
        _refuse('FEE_POLICY_RATE_RANGE')
    shift = exponent + 8  # atoms = coefficient * 10**shift
    # Magnitude bound before any power of ten: the value has
    # len(digits) + shift integer digits in atoms; the maximum has 9.
    if len(digits) + shift > 9:
        _refuse('FEE_POLICY_RATE_RANGE')
    if shift >= 0:
        atoms = coefficient * 10 ** shift
    else:
        if -shift > len(digits):
            _refuse('FEE_POLICY_RATE_PRECISION')  # non-zero below one atom
        atoms, remainder = divmod(coefficient, 10 ** -shift)
        if remainder:
            _refuse('FEE_POLICY_RATE_PRECISION')
    if not 0 <= atoms <= MAX_RATE_ATOMS_PER_KVB:
        _refuse('FEE_POLICY_RATE_RANGE')
    return atoms


def fee_for_vsize(vsize, rate_atoms_per_kvb):
    """ceil(vsize * rate / 1000) in integers."""
    if type(vsize) is not int or vsize <= 0:
        _refuse('FEE_POLICY_VSIZE')
    if type(rate_atoms_per_kvb) is not int or not 0 < rate_atoms_per_kvb <= MAX_RATE_ATOMS_PER_KVB:
        _refuse('FEE_POLICY_RATE_RANGE')
    return (vsize * rate_atoms_per_kvb + 999) // 1000


@dataclass(frozen=True)
class SmartEstimate:
    target: int
    rate: int | None          # atoms/kvB, None when Core returned no feerate
    errors: tuple[str, ...]
    blocks: int | None


@dataclass(frozen=True)
class RawHorizon:
    name: str
    rate: int | None
    errors: tuple[str, ...]
    pass_confirmed: Decimal | None   # 'pass'.totalconfirmed, None without a pass bucket


@dataclass(frozen=True)
class PolicyInputs:
    network: str
    core_version: int
    relayfee: int
    mempoolminfee: int
    minrelaytxfee: int
    smart: tuple[SmartEstimate, ...]
    raw: tuple[tuple[int, tuple[RawHorizon, ...]], ...]
    raw_malformed: tuple[int, ...] = ()

    def digest(self):
        """Stable provenance digest of every value the quote depends on,
        including the raw estimator evidence used by the classification
        (PEER-099). Sign-time validity is quote_still_valid, not equality
        of this digest: an approved fee stays fixed while it covers the floor."""
        payload = json.dumps(dict(
            network=self.network, core_version=self.core_version, relayfee=self.relayfee,
            mempoolminfee=self.mempoolminfee, minrelaytxfee=self.minrelaytxfee,
            smart=[(s.target, s.rate, list(s.errors), s.blocks) for s in self.smart],
            raw=[(target, [(h.name, h.rate, list(h.errors),
                            None if h.pass_confirmed is None else str(h.pass_confirmed))
                           for h in horizons]) for target, horizons in self.raw],
            raw_malformed=list(self.raw_malformed)), sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    @property
    def floor(self):
        return max(self.mempoolminfee, self.minrelaytxfee, self.relayfee)


def _require_dict(value):
    if type(value) is not dict:
        _refuse('FEE_POLICY_UNVERIFIED')
    return value


def _errors(container):
    errors = container.get('errors', [])
    if type(errors) is not list or any(type(e) is not str for e in errors):
        _refuse('FEE_POLICY_UNVERIFIED')
    return tuple(errors)


def parse_policy_inputs(network, networkinfo, mempoolinfo, smart_by_target, raw_by_target):
    """Validate raw RPC results (as returned by the client) into PolicyInputs."""
    if type(network) is not str or not network:
        _refuse('FEE_POLICY_NETWORK')
    networkinfo = _require_dict(networkinfo)
    mempoolinfo = _require_dict(mempoolinfo)
    version = networkinfo.get('version')
    if type(version) is not int:
        _refuse('FEE_POLICY_UNVERIFIED')
    if mempoolinfo.get('loaded') is not True:
        _refuse('FEE_POLICY_MEMPOOL_NOT_LOADED')
    for name, source in (('relayfee', networkinfo), ('mempoolminfee', mempoolinfo),
                         ('minrelaytxfee', mempoolinfo)):
        if name not in source:
            _refuse('FEE_POLICY_UNVERIFIED')
    relayfee = coin_rate_to_atoms_per_kvb(networkinfo['relayfee'])
    mempoolminfee = coin_rate_to_atoms_per_kvb(mempoolinfo['mempoolminfee'])
    minrelaytxfee = coin_rate_to_atoms_per_kvb(mempoolinfo['minrelaytxfee'])
    if min(relayfee, mempoolminfee, minrelaytxfee) <= 0:
        _refuse('FEE_POLICY_FLOOR_MISSING')
    if mempoolminfee < minrelaytxfee:
        # Core never reports a dynamic minimum below its static relay minimum.
        _refuse('FEE_POLICY_CONTRADICTORY')
    smart = []
    if set(smart_by_target) != set(ESTIMATE_TARGETS):
        _refuse('FEE_POLICY_UNVERIFIED')
    for target in ESTIMATE_TARGETS:
        entry = _require_dict(smart_by_target[target])
        rate = coin_rate_to_atoms_per_kvb(entry['feerate']) if 'feerate' in entry else None
        # v0.1.13 always returns 'blocks' (0 when no estimate): required.
        blocks = entry.get('blocks')
        if type(blocks) is not int or not 0 <= blocks <= 1008:
            _refuse('FEE_POLICY_UNVERIFIED')
        smart.append(SmartEstimate(target, rate, _errors(entry), blocks))
    raw, malformed = [], []
    for target in sorted(raw_by_target):
        entry = raw_by_target[target]
        if entry is None:  # diagnostic interface; absence is recorded, not fatal
            raw.append((target, ()))
            continue
        try:
            raw.append((target, _raw_horizons(entry)))
        except FeePolicyError:
            # estimaterawfee is diagnostic evidence: a malformed reply can only
            # weaken the classification (RAW_EVIDENCE_MALFORMED), never abort
            # the floor quote and never count as evidence.
            raw.append((target, ()))
            malformed.append(target)
    return PolicyInputs(network, version, relayfee, mempoolminfee, minrelaytxfee,
                        tuple(smart), tuple(raw), tuple(malformed))


MAX_SAMPLE_COUNT = Decimal(10) ** 12


def _sample_count(value):
    """A finite, non-negative, bounded decayed sample count (Decimal or int)."""
    if type(value) is bool or not isinstance(value, (Decimal, int)):
        _refuse('FEE_POLICY_UNVERIFIED')
    if type(value) is int:
        value = Decimal(value)
    if not value.is_finite() or value.is_signed() and value != 0 or value > MAX_SAMPLE_COUNT:
        _refuse('FEE_POLICY_UNVERIFIED')
    return value


def _raw_horizons(entry):
    horizons = []
    for name in ('short', 'medium', 'long'):
        if name not in _require_dict(entry):
            continue
        horizon = _require_dict(entry[name])
        rate = coin_rate_to_atoms_per_kvb(horizon['feerate']) if 'feerate' in horizon else None
        bucket = horizon.get('pass')
        confirmed = None
        if bucket is not None:
            confirmed = _sample_count(_require_dict(bucket).get('totalconfirmed'))
        horizons.append(RawHorizon(name, rate, _errors(horizon), confirmed))
    return tuple(horizons)


def classify_estimator(inputs):
    """(classification, reasons): evidence weighed together, never one signal alone."""
    reasons = []
    rated = [s for s in inputs.smart if s.rate is not None and not s.errors]
    if not rated:
        return UNAVAILABLE, ('NO_FEERATE_WITHOUT_ERRORS',)
    if any(s.errors or s.rate is None for s in inputs.smart):
        reasons.append('SOME_TARGETS_UNAVAILABLE')
    rates = {s.rate for s in rated}
    if len(rated) > 1 and len(rates) == 1:
        reasons.append('HORIZONS_IDENTICAL')
    if CORE_DEFAULT_FALLBACK_FEE_ATOMS_PER_KVB in rates:
        reasons.append('EQUALS_CORE_FALLBACK')
    raw = dict(inputs.raw)
    quote_raw = raw.get(QUOTE_TARGET)
    if QUOTE_TARGET in inputs.raw_malformed:
        reasons.append('RAW_EVIDENCE_MALFORMED')
    elif not quote_raw:
        reasons.append('RAW_EVIDENCE_MISSING')
    else:
        horizons = {h.name: h for h in quote_raw}
        short = horizons.get('short')
        if short is None or short.errors or short.pass_confirmed is None:
            reasons.append('SHORT_HORIZON_INSUFFICIENT')
        used = [h for h in quote_raw if not h.errors and h.pass_confirmed is not None]
        if not used or max(h.pass_confirmed for h in used) < ESTIMATOR_MIN_CONFIRMED_SAMPLES:
            reasons.append('SAMPLES_BELOW_THRESHOLD')
    return (UNVALIDATED if reasons else USABLE), tuple(reasons)


@dataclass(frozen=True)
class FeeQuote:
    network: str
    rate_atoms_per_kvb: int
    floor_atoms_per_kvb: int
    source: str
    estimator: str
    reasons: tuple[str, ...]
    inputs_digest: str


def quote(inputs):
    """The automatic fee rate for a new transaction, with its provenance."""
    floor = inputs.floor
    classification, reasons = classify_estimator(inputs)
    rate, source = FLOOR_MULTIPLIER * floor, SOURCE_FLOOR_2X
    if ALLOW_USABLE_ESTIMATOR_TO_RAISE_RATE and classification == USABLE:
        estimate = next(s.rate for s in inputs.smart if s.target == QUOTE_TARGET)
        if estimate is not None and estimate > rate:
            rate, source = estimate, SOURCE_ESTIMATOR
    if not 0 < rate <= MAX_RATE_ATOMS_PER_KVB:
        _refuse('FEE_POLICY_RATE_RANGE')
    return FeeQuote(inputs.network, rate, floor, source, classification, reasons, inputs.digest())


def check_fee_limits(fee_atoms, amount_atoms, vsize, quote_):
    """Refuse excessive or disproportionate fees before any review is shown."""
    if type(fee_atoms) is not int or type(amount_atoms) is not int or amount_atoms <= 0:
        _refuse('FEE_POLICY_UNVERIFIED')
    if not 1 <= fee_atoms <= MAX_FEE_ATOMS:
        _refuse('FEE_ABSOLUTE_LIMIT')
    floor_fee = fee_for_vsize(vsize, quote_.floor_atoms_per_kvb)
    if fee_atoms < floor_fee:
        _refuse('FEE_BELOW_NETWORK_FLOOR')
    if fee_atoms > amount_atoms:
        _refuse('FEE_EXCEEDS_AMOUNT')
    if fee_atoms > max(amount_atoms * DISPROPORTIONATE_PERCENT // 100, floor_fee):
        _refuse('FEE_DISPROPORTIONATE')


def quote_still_valid(quote_, fresh_inputs):
    """Before Sign: same network and the approved rate still meets the floor."""
    return (fresh_inputs.network == quote_.network
            and fresh_inputs.floor <= quote_.rate_atoms_per_kvb)
