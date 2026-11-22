"""Read-only admission verification. Acceptance never authorizes submission."""
from decimal import Decimal
import re


# Confirmed by FE-007 on v0.1.13.
# Missing required fields on acceptance fail closed.
PREFLIGHT_REQUIRED_FIELDS = (
    'txid', 'wtxid', 'vsize', 'fees.base', 'fees.effective-feerate',
    'fees.effective-includes',
)
PREFLIGHT_REJECT_REASONS = {
    'min relay fee not met': 'FEE_POLICY_REJECTED',
    'insufficient fee': 'FEE_POLICY_REJECTED',
    'missing-inputs': 'INPUT_SPENT_OR_CONFLICTED',
    'replacement-adds-unconfirmed': 'CONFLICT_REJECTED',
    'non-final': 'POLICY_REJECTED',
    'max-fee-exceeded': 'POLICY_REJECTED',
    'txn-already-in-mempool': 'ALREADY_IN_MEMPOOL',
}


def _coin_atoms(value, expected):
    """Exact coin-to-atom conversion, independent of Decimal context/policy caps."""
    if type(value) not in (Decimal, int):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    sign, digits, exponent = Decimal(value).as_tuple()
    if type(exponent) is not int:
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    coefficient = 0
    for digit in digits:
        coefficient = coefficient * 10 + digit
    if coefficient == 0:
        return 0
    shift = exponent + 8
    # Bound exponent work by the committed value's magnitude, rather than
    # adding a fee-policy cap to this equality check.
    if (sign or len(digits) + shift > len(str(expected))
            or -shift > len(digits)):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    if shift >= 0:
        return coefficient * 10**shift
    atoms, remainder = divmod(coefficient, 10**-shift)
    if remainder:
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    return atoms


def verify_preflight(reply, *, txid, wtxid, vsize, fee_atoms,
                     quoted_rate_atoms_per_kvb=None):
    """Return None for verified acceptance, a fixed token for rejection.

    Raises on verification failure (caller latches). Rejections need no economic
    fields and never latch. Tokens are internal diagnostics; callers retain the
    existing public rejection code. No raw Core reason leaves this boundary.
    This function writes no state and grants no broadcast authority.
    """
    if (type(reply) is not list or len(reply) != 1 or type(reply[0]) is not dict
            or type(reply[0].get('allowed')) is not bool):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    item = reply[0]
    if item['allowed'] is False:
        reason = item.get('reject-reason')
        return (PREFLIGHT_REJECT_REASONS.get(reason, 'POLICY_REJECTED')
                if type(reason) is str else 'POLICY_REJECTED')
    fields = {}
    for path in PREFLIGHT_REQUIRED_FIELDS:
        value = item
        for key in path.split('.'):
            if type(value) is not dict or key not in value:
                raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
            value = value[key]
        fields[path] = value
    if (type(fields['txid']) is not str
            or re.fullmatch('[0-9a-fA-F]{64}', fields['txid']) is None
            or fields['txid'] != txid):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    if (type(fields['wtxid']) is not str or fields['wtxid'] != wtxid
            or fields['fees.effective-includes'] != [wtxid]):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    if type(fields['vsize']) is not int or fields['vsize'] != vsize:
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    # Context-independent exact integer Decimal math; floats/strings refused.
    base = fields['fees.base']
    rate = fields['fees.effective-feerate']
    if type(base) not in (Decimal, int) or type(rate) not in (Decimal, int):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    if _coin_atoms(base, fee_atoms) != fee_atoms:
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    expected_rate = (fee_atoms * 1000) // vsize
    atoms_rate = _coin_atoms(rate, expected_rate)
    quote = quoted_rate_atoms_per_kvb
    if (atoms_rate != expected_rate
            or (quote is not None and atoms_rate < quote)):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    return None
