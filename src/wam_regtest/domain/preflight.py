"""Read-only admission verification. Acceptance never authorizes submission."""
from decimal import Decimal
import re

from ..infrastructure.tx_size import serialized_vsize


# Pending FE-007 confirmation against official v0.1.13. Missing required fields
# on acceptance fail closed; effective-includes is optional, but checked if set.
PREFLIGHT_REQUIRED_FIELDS = (
    'txid', 'vsize', 'fees.base', 'fees.effective-feerate',
)
PREFLIGHT_REJECT_REASONS = {
    'min relay fee not met': 'FEE_POLICY_REJECTED',
    'insufficient fee': 'FEE_POLICY_REJECTED',
    'bad-txns-inputs-missingorspent': 'INPUT_SPENT_OR_CONFLICTED',
    'txn-mempool-conflict': 'CONFLICT_REJECTED',
    'replacement-adds-unconfirmed': 'CONFLICT_REJECTED',
    'bip125-replacement-disallowed': 'CONFLICT_REJECTED',
    'dust': 'POLICY_REJECTED',
    'non-final': 'POLICY_REJECTED',
    'non-BIP68-final': 'POLICY_REJECTED',
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


def verify_preflight(reply, signed, review):
    """Return None for verified acceptance, a fixed token for rejection.

    Raises on verification failure (caller latches). Rejections need no economic
    fields and never latch. Tokens are internal diagnostics; callers retain the
    existing public rejection code. No raw Core reason leaves this boundary.
    This function writes no state and grants no broadcast authority.
    """
    from wam_sp.psbt import PSBT
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
    psbt = PSBT.decode(signed)
    raw = psbt.finalize()
    txid = fields['txid']
    if (type(txid) is not str or re.fullmatch('[0-9a-fA-F]{64}', txid) is None
            or txid != psbt.txid()):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    vsize = fields['vsize']
    if (type(vsize) is not int or vsize != serialized_vsize(raw)
            or (getattr(review, 'vsize', None) is not None and vsize != review.vsize)):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    # Context-independent exact integer Decimal math; floats/strings refused.
    base = fields['fees.base']
    rate = fields['fees.effective-feerate']
    if type(base) not in (Decimal, int) or type(rate) not in (Decimal, int):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    if _coin_atoms(base, review.fee) != review.fee:
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    expected_rate = (review.fee * 1000) // vsize
    atoms_rate = _coin_atoms(rate, expected_rate)
    quote = getattr(review, 'rate_atoms_per_kvb', None)
    if (atoms_rate != expected_rate
            or (quote is not None and atoms_rate < quote)):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    if ('effective-includes' in item['fees']
            and item['fees']['effective-includes'] != [txid]):
        raise ValueError('WALLET_MEMPOOL_REPLY_DENIED')
    return None
