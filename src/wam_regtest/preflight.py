"""REC-1a typed preflight keys (PM-087, UAT).

The shared contract in :mod:`wam_regtest.domain.preflight` is unchanged:
its ``PREFLIGHT_REJECT_REASONS`` values and the resume allowlist built on
them keep their exact tokens (REC-2, FEE-3). This module only adds the
REC-1a typed view, where Core's exact ``txn-already-in-chain`` and
``dust`` reasons get their own keys instead of the generic
``POLICY_REJECTED`` fallback. Every other mapping is identical.
"""
from .domain.preflight import PREFLIGHT_REJECT_REASONS, verify_preflight

TYPED_PREFLIGHT_KEYS = dict(PREFLIGHT_REJECT_REASONS)
TYPED_PREFLIGHT_KEYS.update({
    'txn-already-in-chain': 'ALREADY_IN_CHAIN',
    'dust': 'DUST_REJECTED',
})
# Descriptive alias for the same REC-1a mapping.
REC1_PREFLIGHT_REJECT_REASONS = TYPED_PREFLIGHT_KEYS
PREFLIGHT_REJECT_REASONS_TYPED = TYPED_PREFLIGHT_KEYS


def typed_preflight_key(reason):
    """Typed REC-1a key for one exact Core reject-reason, else generic."""
    if type(reason) is not str:
        return 'POLICY_REJECTED'
    return TYPED_PREFLIGHT_KEYS.get(reason, 'POLICY_REJECTED')


def verify_preflight_typed(reply, *, txid, wtxid, vsize, fee_atoms,
                           quoted_rate_atoms_per_kvb=None):
    """Domain verification with REC-1a typed rejection keys.

    Acceptance and malformed-reply behaviour are the domain verifier's;
    only a definitive rejection token is upgraded to its typed key.
    """
    if (type(reply) is list and len(reply) == 1 and type(reply[0]) is dict
            and reply[0].get('allowed') is False):
        return typed_preflight_key(reply[0].get('reject-reason'))
    return verify_preflight(reply, txid=txid, wtxid=wtxid, vsize=vsize,
                             fee_atoms=fee_atoms,
                             quoted_rate_atoms_per_kvb=quoted_rate_atoms_per_kvb)
