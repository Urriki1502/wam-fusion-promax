"""Read-only Core fee-policy adapter for the automatic fee (FEE-1).

Uses only the caller's existing authenticated, loopback-only Core RPC object
(the same `rpc.call(method, params)` the wallet session already uses). It
issues read-only calls: getnetworkinfo, getmempoolinfo, estimatesmartfee and
estimaterawfee. It never broadcasts, never sends, never logs responses.
Transport or RPC failures fail closed as FEE_POLICY_UNVERIFIED.
estimaterawfee is a version-sensitive diagnostic: if it fails, the absence is
recorded and the estimator can only be classified weaker, never stronger.
"""
from __future__ import annotations

from ..domain.fee_policy import ESTIMATE_TARGETS, QUOTE_TARGET, FeePolicyError, parse_policy_inputs

READ_ONLY_METHODS = frozenset(('getnetworkinfo', 'getmempoolinfo', 'estimatesmartfee', 'estimaterawfee'))


def _call(rpc, method, params):
    assert method in READ_ONLY_METHODS
    try:
        return rpc.call(method, params)
    except Exception:
        raise FeePolicyError('FEE_POLICY_UNVERIFIED') from None


def read_policy_inputs(rpc, network):
    """Fetch and validate the selected Core's fee policy for `network`."""
    networkinfo = _call(rpc, 'getnetworkinfo', [])
    mempoolinfo = _call(rpc, 'getmempoolinfo', [])
    smart = {t: _call(rpc, 'estimatesmartfee', [t, 'conservative']) for t in ESTIMATE_TARGETS}
    raw = {}
    for target in (QUOTE_TARGET,):
        try:
            raw[target] = rpc.call('estimaterawfee', [target])
        except Exception:
            raw[target] = None
    return parse_policy_inputs(network, networkinfo, mempoolinfo, smart, raw)
