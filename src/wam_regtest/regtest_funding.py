"""Existing once-only public REGTEST receive helper, shared by GUI and probes.

Caller must retain the original owned-Core and new-profile guards. No generic
CLI, additional mining policy, wallet authority or test fault injector lives here.
"""
from types import SimpleNamespace


def fund_checkpoint_fixture(rpc,payment_code,address,record):
    """Height-agnostic repeatable public REGTEST receive helper.

    Each call carries the caller's owned-Core/new-profile guards. The fixture
    mines ITS OWN fresh coinbase to the public mining address at whatever the
    current height then is, advances it to maturity, and pays it into the
    wallet's BIP352 receive via _public_fixture_payment, then 1 confirm block.
    """
    from .core import CoreSmokeError
    from .wsp_live import RealWspScanError, _public_fixture_payment
    stage='attestation'
    try:
        rpc.attest();stage='height'
        start=rpc.call('getblockcount')
        if type(start) is not int or start<0:
            raise RealWspScanError('WSP_PUBLIC_FIXTURE_HEIGHT_DENIED')
        stage='generation'
        rpc._call('generatetoaddress',['101',address]);stage='payment'
        return _public_fixture_payment(rpc,SimpleNamespace(payment_code=lambda:payment_code),address,
                                       funding_height=start+1,expected_before_height=start+101)
    except Exception as error:
        detail={'stage':stage}
        cause=error.__context__
        if type(cause) is CoreSmokeError and len(cause.args)==1 and type(cause.args[0]) is str:
            code=cause.args[0]
            if code in ('CORE_RPC_TIMEOUT_UNCERTAIN','CORE_RPC_SCOPE_FAULTED',
                    'CORE_RPC_AUTHENTICATION_DENIED','CORE_RPC_UNAVAILABLE',
                    'CORE_RPC_PROCESS_IDENTITY_DENIED','CORE_RPC_CREDENTIAL_CHANGED_OR_UNSAFE',
                    'CORE_LOCAL_NETWORK_POLICY_DENIED','CORE_RPC_MUTATION_CONSENT_REQUIRED',
                    'CORE_LOCAL_RPC_PARAMS_DENIED','CORE_LOCAL_RPC_METHOD_DENIED',
                    'CORE_RPC_REPLY_DENIED','CORE_RPC_REPLY_BOUNDS_DENIED','CORE_RPC_DENIED',
                    'CORE_RPC_PROCESS_DENIED'):
                detail['cli_code']=code
        record['fixture_funding_failure']=detail
        raise
    finally:
        if getattr(rpc,'_transport',None) is not None:rpc._transport.close()

