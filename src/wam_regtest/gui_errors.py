"""Fixed public UX categories. Never format exception text or authorize recovery."""
INPUT_ERRORS=frozenset(('WALLET_INPUT_AMOUNT_INVALID','WALLET_INPUT_FEE_INVALID',
                        'WALLET_INPUT_RECIPIENT_INVALID','WALLET_INPUT_FUNDS_UNAVAILABLE'))
from .presentation.strings import CATALOG

# Public codes remain identifiers; English compatibility mapping is derived.
_MESSAGES = {key.removeprefix('errors.'): value
             for key, value in CATALOG['en'].items() if key.startswith('errors.')}

def public_code(code,*,fallback='WALLET_OPERATION_DENIED_STATE_RETAINED'):
    safe=fallback if type(fallback) is str and fallback in _MESSAGES else 'WALLET_OPERATION_DENIED_STATE_RETAINED'
    return code if type(code) is str and code in _MESSAGES else safe

def error_text(code,*,fallback='WALLET_OPERATION_DENIED_STATE_RETAINED'):
    from .bip39_locale import t as ui_text
    # No arbitrary reason, path, RPC error, address, passphrase or traceback.
    return ui_text('errors.' + public_code(code,fallback=fallback))

def preflight_rejection(error):
    """Fixed public preflight-rejection token from a trusted rejection error."""
    from .wallet_session import WalletSessionError, PREFLIGHT_REJECTION_TOKENS
    from .wallet_executor import WalletExecutorError
    from .domain.errors import Q06SpendSessionError
    if type(error) not in (WalletSessionError, Q06SpendSessionError, WalletExecutorError):
        return None
    if error.args != ('WALLET_BROADCAST_REJECTED_LOCK_RETAINED',):
        return None
    token = getattr(error, 'preflight_rejection', None)
    return token if type(token) is str and token in PREFLIGHT_REJECTION_TOKENS else None

def operation_error(action,error):
    from .wallet_session import WalletSessionError
    from .vault import VaultError
    from .wallet_executor import WalletExecutorError
    from .domain.errors import Q06SpendSessionError
    # Do not call str(error): an external exception may contain private data
    # or implement a hostile formatter. Exact single-argument categories only.
    args=error.args if type(error) in (ValueError,WalletSessionError,VaultError,WalletExecutorError,Q06SpendSessionError) else ()
    code=args[0] if len(args)==1 and type(args[0]) is str else None
    if type(error) is WalletExecutorError and code in _MESSAGES:return code
    if type(error) is WalletExecutorError:
        if (action in ('snapshot','mine') and
                code=='Q06_GUI_ANCHORED_SCANNER_REQUIRES_RECONCILIATION'):
            return 'WALLET_NATIVE_CHECKPOINT_VERIFICATION_REQUIRED'
        if action in ('open','unlock') and code in (
                'Q06_SEED_REOPEN_DENIED','Q06_SEED_PASSWORD_DENIED',
                'Q06_GUI_UNLOCK_RECONCILIATION_DENIED'):
            return 'WALLET_UNLOCK_REFUSED'
        if code=='MANAGED_WALLET_ORIGINAL_OWNER_REQUIRED':
            return 'WALLET_CORE_IDENTITY_DENIED'
    if action in ('prepare', 'prepare_auto') and type(error) is ValueError:
        if code in ('INVALID_ADDRESS','INVALID_ENCODING','INVALID_PADDING','WRONG_NETWORK_OR_ADDRESS',
                    'INVALID_VERSION_OR_CHECKSUM','INVALID_ADDRESS_LENGTH','INVALID_PUBLIC_KEY'):
            return 'WALLET_INPUT_RECIPIENT_INVALID'
        if code=='PAYMENT_AMOUNT':return 'WALLET_INPUT_AMOUNT_INVALID'
        if code=='FEE_POLICY':return 'WALLET_INPUT_FEE_INVALID'
        if code=='INSUFFICIENT_SINGLE_CLUSTER_FUNDS':return 'WALLET_INPUT_FUNDS_UNAVAILABLE'
    # PM-072: the session alone proves the dust-change cause after WSP refuses.
    if (action in ('prepare', 'prepare_auto') and type(error) is WalletSessionError
            and code == 'WALLET_CHANGE_BELOW_DUST'):
        return code
    if type(error) in (WalletSessionError, Q06SpendSessionError) and code in _MESSAGES and code not in INPUT_ERRORS:
        return code
    if action in ('unlock','recover') and type(error) in (VaultError,WalletSessionError):
        return 'WALLET_UNLOCK_REFUSED' if action=='unlock' else 'WALLET_RECOVERY_REFUSED'
    return 'WALLET_SYNC_UNVERIFIED' if action=='sync' else 'WALLET_OPERATION_DENIED_STATE_RETAINED'
