"""Shared domain errors.

bip39_owner_backend re-exports Q06ReadOnlyError and bip39_spend_session
re-exports Q06SpendSessionError. Both import paths are the same object.
"""


class Q06ReadOnlyError(ValueError):
    pass


class Q06SpendSessionError(ValueError):
    """Public bounded error. Never interpolate secrets, paths or RPC details."""
