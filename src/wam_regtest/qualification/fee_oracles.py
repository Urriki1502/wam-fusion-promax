"""REGTEST qualification review oracles; excluded from production bundles."""


def quoted_fee_holds(review):
    """REGTEST GUI review: 2x floor rate, size is covered, debit and balance agree."""
    from ..domain.fee_policy import FLOOR_MULTIPLIER, SOURCE_FLOOR_2X, fee_for_vsize
    quote = getattr(review, "fee_quote", None)
    numbers = (
        getattr(review, "vsize", None), getattr(review, "fee", None),
        getattr(review, "atoms", None), getattr(review, "total_debit", None),
        getattr(review, "overpay_atoms", None),
        getattr(review, "available_before", None),
        getattr(review, "available_after", None),
        getattr(review, "change_atoms", None))
    if quote is None or any(type(value) is not int for value in numbers):
        raise ValueError("FEE_QUOTE_REQUIRED")
    if (review.rate_source != SOURCE_FLOOR_2X
            or review.rate_atoms_per_kvb != FLOOR_MULTIPLIER * quote.floor_atoms_per_kvb):
        raise ValueError("FEE_QUOTE_NOT_NETWORK_FLOOR")
    need = fee_for_vsize(review.vsize, review.rate_atoms_per_kvb)
    if review.fee < need or review.overpay_atoms != review.fee - need:
        raise ValueError("FEE_QUOTE_SIZE")
    if review.total_debit != review.atoms + review.fee:
        raise ValueError("FEE_QUOTE_DEBIT")
    selected = review.atoms + review.fee + review.change_atoms
    if review.available_before - review.available_after != selected:
        raise ValueError("FEE_QUOTE_BALANCE")
    return True
