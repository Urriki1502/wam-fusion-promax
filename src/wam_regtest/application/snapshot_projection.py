"""Public owned-spend snapshot built from a read model and session accessors.

Application layer. May import domain and foundation. Never imports PySide6.
"""


def project_owned_spend_snapshot(item, session, *, profile, account_id, available_atoms):
    """Today's public dict. Same keys and values; no reservation_states."""
    return {
        "status": "Q06_REGTEST_BIP39_OWNED_SPEND_VERIFIED",
        "profile": profile,
        "account_id": account_id,
        "receive_code": item.receive_code,
        "height": item.height, "tip": item.tip,
        "confirmed_atoms": item.confirmed_atoms,
        "available_atoms": available_atoms,
        "history_count_shown": len(item.history),
        "history": tuple({
            "txid": h.txid, "height": h.block_height,
            "atoms": h.credit_atoms - h.debit_atoms
        } for h in item.history),
        "reservation_count": item.reservation_count,
        "payment_review": session.payment_review,
        "payment_signed": session.payment_signed,
        "recovered_unsigned_cancel_available": session.recovered_unsigned_cancel_available(),
        "pending_confirm_txid": session.pending_confirm_txid,
        # Same verified WalletReadSnapshot consumed by existing Fusion UI.
        # No duplicate scanner, signer or new custody/session authority.
        "fusion_snapshot": item,
        "signer_allowed": True, "broadcast_allowed": True,
        "mainnet_allowed": False,
    }
