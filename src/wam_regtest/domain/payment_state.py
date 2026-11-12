"""Payment reservation states the application already stores.

Names the WSP reservation strings and the create-only evidence stages, and
the transitions this wallet relies on. It does not add a terminal
'confirmed' reservation state: after a verified confirm the row stays
'broadcast' (audit F-04, an owner decision). It does not import or change
WSP. 'manual' is WSP coin-control, not a step of this payment flow.

The one app-level write is the uncertain checkpoint taken before
submission. Fresh broadcast marks every row of the token. Resume marks
only rows still 'signed'. Those predicates are not interchangeable: the
checkpoint saved before sendrawtransaction would differ if a token still
had a non-signed row. Neither statement opens a transaction, and sqlite3
errors propagate with their original type.
"""

DRAFT = 'draft'
SIGNED = 'signed'
UNCERTAIN = 'uncertain'
BROADCAST = 'broadcast'

RESERVATION_STATES = frozenset((DRAFT, SIGNED, UNCERTAIN, BROADCAST))
# Create-only evidence filenames use these stages. A draft has no evidence file.
EVIDENCE_STAGES = frozenset((SIGNED, UNCERTAIN, BROADCAST))

# (source, destination). None means the reservation rows are deleted.
# WSP performs draft→signed, draft→deleted and uncertain→broadcast.
# This module performs only signed→uncertain, and only before submission.
LEGAL_TRANSITIONS = frozenset((
    (DRAFT, SIGNED),
    (DRAFT, None),
    (SIGNED, UNCERTAIN),
    (UNCERTAIN, BROADCAST),
))


def mark_reservations_uncertain_before_submission(db, token, *, signed_rows_only):
    """Mark reservations uncertain. Does not BEGIN, COMMIT or translate errors.

    ``signed_rows_only`` False is the fresh-broadcast statement (every row of
    the token). True is the resume statement (rows still 'signed').
    """
    statement = (
        "UPDATE reservations SET state='uncertain' WHERE token=? AND state='signed'"
        if signed_rows_only else
        "UPDATE reservations SET state='uncertain' WHERE token=?")
    db.execute(statement, (token,))


# Reservation states that still need the owner's attention: an unsigned draft,
# a signed but unsubmitted payment, or a submission whose outcome is uncertain.
# A token whose rows are all 'broadcast' was submitted; after a verified confirm
# those rows remain (no terminal state, audit F-04) but need no action (W-TX-03).
ATTENTION_STATES = frozenset((DRAFT, SIGNED, UNCERTAIN))


def reservations_need_attention(reservation_states):
    """True if any reservation is draft, signed or uncertain (unknown states count too)."""
    states = set(reservation_states)
    return bool(states & ATTENTION_STATES) or bool(states - RESERVATION_STATES)
