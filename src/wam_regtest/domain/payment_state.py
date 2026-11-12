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


def state_counts_match(state_counts, reservation_count, reservation_states):
    """True only if per-state counts are well-formed and agree with the fingerprint.

    ``state_counts`` is ((state, rows), ...) sorted by state; every rows value is a
    positive int, the rows sum to ``reservation_count``, and the states are exactly
    ``reservation_states`` (the fingerprint's sorted distinct states).
    """
    if type(state_counts) is not tuple or type(reservation_count) is not int:
        return False
    for entry in state_counts:
        if (type(entry) is not tuple or len(entry) != 2 or type(entry[0]) is not str
                or type(entry[1]) is not int or entry[1] < 1):
            return False
    return (sum(rows for _, rows in state_counts) == reservation_count
            and tuple(state for state, _ in state_counts) == tuple(reservation_states))


def reserved_rows_needing_attention(reservation_state_counts):
    """Rows that still lock coins for the owner (W-TX-03b): every row not 'broadcast'."""
    return sum(rows for state, rows in reservation_state_counts if state != BROADCAST)


def reservations_need_attention(reservation_states):
    """True if any reservation is draft, signed or uncertain (unknown states count too)."""
    states = set(reservation_states)
    return bool(states & ATTENTION_STATES) or bool(states - RESERVATION_STATES)
