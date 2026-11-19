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


# OBS-01a broadcast lock classes. Confirmed leftover rows stay 'broadcast'
# in SQLite (audit F-04) and are not locked. Every other broadcast class is.
BROADCAST_CONFIRMED = 'BROADCAST_CONFIRMED'
BROADCAST_PENDING_MEMPOOL = 'BROADCAST_PENDING_MEMPOOL'
BROADCAST_EVICTED_LOCAL = 'BROADCAST_EVICTED_LOCAL'
BROADCAST_BLOCK_CONFLICTED = 'BROADCAST_BLOCK_CONFLICTED'
BROADCAST_INPUT_UNAVAILABLE = 'BROADCAST_INPUT_UNAVAILABLE'
BROADCAST_UNKNOWN = 'BROADCAST_UNKNOWN'

LOCKED_BROADCAST_CLASSIFICATIONS = frozenset((
    BROADCAST_PENDING_MEMPOOL,
    BROADCAST_EVICTED_LOCAL,
    BROADCAST_BLOCK_CONFLICTED,
    BROADCAST_INPUT_UNAVAILABLE,
    BROADCAST_UNKNOWN,
))

_OBS_TO_BROADCAST_CLASS = {
    'CONFIRMED': BROADCAST_CONFIRMED,
    'IN_MEMPOOL': BROADCAST_PENDING_MEMPOOL,
    'NOT_SEEN_LOCALLY': BROADCAST_EVICTED_LOCAL,
    'BLOCK_CONFLICTED': BROADCAST_BLOCK_CONFLICTED,
    'INPUT_UNAVAILABLE': BROADCAST_INPUT_UNAVAILABLE,
    'UNKNOWN': BROADCAST_UNKNOWN,
}

_LOCK_COUNT_KEYS = ('non_broadcast', 'mempool', 'evicted', 'conflicted', 'unknown')
_LOCK_BREAKDOWN_KEYS = (
    'draft', 'signed', 'uncertain', 'other', 'block_conflicted', 'input_unavailable')


def _lock_zeros(keys):
    return {key: 0 for key in keys}


def read_only_reservation_lock_summary():
    """Explicit unverified summary for a pre-checkpoint read-only scan.

    Never claims zero locks or a verified operating state.
    """
    return {
        'verified': False,
        'read_only': True,
        'attention_level': 'READ_ONLY',
        'locked_inputs_total': None,
        'confirmed_leftover_inputs': 0,
        'counts': _lock_zeros(_LOCK_COUNT_KEYS),
        'state_breakdown': _lock_zeros(_LOCK_BREAKDOWN_KEYS),
        'tokens_needing_attention': 0,
        'observation_refused_reason': None,
    }


def classify_broadcast_reservations(tokens, observed=None, *, observation_refused_reason=None):
    """Map evidence-checked broadcast tokens to domain lock classes. Pure.

    ``tokens`` items provide ``token``, ``rows``, ``txid``, ``evidence``
    (``ok``, ``unavailable``, ``mixed`` or ``duplicate``) and optional ``reason``.
    ``observed`` maps a txid to an OBS-01a result (``state``). A whole-acquisition
    refusal classifies every evidence-ok token as ``BROADCAST_UNKNOWN``.
    """
    observed = {} if observed is None else observed
    classified = []
    for token in tokens:
        rows = token['rows']
        evidence = token.get('evidence')
        txid = token.get('txid')
        if evidence != 'ok' or observation_refused_reason is not None:
            if observation_refused_reason is not None and evidence == 'ok':
                reason = observation_refused_reason
            elif evidence == 'mixed':
                reason = token.get('reason') or 'MIXED_TOKEN_STATES'
            elif evidence == 'duplicate':
                reason = token.get('reason') or 'DUPLICATE_TXID'
            else:
                reason = token.get('reason') or 'EVIDENCE_UNAVAILABLE'
            classified.append({
                'token': token['token'],
                'classification': BROADCAST_UNKNOWN,
                'rows': rows,
                'txid': txid,
                'reason': reason,
                'observation_unknown': True,
            })
            continue
        item = observed.get(txid)
        state = item.get('state') if isinstance(item, dict) else None
        classification = _OBS_TO_BROADCAST_CLASS.get(state, BROADCAST_UNKNOWN)
        classified.append({
            'token': token['token'],
            'classification': classification,
            'rows': rows,
            'txid': txid,
            'reason': item.get('reason') if classification == BROADCAST_UNKNOWN and isinstance(item, dict) else None,
            'observation_unknown': classification == BROADCAST_UNKNOWN,
        })
    return classified


def _attention_level(counts, locked_total, verified):
    if not verified or counts['unknown'] > 0 or locked_total is None:
        return 'UNKNOWN_UNVERIFIED'
    if counts['conflicted'] > 0 or counts['evicted'] > 0 or counts['non_broadcast'] > 0:
        return 'ATTENTION_REQUIRED'
    if counts['mempool'] > 0:
        return 'PENDING'
    if locked_total == 0:
        return 'NONE'
    return 'UNKNOWN_UNVERIFIED'


def summarize_reservation_locks(broadcast, non_broadcast, *, verified_fingerprint=True,
                                observation_refused_reason=None):
    """Aggregate classified broadcast tokens and non-broadcast reservation rows.

    A fingerprint mismatch (``verified_fingerprint`` false) counts every
    broadcast row as unknown and leaves the locked total unknown.
    """
    counts = _lock_zeros(_LOCK_COUNT_KEYS)
    breakdown = _lock_zeros(_LOCK_BREAKDOWN_KEYS)
    confirmed = 0
    attention_tokens = set()
    for item in non_broadcast:
        rows = item['rows']
        state = item['state']
        counts['non_broadcast'] += rows
        if state in ('draft', 'signed', 'uncertain'):
            breakdown[state] += rows
        else:
            breakdown['other'] += rows
        attention_tokens.add(item['token'])
    for item in broadcast:
        classification = item['classification']
        rows = item['rows']
        if not verified_fingerprint:
            classification = BROADCAST_UNKNOWN
        if classification == BROADCAST_CONFIRMED:
            confirmed += rows
            continue
        attention_tokens.add(item['token'])
        if classification == BROADCAST_PENDING_MEMPOOL:
            counts['mempool'] += rows
        elif classification == BROADCAST_EVICTED_LOCAL:
            counts['evicted'] += rows
        elif classification == BROADCAST_BLOCK_CONFLICTED:
            counts['conflicted'] += rows
            breakdown['block_conflicted'] += rows
        elif classification == BROADCAST_INPUT_UNAVAILABLE:
            counts['conflicted'] += rows
            breakdown['input_unavailable'] += rows
        else:
            counts['unknown'] += rows
    if verified_fingerprint:
        locked_total = (counts['non_broadcast'] + counts['mempool'] + counts['evicted']
                        + counts['conflicted'] + counts['unknown'])
    else:
        locked_total = None
    verified = (verified_fingerprint and locked_total is not None and counts['unknown'] == 0
                and observation_refused_reason is None)
    return {
        'verified': verified,
        'read_only': False,
        'attention_level': _attention_level(counts, locked_total, verified),
        'locked_inputs_total': locked_total,
        'confirmed_leftover_inputs': confirmed if verified_fingerprint else 0,
        'counts': counts,
        'state_breakdown': breakdown,
        'tokens_needing_attention': len(attention_tokens),
        'observation_refused_reason': observation_refused_reason,
    }


# REC-1a (UAT, PM-087): read-only broadcast-state classification. Derived
# only from durable reservation rows, payment evidence and an OBS-01a
# observation. UAT produces no rebroadcast-eligible state: a token that
# would be eligible is NOT_OBSERVED_LOCALLY with REBROADCAST_DEFERRED.
REC1_CONFIRMED = 'CONFIRMED'
REC1_IN_LOCAL_MEMPOOL = 'IN_LOCAL_MEMPOOL'
REC1_NOT_OBSERVED_LOCALLY = 'NOT_OBSERVED_LOCALLY'
REC1_CONFLICTED = 'CONFLICTED'
REC1_REJECTED_BY_POLICY = 'REJECTED_BY_POLICY'
REC1_BROADCAST_OUTCOME_UNCERTAIN = 'BROADCAST_OUTCOME_UNCERTAIN'
REC1_CORRUPTED_EVIDENCE = 'CORRUPTED_EVIDENCE'
REC1_QUARANTINED = 'QUARANTINED'

REC1_STATES = frozenset((
    REC1_CONFIRMED, REC1_IN_LOCAL_MEMPOOL, REC1_NOT_OBSERVED_LOCALLY,
    REC1_CONFLICTED, REC1_REJECTED_BY_POLICY,
    REC1_BROADCAST_OUTCOME_UNCERTAIN, REC1_CORRUPTED_EVIDENCE))

REC1_REASON_REBROADCAST_DEFERRED = 'REBROADCAST_DEFERRED'
REC1_REASON_EVIDENCE_READ_FAILED = 'EVIDENCE_READ_FAILED'
REC1_REASON_EVIDENCE_MISSING = 'EVIDENCE_MISSING'
REC1_REASON_EVIDENCE_INVALID = 'EVIDENCE_INVALID'
REC1_REASON_EVIDENCE_INPUT_MISMATCH = 'EVIDENCE_INPUT_MISMATCH'
REC1_REASON_LINKED = 'LINKED_TO_CORRUPTED_EVIDENCE'
REC1_REASON_MIXED = 'MIXED_TOKEN_STATES'

_REC1_RECORDED_REJECTIONS = frozenset((
    'FEE_POLICY_REJECTED', 'POLICY_REJECTED', 'ALREADY_IN_MEMPOOL',
    'ALREADY_IN_CHAIN', 'DUST_REJECTED', 'INPUT_SPENT_OR_CONFLICTED',
    'CONFLICT_REJECTED', 'TXN_ALREADY_IN_CHAIN'))

_REC1_CORRUPT_EVIDENCE = frozenset((
    'invalid', 'missing', 'mismatch', 'mixed', 'corrupted', 'unavailable'))


def linked_quarantine_closure(token_inputs, corrupted):
    """Tokens quarantined by linkage to a corrupted token. Pure.

    ``token_inputs`` maps each token to its outpoints (reserved rows plus,
    when decoded, evidence inputs). Two tokens are linked when they share
    an outpoint; the closure is every token reachable from a corrupted one.
    """
    by_outpoint = {}
    for token, outpoints in token_inputs.items():
        for outpoint in outpoints or ():
            by_outpoint.setdefault(outpoint, set()).add(token)
    quarantined = set(corrupted)
    queue = list(quarantined)
    while queue:
        token = queue.pop()
        neighbours = set()
        for outpoint in token_inputs.get(token) or ():
            neighbours.update(by_outpoint.get(outpoint, ()))
        for other in neighbours:
            if other not in quarantined:
                quarantined.add(other)
                queue.append(other)
    return quarantined


def classify_rec1_token(*, reservation_state=None, evidence='verified',
                        observation_state=None, recorded_rejection=None,
                        quarantined=False, quarantine_reason=None):
    """One REC-1a classification. Pure; never spendable or recovered."""
    if quarantined or evidence in _REC1_CORRUPT_EVIDENCE:
        reason = quarantine_reason or {
            'invalid': REC1_REASON_EVIDENCE_INVALID,
            'missing': REC1_REASON_EVIDENCE_MISSING,
            'mismatch': REC1_REASON_EVIDENCE_INPUT_MISMATCH,
            'mixed': REC1_REASON_MIXED,
        }.get(evidence, REC1_REASON_EVIDENCE_READ_FAILED)
        return {'rec1_state': REC1_CORRUPTED_EVIDENCE, 'rec1_reason': reason,
                'quarantined': True, 'spendable': False, 'recovered': False}
    if observation_state == 'CONFIRMED':
        return {'rec1_state': REC1_CONFIRMED, 'rec1_reason': None,
                'quarantined': False, 'spendable': False, 'recovered': False}
    if observation_state == 'IN_MEMPOOL':
        return {'rec1_state': REC1_IN_LOCAL_MEMPOOL, 'rec1_reason': None,
                'quarantined': False, 'spendable': False, 'recovered': False}
    if observation_state in ('BLOCK_CONFLICTED', 'INPUT_UNAVAILABLE'):
        return {'rec1_state': REC1_CONFLICTED, 'rec1_reason': observation_state,
                'quarantined': False, 'spendable': False, 'recovered': False}
    if (type(recorded_rejection) is str
            and recorded_rejection in _REC1_RECORDED_REJECTIONS):
        # Only an existing recorded typed rejection yields this state.
        return {'rec1_state': REC1_REJECTED_BY_POLICY,
                'rec1_reason': recorded_rejection,
                'quarantined': False, 'spendable': False, 'recovered': False}
    if observation_state in ('NOT_SEEN_LOCALLY', 'NOT_OBSERVED_LOCALLY',
                             'NOT_FOUND_LOCALLY'):
        return {'rec1_state': REC1_NOT_OBSERVED_LOCALLY,
                'rec1_reason': REC1_REASON_REBROADCAST_DEFERRED,
                'quarantined': False, 'spendable': False, 'recovered': False}
    if observation_state == 'UNKNOWN' or reservation_state == UNCERTAIN:
        return {'rec1_state': REC1_BROADCAST_OUTCOME_UNCERTAIN,
                'rec1_reason': observation_state,
                'quarantined': False, 'spendable': False, 'recovered': False}
    return {'rec1_state': REC1_BROADCAST_OUTCOME_UNCERTAIN,
            'rec1_reason': observation_state,
            'quarantined': False, 'spendable': False, 'recovered': False}
