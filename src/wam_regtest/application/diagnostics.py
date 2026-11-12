"""Internal diagnostic context: fixed stage and category tokens only (audit F-05).

Public refusal behaviour is unchanged: callers still raise their existing
public codes (for example ``Q06_GUI_UNLOCK_RECONCILIATION_DENIED``), and the
GUI still shows ``WALLET_UNLOCK_REFUSED``. This module only keeps the *reason
category* that those fail-closed wrappers deliberately drop, so that a refusal
can be classified without exposing anything private.

What may be recorded:
  * a stage token chosen by the caller from a fixed literal (``STAGE_RE``);
  * a category derived from the underlying exception: its single ``args[0]``
    when that is an upper-case code token (``CODE_RE``), else its class name
    when that is a plain identifier, else ``INTERNAL``.
Never recorded: exception text, other args, paths, seeds, passwords, keys,
TXIDs, addresses or amounts. The same code-token rule is used by the existing
``bip39_reconciliation`` diagnostics.

Where it goes:
  * an in-process bounded ring (``records()``), read by qualification probes
    in the same process;
  * standard error, only when ``WAM_INTERNAL_DIAGNOSTICS=1`` is set
    explicitly. This grants no authority and changes no wallet behaviour.

This module also holds the pre-existing environment-gated qualification
markers, with their exact gates and output unchanged, so that every
diagnostic environment switch lives in one place.
"""
from collections import deque
import os
import re
import sys
import threading
import time

STAGE_RE = re.compile(r'[A-Z][A-Z0-9_]{0,63}\Z')
CODE_RE = re.compile(r'[A-Z][A-Z0-9_]{0,95}\Z')
_CLASS_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')
_RING_SIZE = 64
_ENV_EMIT = 'WAM_INTERNAL_DIAGNOSTICS'

_lock = threading.Lock()
_ring = deque(maxlen=_RING_SIZE)


class DiagnosticRecord(tuple):
    """Immutable (monotonic, stage, category, open_stage) record."""
    __slots__ = ()

    def __new__(cls, monotonic, stage, category, open_stage):
        return super().__new__(cls, (monotonic, stage, category, open_stage))

    monotonic = property(lambda self: self[0])
    stage = property(lambda self: self[1])
    category = property(lambda self: self[2])
    open_stage = property(lambda self: self[3])


def category_of(error):
    """Fixed category token for an exception, never its text."""
    if error is None:
        return 'NONE'
    args = getattr(error, 'args', ())
    if (type(args) is tuple and len(args) == 1 and type(args[0]) is str
            and CODE_RE.match(args[0])):
        return args[0]
    name = type(error).__name__
    return name if _CLASS_RE.match(name) else 'INTERNAL'


def _fixed_stage(value):
    return value if type(value) is str and STAGE_RE.match(value) else None


def record(stage, error=None, open_stage=None):
    """Record one fixed stage token and the category of ``error`` (or its cause).

    Call it inside the ``except`` block BEFORE a fail-closed wrapper is raised
    ``from None``, so the original exception is still available. ``stage`` and
    ``open_stage`` must be literal upper-case tokens; otherwise they become
    ``INVALID_STAGE`` / ``None``. When ``error`` wraps another exception (``__cause__``
    or an unsuppressed ``__context__``), the innermost category is the one
    recorded; a fixed ``open_stage`` attribute anywhere in that chain is kept.
    Never raises.
    """
    try:
        token = _fixed_stage(stage) or 'INVALID_STAGE'
        open_stage = _fixed_stage(open_stage)
        inner = error
        seen = 0
        while inner is not None and seen < 8:
            open_stage = open_stage or _fixed_stage(getattr(inner, 'open_stage', None))
            nxt = inner.__cause__ or (None if inner.__suppress_context__ else inner.__context__)
            if nxt is None:
                break
            inner, seen = nxt, seen + 1
        item = DiagnosticRecord(round(time.monotonic(), 3), token, category_of(inner), open_stage)
        with _lock:
            _ring.append(item)
        if os.environ.get(_ENV_EMIT) == '1' and sys.stderr is not None:
            print('WAM_DIAG stage=%s category=%s open_stage=%s'
                  % (item.stage, item.category, item.open_stage or '-'),
                  file=sys.stderr, flush=True)
        return item
    except Exception:
        return None


def records():
    """Immutable copy of the recorded tokens, oldest first."""
    with _lock:
        return tuple(_ring)


def clear():
    with _lock:
        _ring.clear()


# Pre-existing environment-gated markers (gates and text unchanged).

def q06_spend_qualification():
    """darwin + GITHUB_ACTIONS=true + WAM_Q06_CI_SPEND_QUALIFY=1 (Q06 spend probe)."""
    return (sys.platform == 'darwin' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('WAM_Q06_CI_SPEND_QUALIFY') == '1')


def q06_spend_marker(text):
    if q06_spend_qualification():
        print(text, flush=True)


def ci_marker(text):
    """CI=true (native checkpoint advance stage)."""
    if os.environ.get('CI') == 'true':
        print(text, flush=True)


def reconciliation_marker(phase, error):
    """WAM_RECONCILIATION_DIAGNOSTICS=1 (shared reconciliation stage + code)."""
    if os.environ.get('WAM_RECONCILIATION_DIAGNOSTICS') == '1':
        args = error.args
        code = (args[0] if len(args) == 1 and type(args[0]) is str
                and re.fullmatch('[A-Z0-9_]{1,96}', args[0]) else 'INTERNAL_DENIED')
        print('Q06_RECONCILIATION_DENIED_STAGE=' + phase + ';CATEGORY=' + code, flush=True)
