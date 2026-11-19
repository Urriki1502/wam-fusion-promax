"""Validated public error token.

Only a single, strictly-shaped token already carried in ``error.args[0]``
may reach user or log visible output. Anything else is replaced by a
caller supplied fallback, itself validated, so unforeseen exception text
(paths, RPC replies, addresses or secrets) is never emitted.
"""
from __future__ import annotations

import re

_TOKEN = re.compile(r"[A-Z][A-Z0-9_]{0,95}")
_UNPRINTABLE = "WAM_ERROR_UNPRINTABLE"


def _is_token(value: object) -> bool:
    return isinstance(value, str) and _TOKEN.fullmatch(value) is not None


def public_token(error: object, fallback: object) -> str:
    try:
        args = error.args  # type: ignore[attr-defined]
    except Exception:
        args = None
    if type(args) is tuple and len(args) == 1 and _is_token(args[0]):
        return args[0]
    if _is_token(fallback):
        return fallback  # type: ignore[return-value]
    return _UNPRINTABLE
