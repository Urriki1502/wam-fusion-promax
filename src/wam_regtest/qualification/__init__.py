"""Qualification layer: probe and smoke orchestration.

NEVER shipped in a production app. May import any layer. Nothing in RUNTIME
may import this package.
"""
import re

FAILURE_EXCEPTION_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_FAILURE_EXCEPTION_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def failure_exception_name(error):
    """Return ONLY the exception class name (never message, args, traceback, paths or secrets)."""
    name = type(error).__name__
    if type(name) is str and _FAILURE_EXCEPTION_IDENT_RE.match(name) is not None:
        return name[:64]
    return "Exception"


def valid_failure_exception(value):
    """True when value is a safe exception class name matching ^[A-Za-z_][A-Za-z0-9_]{0,63}$."""
    return type(value) is str and FAILURE_EXCEPTION_RE.match(value) is not None


def valid_optional_failure_exception(record):
    """True when optional failure_exception is absent, None, or ^[A-Za-z_][A-Za-z0-9_]{0,63}$."""
    if type(record) is not dict:
        return False
    if "failure_exception" not in record or record["failure_exception"] is None:
        return True
    return valid_failure_exception(record["failure_exception"])

