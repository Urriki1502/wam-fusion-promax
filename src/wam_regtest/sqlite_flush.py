"""One WAM factory for Scanner/Store connections (DUR-01b).

On darwin the factory sets ``fullfsync``, ``checkpoint_fullfsync`` and
``synchronous=FULL``, then reads them back before the connection is
returned. Every configured connection must report ``journal_mode``
DELETE. A failed set, a readback mismatch, or any other journal mode
closes the connection and raises ``SQLITE_FLUSH_UNCONFIGURED``.

``DISCLOSURE`` is binding: readback is not proof that ``F_FULLFSYNC``
succeeded (SQLite's unix VFS falls back to fsync on fcntl error);
DELETE with synchronous FULL can lose the last commit on power loss;
the live VFS name is UNVERIFIED. ``synchronous=EXTRA`` is not adopted
and WSP is not modified.
"""
from __future__ import annotations

import sqlite3
import sys

from .wallet_session import WalletSessionError

SQLITE_FLUSH_UNCONFIGURED = "SQLITE_FLUSH_UNCONFIGURED"
_CONFIGURED = "_wam_sqlite_flush_configured"
_RECOVERY = (
    "this SQLite build/connection did not accept full-fsync configuration; "
    "custody writes refused — reopen/recreate with an F_FULLFSYNC-capable build"
)
DISCLOSURE = (
    "Readback proves the PRAGMA was accepted, not that F_FULLFSYNC succeeded. "
    "SQLite's unix VFS falls back to fsync when fcntl fails. "
    "journal_mode DELETE with synchronous FULL can lose the last commit on "
    "power loss. The live VFS name is UNVERIFIED. synchronous=EXTRA is not "
    "adopted."
)

# (name, assignment, readback). Names are fixed literals, never caller data.
_DARWIN_PRAGMAS = (
    ("fullfsync", "ON", 1),
    ("checkpoint_fullfsync", "ON", 1),
    ("synchronous", "FULL", 2),
)


class SqliteFlushUnconfigured(WalletSessionError):
    """Typed fail-closed token. Outermost constructors may set ``faulted``."""

    def __init__(self):
        super().__init__(SQLITE_FLUSH_UNCONFIGURED)
        self.token = SQLITE_FLUSH_UNCONFIGURED
        self.faulted = False
        self.recovery = _RECOVERY


def sqlite_version() -> str:
    """Pinned interpreter's SQLite library version (recorded, not a VFS proof)."""
    return sqlite3.sqlite_version


def make_scanner(path, accounts, limits=None, logger=None):
    """Construct one Scanner and configure its Store connection once.

    A ``Store`` constructor failure propagates unchanged. No pragma is
    attempted and no ``SQLITE_FLUSH_UNCONFIGURED`` token is raised for
    that failure. Non-darwin hosts skip the fullfsync pragma path and
    still require ``journal_mode`` DELETE.
    """
    from wam_sp.scanner import DEFAULT, Scanner

    if limits is None:
        limits = DEFAULT
    scanner = Scanner(path, accounts, limits, logger)
    _configure_store(scanner.store)
    return scanner


def _execute(db, sql):
    return db.execute(sql)


def _read_pragma(db, name):
    for pragma_name, _setting, _expected in _DARWIN_PRAGMAS:
        if pragma_name == name:
            row = _execute(db, "PRAGMA " + pragma_name).fetchone()
            if row is None:
                raise sqlite3.Error("SQLITE_PRAGMA_READBACK_MISSING")
            return row[0]
    if name == "journal_mode":
        row = _execute(db, "PRAGMA journal_mode").fetchone()
        if row is None:
            raise sqlite3.Error("SQLITE_PRAGMA_READBACK_MISSING")
        return row[0]
    raise sqlite3.Error("SQLITE_PRAGMA_NAME_DENIED")


def _journal_mode(db):
    return _read_pragma(db, "journal_mode")


def _apply_darwin_flush_pragmas(db):
    """Set and read back the darwin flush pragmas. No ``os.fsync`` fallback."""
    for name, setting, _expected in _DARWIN_PRAGMAS:
        _execute(db, "PRAGMA " + name + "=" + setting)
    for name, _setting, expected in _DARWIN_PRAGMAS:
        if _read_pragma(db, name) != expected:
            raise sqlite3.Error("SQLITE_PRAGMA_READBACK_MISMATCH")


def _close_failed(store):
    try:
        store.close()
    except Exception:
        try:
            store.db.close()
        except Exception:
            pass
        store.closed = True


def _configure_store(store):
    if getattr(store, _CONFIGURED, False):
        return
    with store.lock:
        if getattr(store, _CONFIGURED, False):
            return
        if store.closed:
            raise SqliteFlushUnconfigured()
        try:
            if sys.platform == "darwin":
                _apply_darwin_flush_pragmas(store.db)
            mode = _journal_mode(store.db)
        except SqliteFlushUnconfigured:
            _close_failed(store)
            raise
        except Exception:
            _close_failed(store)
            raise SqliteFlushUnconfigured() from None
        if str(mode).upper() != "DELETE":
            _close_failed(store)
            raise SqliteFlushUnconfigured()
        setattr(store, _CONFIGURED, True)
