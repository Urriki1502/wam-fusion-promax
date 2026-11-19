"""Shared best-effort file-data full-flush and directory-flush primitives (DUR-01a).

On macOS (``sys.platform == 'darwin'``), file-data flushes issue
``fcntl.fcntl(fd, F_FULLFSYNC)`` and propagate any ``OSError`` without
falling back to ``os.fsync``. Directory flushes issue ``os.fsync(fd)``
followed by ``full_flush(fd)`` on darwin (best available; APFS namespace
persistence on power loss remains UNVERIFIED). Non-darwin POSIX callers
keep ``os.fsync(fd)``; Windows native branches keep ``FlushFileBuffers``
and do not route through this module.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys

FULL_FLUSH_FAILED = "FULL_FLUSH_FAILED"
_F_FULLFSYNC_DARWIN = 51


def full_flush(fd: int) -> None:
    """Flush file data durably; fail closed on darwin without fsync fallback."""
    if sys.platform == "darwin":
        import fcntl

        code = getattr(fcntl, "F_FULLFSYNC", _F_FULLFSYNC_DARWIN)
        fcntl.fcntl(fd, code)
        return
    os.fsync(fd)


def flush_directory(fd: int) -> None:
    """Best-available directory barrier (namespace power-loss effect UNVERIFIED)."""
    os.fsync(fd)
    if sys.platform == "darwin":
        full_flush(fd)


def flush_after_mkdir(parent_fd: int) -> None:
    """Best-available parent-directory flush after mkdir or FileExistsError."""
    os.fsync(parent_fd)
    if sys.platform == "darwin":
        full_flush(parent_fd)


def _flush_open_directory(path: Path, flush_fn) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(path, flags)
    primary_error = None
    try:
        flush_fn(fd)
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            os.close(fd)
        except OSError:
            if primary_error is None:
                raise


def flush_path_directory(path: Path) -> None:
    """Open ``path`` and run ``flush_directory`` while preserving primary errors."""
    _flush_open_directory(path, flush_directory)


def flush_parent_after_mkdir(parent: Path) -> None:
    """Open ``parent`` and run ``flush_after_mkdir`` while preserving primary errors."""
    _flush_open_directory(parent, flush_after_mkdir)
