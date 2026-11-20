"""Q20 dynamic privacy sweep tool (qualification-only, read-only).

Run by the lead AFTER manual UAT journeys on the production .app with a
DISPOSABLE REGTEST profile. Never modifies files, never uploads data, and
never prints or records any needle or matched bytes.

Derived codebase locations (file:line):
  * App bundle IDs / QSettings stores:
      - scripts/build_macos_production.py:19 -> org.wamcoin.privacywallet.regtest
      - scripts/build_macos_production.py:20 -> org.wamcoin.privacywallet.regtest.qualification
      - scripts/build_macos_bundle.sh:22     -> org.wamcoin.privacywallet.regtest.qualification
      - scripts/sign_macos_release.py:32     -> org.wamcoin.privacywallet.regtest
      - scripts/verify_macos_ci_outputs.py:39-40 -> both production & qualification IDs
      - src/wam_regtest/ui_settings.py:11,25-27,46,58 ->
            QSettings("WAM Privacy Wallet", "REGTEST") (macOS plist
            com.wam-privacy-wallet.REGTEST.plist) and optional WAM_UI_SETTINGS_PATH INI
  * App log / diagnostics / support locations:
      - src/wam_regtest/foundation/diagnostics.py:25-30,115-118 ->
            in-process bounded ring + optional stderr (WAM_INTERNAL_DIAGNOSTICS=1); no disk log
      - src/wam_regtest/core_supervisor.py:135,237-241,279-280 ->
            supervisor.failure + chain/ (-datadir); supervisor sets stdout/stderr=DEVNULL
      - src/wam_regtest/qualification/real_core_smoke.py:30,135 ->
            datadir/core-output.log
      - src/wam_regtest/q04_busy_probe.py:104 ->
            datadir/regtest/debug.log (WAM Core debug.log)
      - src/wam_regtest/vault.py:27-28,32-38,51 ->
            ~/Library/Application Support/WAM Fusion REGTEST/wallet-leases
            and legacy $TMPDIR/wam-regtest-wallet-leases
  * Encrypted vault / ciphertext files excluded from --data-dir scan:
      - src/wam_regtest/encrypted_storage.py:22,26-30 ->
            [a-z0-9-]{1,80}.enc, size >= 52, magic prefix b"WAMSP02\\x00"
      - src/wam_regtest/bip39_seed_vault.py:19-20,143-144 ->
            bip39-12-<32hex>/seed-000000001.enc
      - src/wam_regtest/bip39_native_checkpoint.py:22,35,52 ->
            bip39-12-scan-<32hex>/snapshot-<9digits>.enc
      - src/wam_regtest/vault.py:245, src/wam_regtest/wallet_session.py:323 ->
            wallet-vault/snapshot-<9digits>.enc
      - src/wam_regtest/domain/payment_evidence.py:3,31,163 ->
            q06-payment-evidence/<token>-<stage>.enc
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
import time

SCHEMA = "wam-q20-dynamic-privacy-sweep/v1"
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_PLIST_BYTES = 16 * 1024 * 1024
CHUNK_BYTES = 4 * 1024 * 1024
WAMSP02_MAGIC = b"WAMSP02\x00"
MIN_ENVELOPE_BYTES = 52  # src/wam_regtest/encrypted_storage.py:28

# Derived from scripts/build_macos_production.py:19-20, scripts/build_macos_bundle.sh:22,
# scripts/sign_macos_release.py:32, and src/wam_regtest/ui_settings.py:11,25-26,58.
PREF_PREFIXES = (
    "org.wamcoin.",
    "com.wam-privacy-wallet.",
)

_ENV_TOKEN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PID_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)$")


def load_needles(needles_file: Path) -> list[str]:
    """Load secrets from needles_file: full lines + 3-word windows (never 1-word splits)."""
    if not needles_file.is_file() or needles_file.is_symlink():
        raise ValueError("Q20_DYNAMIC_NEEDLES_FILE_DENIED")
    try:
        text = needles_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise ValueError("Q20_DYNAMIC_NEEDLES_FILE_UNREADABLE") from None

    needles: list[str] = []
    seen: set[str] = set()

    def _add(item: str) -> None:
        if item and item not in seen:
            seen.add(item)
            needles.append(item)

    for line in text.splitlines():
        raw = line.rstrip("\r\n")
        if not raw.strip():
            continue
        _add(raw)
        words = raw.split()
        if len(words) >= 3:
            _add(" ".join(words))
            for idx in range(len(words) - 2):
                _add(" ".join(words[idx : idx + 3]))

    if not needles:
        raise ValueError("Q20_DYNAMIC_EMPTY_NEEDLES_FILE")
    return needles


def build_patterns(needles: list[str]) -> list[bytes]:
    """Expand each needle into plain (UTF-8), UTF-16 (LE/BE), base64, and hex bytes."""
    patterns: list[bytes] = []
    seen: set[bytes] = set()

    def _add(raw: bytes) -> None:
        if raw and raw not in seen:
            seen.add(raw)
            patterns.append(raw)

    for needle in needles:
        utf8 = needle.encode("utf-8")
        _add(utf8)
        _add(needle.encode("utf-16-le"))
        _add(needle.encode("utf-16-be"))
        b64_std = base64.b64encode(utf8)
        _add(b64_std)
        _add(base64.urlsafe_b64encode(utf8))
        hex_lo = utf8.hex().encode("ascii")
        _add(hex_lo)
        _add(hex_lo.upper())

    return patterns


def _bytes_match(data: bytes, patterns: list[bytes]) -> bool:
    return any(pat in data for pat in patterns)


def _open_nofollow_readonly(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    return os.open(path, flags)


def is_encrypted_vault_file(path: Path) -> bool:
    """Return True only for genuine WAMSP02 ciphertext .enc envelopes (>= 52 bytes)."""
    if path.suffix != ".enc" or path.is_symlink():
        return False
    fd = None
    try:
        fd = _open_nofollow_readonly(path)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < MIN_ENVELOPE_BYTES:
            return False
        header = os.read(fd, len(WAMSP02_MAGIC))
        return header == WAMSP02_MAGIC
    except OSError:
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def scan_file_for_patterns(path: Path, patterns: list[bytes]) -> tuple[bool, bool]:
    """Scan a single regular non-symlink file in overlapping chunks.

    Returns (scanned, matched). Never returns matched bytes.
    """
    if path.is_symlink():
        return False, False
    overlap = max((len(p) for p in patterns), default=1) - 1
    fd = None
    try:
        fd = _open_nofollow_readonly(path)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            return False, False
        tail = b""
        while True:
            chunk = os.read(fd, CHUNK_BYTES)
            if not chunk:
                break
            buf = tail + chunk
            if _bytes_match(buf, patterns):
                return True, True
            tail = buf[-overlap:] if overlap > 0 else b""
        return True, False
    except OSError:
        return False, False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _plist_value_matches(value: object, patterns: list[bytes]) -> bool:
    stack = [value]
    while stack:
        cur = stack.pop()
        if isinstance(cur, bytes):
            if _bytes_match(cur, patterns):
                return True
        elif isinstance(cur, str):
            if _bytes_match(cur.encode("utf-8", "replace"), patterns):
                return True
        elif isinstance(cur, dict):
            for k, v in cur.items():
                stack.append(k)
                stack.append(v)
        elif isinstance(cur, (list, tuple)):
            stack.extend(cur)
    return False


def scan_plist_file(path: Path, patterns: list[bytes]) -> tuple[bool, bool]:
    """Scan raw bytes and decoded plist strings/data of a preference file."""
    scanned, matched = scan_file_for_patterns(path, patterns)
    if matched:
        return True, True
    if not scanned or path.suffix != ".plist":
        return scanned, False
    fd = None
    try:
        fd = _open_nofollow_readonly(path)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PLIST_BYTES:
            return scanned, False
        raw = os.read(fd, info.st_size)
    except OSError:
        return scanned, False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    try:
        parsed = plistlib.loads(raw)
    except Exception:
        return scanned, False
    return True, _plist_value_matches(parsed, patterns)


def _walk_regular_files(
    root: Path,
    *,
    since_epoch: float | None = None,
    skip_resolved: set[Path] | None = None,
    skip_vault_enc: bool = False,
) -> list[Path]:
    files: list[Path] = []
    skip = skip_resolved or set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current_dir = Path(dirpath)
        kept_dirs: list[str] = []
        for dname in sorted(dirnames):
            cand = current_dir / dname
            if cand.is_symlink():
                continue
            try:
                if cand.resolve() in skip:
                    continue
            except OSError:
                continue
            kept_dirs.append(dname)
        dirnames[:] = kept_dirs

        for fname in sorted(filenames):
            fpath = current_dir / fname
            if fpath.is_symlink():
                continue
            try:
                resolved = fpath.resolve()
                if resolved in skip:
                    continue
                st = fpath.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if since_epoch is not None and st.st_mtime < since_epoch:
                continue
            if skip_vault_enc and is_encrypted_vault_file(fpath):
                continue
            files.append(fpath)
    return files


def _scan_file_list(
    paths: list[Path],
    patterns: list[bytes],
    *,
    plist_mode: bool = False,
) -> dict[str, object]:
    checked = 0
    matched_paths: list[str] = []
    scanner = scan_plist_file if plist_mode else scan_file_for_patterns
    for path in paths:
        scanned, hit = scanner(path, patterns)
        if scanned:
            checked += 1
        if hit:
            matched_paths.append(str(path))
    matched_paths.sort()
    return {
        "checked_paths_count": checked,
        "matches_count": len(matched_paths),
        "matched_paths": matched_paths,
        "status": "FAIL" if matched_paths else "PASS",
    }


def _skipped(reason: str, *, extra: dict[str, object] | None = None) -> dict[str, object]:
    out: dict[str, object] = {
        "checked_paths_count": 0,
        "matches_count": 0,
        "matched_paths": [],
        "status": f"SKIPPED({reason})",
    }
    if extra:
        out.update(extra)
    return out


def check_logs_and_app_support(
    logs_dir: Path,
    app_support_dir: Path,
    patterns: list[bytes],
    *,
    since_epoch: float,
    skip_resolved: set[Path],
) -> dict[str, object]:
    """Check ~/Library/Logs (WAM*/Python*/DiagnosticReports) and WAM App Support."""
    has_logs = logs_dir.is_dir() and not logs_dir.is_symlink()
    has_support = app_support_dir.is_dir() and not app_support_dir.is_symlink()
    if not has_logs and not has_support:
        return _skipped("logs directory not found")

    targets: list[Path] = []
    if has_logs:
        try:
            entries = sorted(logs_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            return _skipped("logs directory unreadable")
        for entry in entries:
            if entry.is_symlink():
                continue
            low = entry.name.lower()
            if entry.name == "DiagnosticReports":
                if entry.is_dir():
                    targets.extend(
                        _walk_regular_files(
                            entry, since_epoch=since_epoch, skip_resolved=skip_resolved
                        )
                    )
            elif low.startswith(("wam", "python")):
                if entry.is_dir():
                    targets.extend(
                        _walk_regular_files(
                            entry, since_epoch=since_epoch, skip_resolved=skip_resolved
                        )
                    )
                elif entry.is_file():
                    try:
                        if entry.lstat().st_mtime >= since_epoch and entry.resolve() not in skip_resolved:
                            targets.append(entry)
                    except OSError:
                        pass

    if has_support:
        try:
            support_entries = sorted(app_support_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            support_entries = []
        for entry in support_entries:
            if entry.is_symlink():
                continue
            if entry.name.lower().startswith("wam") and entry.is_dir():
                targets.extend(
                    _walk_regular_files(
                        entry, since_epoch=None, skip_resolved=skip_resolved
                    )
                )

    return _scan_file_list(targets, patterns)


def check_data_dir(
    data_dir: Path,
    patterns: list[bytes],
    *,
    skip_resolved: set[Path],
) -> dict[str, object]:
    """Check --data-dir tree excluding genuine encrypted vault/ciphertext .enc files."""
    files = _walk_regular_files(
        data_dir,
        since_epoch=None,
        skip_resolved=skip_resolved,
        skip_vault_enc=True,
    )
    return _scan_file_list(files, patterns)


def check_preferences(
    prefs_dir: Path,
    patterns: list[bytes],
    *,
    skip_resolved: set[Path],
) -> dict[str, object]:
    """Check macOS preference plists for app bundle IDs / QSettings store + WAM_UI_SETTINGS_PATH."""
    env_ini = os.environ.get("WAM_UI_SETTINGS_PATH")
    has_prefs = prefs_dir.is_dir() and not prefs_dir.is_symlink()
    targets: list[Path] = []

    if has_prefs:
        try:
            entries = sorted(prefs_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            return _skipped("preferences directory unreadable")
        for entry in entries:
            if entry.is_symlink() or not entry.is_file():
                continue
            if entry.suffix == ".plist" and entry.name.startswith(PREF_PREFIXES):
                try:
                    if entry.resolve() not in skip_resolved:
                        targets.append(entry)
                except OSError:
                    pass
    elif not env_ini:
        return _skipped("preferences directory not found")

    if env_ini:
        ini_path = Path(env_ini)
        if ini_path.is_file() and not ini_path.is_symlink():
            try:
                if ini_path.resolve() not in skip_resolved:
                    targets.append(ini_path)
            except OSError:
                pass

    return _scan_file_list(targets, patterns, plist_mode=True)


def check_clipboard(patterns: list[bytes]) -> dict[str, object]:
    """Check current pasteboard content via pbpaste; reports true/false only."""
    try:
        res = subprocess.run(
            ["pbpaste"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return _skipped("pbpaste unavailable", extra={"contains_needle": False})
    if res.returncode != 0:
        return _skipped("pbpaste failed", extra={"contains_needle": False})
    hit = _bytes_match(res.stdout, patterns)
    return {
        "checked_paths_count": 1,
        "matches_count": 1 if hit else 0,
        "matched_paths": [],
        "contains_needle": bool(hit),
        "status": "FAIL" if hit else "PASS",
    }


def _extract_command_head(args_str: str) -> str:
    tokens = args_str.split()
    head: list[str] = []
    for tok in tokens:
        if _ENV_TOKEN_RE.match(tok):
            break
        head.append(tok)
    return " ".join(head)


def _is_target_process(args_str: str, pid: int | None, self_pid: int) -> bool:
    if pid is not None and pid == self_pid:
        return False
    if "qualify_q20_dynamic.py" in args_str:
        return False
    cmd_head = _extract_command_head(args_str) or args_str
    if "WAM Privacy Wallet" in cmd_head:
        return True
    for tok in cmd_head.split():
        base = os.path.basename(tok)
        if base in ("wamd", "wam-cli"):
            return True
        if any(marker in tok for marker in ("wam_regtest", "production_entry", "package_entry")):
            return True
    return False


def check_processes(patterns: list[bytes]) -> dict[str, object]:
    """Check 'ps -Eww -x -o pid=,args=' for running wamd/wam-cli/app processes."""
    try:
        res = subprocess.run(
            ["ps", "-Eww", "-x", "-o", "pid=,args="],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return _skipped("ps unavailable", extra={"contains_needle": False})
    if res.returncode != 0:
        return _skipped("ps failed", extra={"contains_needle": False})

    self_pid = os.getpid()
    text = res.stdout.decode("utf-8", "replace")
    checked = 0
    hit = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.upper() in ("ARGS", "PID ARGS"):
            continue
        match = _PID_LINE_RE.match(line)
        if match:
            pid = int(match.group(1))
            args_str = match.group(2)
        else:
            pid = None
            args_str = line
        if not _is_target_process(args_str, pid, self_pid):
            continue
        checked += 1
        if _bytes_match(args_str.encode("utf-8", "replace"), patterns):
            hit = True

    return {
        "checked_paths_count": checked,
        "matches_count": 1 if hit else 0,
        "matched_paths": [],
        "contains_needle": bool(hit),
        "status": "FAIL" if hit else "PASS",
    }


def check_temp(
    tmpdir: Path,
    patterns: list[bytes],
    *,
    since_epoch: float,
    skip_resolved: set[Path],
) -> dict[str, object]:
    """Check $TMPDIR regular files modified in the run window."""
    if not tmpdir.is_dir() or tmpdir.is_symlink():
        return _skipped("tmpdir not found")
    try:
        os.listdir(tmpdir)
    except OSError:
        return _skipped("tmpdir unreadable")
    files = _walk_regular_files(
        tmpdir, since_epoch=since_epoch, skip_resolved=skip_resolved
    )
    return _scan_file_list(files, patterns)


def _write_private_json(output_path: Path, payload: dict[str, object]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(output_path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise OSError("Q20_DYNAMIC_OUTPUT_WRITE_DENIED")
            offset += written
    finally:
        os.close(fd)


def run_sweep(
    *,
    needles_file: Path,
    data_dir: Path,
    output_path: Path,
    logs_dir: Path | None = None,
    app_support_dir: Path | None = None,
    prefs_dir: Path | None = None,
    tmpdir: Path | None = None,
    window_minutes: float = 120.0,
    since_epoch: float | None = None,
) -> tuple[dict[str, object], list[str]]:
    """Execute the full Q20 dynamic privacy sweep and write the private JSON receipt."""
    if not data_dir.is_dir() or data_dir.is_symlink():
        raise ValueError("Q20_DYNAMIC_DATA_DIR_DENIED")
    needles = load_needles(needles_file)
    patterns = build_patterns(needles)

    now_epoch = time.time()
    effective_since = (
        since_epoch if since_epoch is not None else now_epoch - (window_minutes * 60.0)
    )

    resolved_data = data_dir.resolve()
    resolved_needles = needles_file.resolve()
    resolved_output = output_path.resolve()
    skip_common = {resolved_needles, resolved_output}
    skip_temp = {resolved_needles, resolved_output, resolved_data}

    home = Path.home()
    resolved_logs = logs_dir if logs_dir is not None else home / "Library" / "Logs"
    resolved_support = (
        app_support_dir
        if app_support_dir is not None
        else home / "Library" / "Application Support"
    )
    resolved_prefs = (
        prefs_dir if prefs_dir is not None else home / "Library" / "Preferences"
    )
    resolved_tmp = (
        tmpdir
        if tmpdir is not None
        else Path(os.environ.get("TMPDIR") or tempfile.gettempdir())
    )

    checks = {
        "logs_crash_reports": check_logs_and_app_support(
            resolved_logs,
            resolved_support,
            patterns,
            since_epoch=effective_since,
            skip_resolved=skip_common,
        ),
        "data_dir": check_data_dir(
            data_dir, patterns, skip_resolved=skip_common
        ),
        "preferences": check_preferences(
            resolved_prefs, patterns, skip_resolved=skip_common
        ),
        "clipboard": check_clipboard(patterns),
        "processes": check_processes(patterns),
        "temp": check_temp(
            resolved_tmp,
            patterns,
            since_epoch=effective_since,
            skip_resolved=skip_temp,
        ),
        "shell_history": _skipped("out of scope: owner's shell"),
    }

    active = [
        chk for chk in checks.values() if not str(chk["status"]).startswith("SKIPPED")
    ]
    overall_pass = bool(active) and all(
        chk["status"] == "PASS" and chk["matches_count"] == 0 for chk in active
    )

    report: dict[str, object] = {
        "schema": SCHEMA,
        "status": "PASS" if overall_pass else "FAIL",
        "overall_pass": overall_pass,
        "mainnet_allowed": False,
        "matched_content_recorded": False,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "since_epoch": effective_since,
        "window_minutes": window_minutes,
        "data_dir": str(data_dir),
        "needles_count": len(needles),
        "checks": checks,
    }
    _write_private_json(output_path, report)

    stdout_lines: list[str] = []
    for name, chk in checks.items():
        line = (
            f"Q20_DYNAMIC_CHECK {name} status={chk['status']} "
            f"checked={chk['checked_paths_count']} matches={chk['matches_count']}"
        )
        if "contains_needle" in chk:
            line += f" contains_needle={'true' if chk['contains_needle'] else 'false'}"
        stdout_lines.append(line)
    stdout_lines.append("Q20_DYNAMIC_SWEEP_PASS" if overall_pass else "Q20_DYNAMIC_SWEEP_FAIL")
    return report, stdout_lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Q20 dynamic privacy sweep (read-only; never prints secrets)."
    )
    parser.add_argument("--needles-file", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--window-minutes", type=float, default=120.0)
    parser.add_argument("--since-epoch", type=float, default=None)
    parser.add_argument("--logs-dir", type=Path, default=None)
    parser.add_argument("--app-support-dir", type=Path, default=None)
    parser.add_argument("--prefs-dir", type=Path, default=None)
    parser.add_argument("--tmpdir", type=Path, default=None)
    args = parser.parse_args(argv)

    try:
        report, stdout_lines = run_sweep(
            needles_file=args.needles_file,
            data_dir=args.data_dir,
            output_path=args.output,
            logs_dir=args.logs_dir,
            app_support_dir=args.app_support_dir,
            prefs_dir=args.prefs_dir,
            tmpdir=args.tmpdir,
            window_minutes=args.window_minutes,
            since_epoch=args.since_epoch,
        )
    except ValueError as err:
        code = err.args[0] if err.args and str(err.args[0]).startswith("Q20_DYNAMIC_") else "Q20_DYNAMIC_DENIED"
        print(code, file=sys.stderr)
        return 2
    except OSError:
        print("Q20_DYNAMIC_IO_DENIED", file=sys.stderr)
        return 2

    for line in stdout_lines:
        print(line, flush=True)
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
