"""Versioned durable quit-notice and acknowledgement store for D-QUIT-1.

Stores bounded, non-secret quit/stop diagnostic notices and acknowledgements
inside the supervisor root's private directory using unpredictable staging
files, F_FULLFSYNC, create-only hardlinks, and the held exclusive_lease(root).
"""
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

from .core_supervisor import DIAGNOSTIC_CODES as _CORE_DIAGNOSTIC_CODES
from .fullflush import flush_directory, full_flush
from .supervisor_protocol import _distinct
from .supervisor_store import (
    MAX_CONTROL_FILE,
    SupervisorStorageError,
    _posix_dir,
    _posix_file,
    _root,
    held_lease,
)

NOTICE_SCHEMA = 'wam.fusion.quit-notice.v1'
MAX_NOTICES = 64
MAX_ACKS = 1024
MAX_CODES = 8

SESSION_KINDS = frozenset(('Q05', 'Q06'))
WALLET_OUTCOMES = frozenset(('RUNTIME_PRESERVED', 'CLEANUP_UNCERTAIN', 'NONE'))
CORE_STOP_OUTCOMES = frozenset(('CLEAN', 'UNCERTAIN', 'BLOCKED', 'NOT_ATTEMPTED'))

QUIT_LOCK_CODES = frozenset((
    'Q06_SPEND_RUNTIME_PRESERVED',
    'Q06_SPEND_RUNTIME_UNCERTAIN',
    'Q06_SPEND_UNCERTAIN_LOCK_RETAINED',
    'WALLET_MANAGED_RUNTIME_PRESERVED',
    'WALLET_LOCK_CLEANUP_UNCERTAIN',
    'WALLET_MANAGED_OWNER_THREAD_REQUIRED',
    'WALLET_MANAGED_OWNER_UNVERIFIED',
    'MANAGED_STOP_NOT_ALLOWED',
    'MANAGED_RECOVERY_ORIGINAL_OWNER_REQUIRED',
    'MANAGED_DEAD_OWNER_RECOVERY_REQUIRED',
    'MANAGED_PROFILE_DENIED',
    'MANAGED_LIVE_OWNER_CLOSE_DENIED',
    'MANAGED_UNCLASSIFIED_FAILURE',
    'CORE_RPC_TIMEOUT_UNCERTAIN',
    'CORE_RPC_PROCESS_IDENTITY_DENIED',
    'CORE_RPC_CREDENTIAL_CHANGED_OR_UNSAFE',
    'CORE_RPC_OWNED_SCOPE_REQUIRED',
    'CORE_RPC_REAUTHENTICATION_REQUIRED',
    'CORE_RPC_CLI_SCOPE_DENIED',
    'RPC_OWNED_PROCESS_REQUIRED',
    'RPC_SOCKET_PROOF_DENIED',
    'RPC_SOCKET_TABLE_DENIED',
    'RPC_SOCKET_TABLE_CHANGED',
    'RPC_NATIVE_PROCESS_PROOF_REQUIRED',
    'RPC_LOOPBACK_SOCKET_REQUIRED',
    'RPC_EXECUTABLE_CUSTODY_DENIED',
    'RPC_EXECUTABLE_METADATA_DENIED',
    'Q06_GUI_RUNTIME_PRESERVED',
    'Q06_GUI_SCANNER_LOCK_UNCERTAIN',
))

NOTICE_CODE_ALLOWLIST = frozenset(_CORE_DIAGNOSTIC_CODES) | QUIT_LOCK_CODES

NOTICE_KEYS = frozenset((
    'schema',
    'seq',
    'profile_id',
    'session_kind',
    'created_utc',
    'wallet_outcome',
    'core_stop',
    'codes',
    'journal_seq',
    'body_sha256',
))

ACK_NOTICE_KEYS = frozenset(('kind', 'seq', 'body_sha256'))
ACK_UNREADABLE_KEYS = frozenset(('kind', 'name', 'raw_sha256', 'size'))

_RE_NOTICE = re.compile(r'supervisor\.notice\.([0-9]{6})')
_RE_ACK = re.compile(r'supervisor\.notice-ack\.([0-9]{6})')
_RE_STAGE = re.compile(r'supervisor\.notice\.stage-([0-9a-f]{16})')
_RE_ARTIFACT_NAME = re.compile(
    r'supervisor\.notice.*|supervisor\.failure'
)
_RE_HEX32 = re.compile(r'[0-9a-f]{32}')
_RE_HEX64 = re.compile(r'[0-9a-f]{64}')
_RE_UTC_SEC = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
_STAT_FIELDS = (
    'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink',
    'st_size', 'st_mtime_ns', 'st_ctime_ns',
)


class QuitNoticeError(ValueError):
    """Fail-closed quit-notice store error with fixed public codes."""


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(',', ':'), ensure_ascii=True
    ).encode('ascii')


def _deny_constant(_token):
    raise ValueError('QUIT_NOTICE_JSON_CONSTANT_DENIED')


def _loads_strict_json(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_CONTROL_FILE:
        raise QuitNoticeError('QUIT_NOTICE_SIZE_DENIED')
    try:
        text = raw.decode('ascii')
        obj = json.loads(
            text, object_pairs_hook=_distinct, parse_constant=_deny_constant
        )
    except (UnicodeDecodeError, ValueError, TypeError):
        raise QuitNoticeError('QUIT_NOTICE_JSON_DENIED') from None
    if type(obj) is not dict:
        raise QuitNoticeError('QUIT_NOTICE_SHAPE_DENIED')
    if raw != _canonical(obj):
        raise QuitNoticeError('QUIT_NOTICE_CANONICAL_DENIED')
    return obj


def _check_acl(fd):
    if sys.platform == 'darwin':
        from .private_directory import _require_absent_acl
        _require_absent_acl(fd)
    else:
        from .linux_private_storage import _no_acl
        _no_acl(fd)


def _win_lease_held(root):
    """Return True iff THIS process holds exclusive_lease(root) on Windows."""
    record = held_lease(root)
    if (record is None or record.get('platform') != 'win32'
            or 'handle' not in record or 'file_id' not in record or 'dir_id' not in record):
        return False
    import ctypes
    from . import windows_private_storage as native
    native.require_native()
    with native.directory_guard(root) as dir_handle:
        dir_info = native._metadata(dir_handle, directory=True)
        if dir_info[:3] != record['dir_id']:
            raise QuitNoticeError('QUIT_NOTICE_LEASE_INVALID')
        try:
            held_info = native._metadata(record['handle'])
            native.verify_security(record['handle'])
        except (OSError, ValueError):
            raise QuitNoticeError('QUIT_NOTICE_LEASE_INVALID') from None
        if held_info[3] != 0 or held_info[:3] != record['file_id']:
            raise QuitNoticeError('QUIT_NOTICE_LEASE_INVALID')
        # Probe OPEN_EXISTING with share=0: must fail with ERROR_SHARING_VIOLATION (32).
        probe = native.create(str(root / 'supervisor.lock'), 0xc0000000, 0, None, 3, 0x200080, None)
        if probe not in (None, native.INVALID):
            native.close(probe)
            return False
        err = ctypes.get_last_error()
        if err == 2:  # ERROR_FILE_NOT_FOUND
            return False
        if err != 32:  # Not ERROR_SHARING_VIOLATION -> ambiguous/denied
            raise QuitNoticeError('QUIT_NOTICE_LEASE_INVALID')
        after = native._metadata(record['handle'])
        if after[3] != 0 or after[:3] != record['file_id']:
            raise QuitNoticeError('QUIT_NOTICE_LEASE_INVALID')
        return True


def _lease_held(root):
    """Return True iff THIS process holds exclusive_lease(root) on the same lock file."""
    root = _root(root)
    if sys.platform == 'win32':
        return _win_lease_held(root)
    record = held_lease(root)
    if record is None:
        return False
    import fcntl
    with _posix_dir(root) as directory:
        dir_info = os.fstat(directory)
        if dir_info.st_dev != record['dir_dev'] or dir_info.st_ino != record['dir_ino']:
            raise QuitNoticeError('QUIT_NOTICE_LEASE_INVALID')
        try:
            held_info = os.fstat(record['fd'])
        except OSError:
            return False
        if (not stat.S_ISREG(held_info.st_mode) or held_info.st_size != 0
                or held_info.st_dev != record['dev'] or held_info.st_ino != record['ino']):
            raise QuitNoticeError('QUIT_NOTICE_LEASE_INVALID')
        try:
            handle = _posix_file(directory, 'supervisor.lock', create=False)
        except FileNotFoundError:
            return False
        except SupervisorStorageError:
            raise QuitNoticeError('QUIT_NOTICE_LEASE_INVALID') from None
        try:
            info = os.fstat(handle)
            if (info.st_size != 0 or info.st_dev != record['dev']
                    or info.st_ino != record['ino']):
                raise QuitNoticeError('QUIT_NOTICE_LEASE_INVALID')
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                after = os.stat('supervisor.lock', dir_fd=directory, follow_symlinks=False)
                if after.st_ino != record['ino'] or after.st_dev != record['dev']:
                    raise QuitNoticeError('QUIT_NOTICE_LEASE_INVALID')
                return True
            try:
                return False
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            os.close(handle)


def assert_exclusive_lease(root):
    """Refuse unless THIS process holds exclusive_lease(root); never acquire it."""
    try:
        held = _lease_held(root)
    except SupervisorStorageError:
        raise QuitNoticeError('QUIT_NOTICE_LEASE_REQUIRED') from None
    if not held:
        raise QuitNoticeError('QUIT_NOTICE_LEASE_REQUIRED')


def _utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def validate_notice_record(obj, *, expected_seq=None, expected_profile_id=None):
    """Validate a parsed wam.fusion.quit-notice.v1 record; return a copy."""
    if type(obj) is not dict or set(obj) != NOTICE_KEYS:
        raise QuitNoticeError('QUIT_NOTICE_KEYS_DENIED')
    if obj['schema'] != NOTICE_SCHEMA:
        raise QuitNoticeError('QUIT_NOTICE_SCHEMA_DENIED')
    seq = obj['seq']
    if type(seq) is not int or not 1 <= seq <= MAX_NOTICES:
        raise QuitNoticeError('QUIT_NOTICE_SEQ_DENIED')
    if expected_seq is not None and seq != expected_seq:
        raise QuitNoticeError('QUIT_NOTICE_SEQ_MISMATCH')
    profile_id = obj['profile_id']
    if type(profile_id) is not str or _RE_HEX32.fullmatch(profile_id) is None:
        raise QuitNoticeError('QUIT_NOTICE_PROFILE_DENIED')
    if expected_profile_id is not None and profile_id != expected_profile_id:
        raise QuitNoticeError('QUIT_NOTICE_PROFILE_MISMATCH')
    if type(obj['session_kind']) is not str or obj['session_kind'] not in SESSION_KINDS:
        raise QuitNoticeError('QUIT_NOTICE_SESSION_KIND_DENIED')
    created_utc = obj['created_utc']
    if type(created_utc) is not str or _RE_UTC_SEC.fullmatch(created_utc) is None:
        raise QuitNoticeError('QUIT_NOTICE_TIMESTAMP_DENIED')
    try:
        datetime.strptime(created_utc, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        raise QuitNoticeError('QUIT_NOTICE_TIMESTAMP_DENIED') from None
    if type(obj['wallet_outcome']) is not str or obj['wallet_outcome'] not in WALLET_OUTCOMES:
        raise QuitNoticeError('QUIT_NOTICE_WALLET_OUTCOME_DENIED')
    if type(obj['core_stop']) is not str or obj['core_stop'] not in CORE_STOP_OUTCOMES:
        raise QuitNoticeError('QUIT_NOTICE_CORE_STOP_DENIED')
    codes = obj['codes']
    if (type(codes) is not list or len(codes) > MAX_CODES
            or any(type(c) is not str or c not in NOTICE_CODE_ALLOWLIST for c in codes)
            or len(set(codes)) != len(codes)):
        raise QuitNoticeError('QUIT_NOTICE_CODE_DENIED')
    journal_seq = obj['journal_seq']
    if type(journal_seq) is not int or not 0 <= journal_seq <= 100000:
        raise QuitNoticeError('QUIT_NOTICE_JOURNAL_SEQ_DENIED')
    body_sha256 = obj['body_sha256']
    if type(body_sha256) is not str or _RE_HEX64.fullmatch(body_sha256) is None:
        raise QuitNoticeError('QUIT_NOTICE_HASH_DENIED')
    body = {k: v for k, v in obj.items() if k != 'body_sha256'}
    if body_sha256 != sha256(_canonical(body)).hexdigest():
        raise QuitNoticeError('QUIT_NOTICE_HASH_MISMATCH')
    return dict(obj, codes=list(codes))


def parse_notice_bytes(raw, *, expected_seq=None, expected_profile_id=None):
    obj = _loads_strict_json(raw)
    return validate_notice_record(
        obj, expected_seq=expected_seq, expected_profile_id=expected_profile_id
    )


def validate_ack_record(obj):
    """Validate a parsed supervisor.notice-ack record; return a copy."""
    if type(obj) is not dict:
        raise QuitNoticeError('QUIT_NOTICE_ACK_SHAPE_DENIED')
    kind = obj.get('kind')
    if kind == 'notice':
        if set(obj) != ACK_NOTICE_KEYS:
            raise QuitNoticeError('QUIT_NOTICE_ACK_KEYS_DENIED')
        seq = obj['seq']
        body_sha256 = obj['body_sha256']
        if type(seq) is not int or not 1 <= seq <= MAX_NOTICES:
            raise QuitNoticeError('QUIT_NOTICE_ACK_SEQ_DENIED')
        if type(body_sha256) is not str or _RE_HEX64.fullmatch(body_sha256) is None:
            raise QuitNoticeError('QUIT_NOTICE_ACK_HASH_DENIED')
        return dict(obj)
    if kind == 'unreadable':
        if set(obj) != ACK_UNREADABLE_KEYS:
            raise QuitNoticeError('QUIT_NOTICE_ACK_KEYS_DENIED')
        name = obj['name']
        raw_sha256 = obj['raw_sha256']
        size = obj['size']
        if (type(name) is not str or not name or len(name) > 128
                or '/' in name or '\\' in name or '\x00' in name or '..' in name
                or _RE_ARTIFACT_NAME.fullmatch(name) is None):
            raise QuitNoticeError('QUIT_NOTICE_ACK_NAME_DENIED')
        if type(raw_sha256) is not str or _RE_HEX64.fullmatch(raw_sha256) is None:
            raise QuitNoticeError('QUIT_NOTICE_ACK_HASH_DENIED')
        if type(size) is not int or not 0 <= size <= MAX_CONTROL_FILE:
            raise QuitNoticeError('QUIT_NOTICE_ACK_SIZE_DENIED')
        return dict(obj)
    raise QuitNoticeError('QUIT_NOTICE_ACK_KIND_DENIED')


def build_notice(
    *,
    seq,
    profile_id,
    session_kind,
    wallet_outcome,
    core_stop,
    codes=(),
    journal_seq=0,
    created_utc=None,
):
    """Build and strictly validate a canonical wam.fusion.quit-notice.v1 dict."""
    if type(codes) not in (list, tuple, set, frozenset):
        raise QuitNoticeError('QUIT_NOTICE_CODE_DENIED')
    code_list = sorted(set(codes))
    if any(type(c) is not str or c not in NOTICE_CODE_ALLOWLIST for c in code_list):
        raise QuitNoticeError('QUIT_NOTICE_CODE_DENIED')
    if len(code_list) > MAX_CODES:
        raise QuitNoticeError('QUIT_NOTICE_CODE_DENIED')
    body = {
        'schema': NOTICE_SCHEMA,
        'seq': seq,
        'profile_id': profile_id,
        'session_kind': session_kind,
        'created_utc': _utc_now() if created_utc is None else created_utc,
        'wallet_outcome': wallet_outcome,
        'core_stop': core_stop,
        'codes': code_list,
        'journal_seq': journal_seq,
    }
    raw_body = _canonical(body)
    body['body_sha256'] = sha256(raw_body).hexdigest()
    validated = validate_notice_record(body, expected_seq=seq, expected_profile_id=profile_id)
    if len(_canonical(validated)) > MAX_CONTROL_FILE:
        raise QuitNoticeError('QUIT_NOTICE_SIZE_DENIED')
    return validated


def _win_durable_publish(root, *, candidate_seq, max_seq, final_fmt, build_payload):
    """Native Win32 create-new private stage, FlushFileBuffers, and atomic non-replacing rename."""
    import ctypes as c
    from ctypes import wintypes as w
    from . import windows_private_storage as native
    native.require_native()
    with native.directory_guard(root):
        seq = candidate_seq
        while seq <= max_seq:
            record, raw = build_payload(seq)
            if len(raw) > MAX_CONTROL_FILE:
                raise QuitNoticeError('QUIT_NOTICE_SIZE_DENIED')
            stage = 'supervisor.notice.stage-' + secrets.token_hex(8)
            final = final_fmt.format(seq)
            handle = None
            try:
                with native.security_attributes() as sa:
                    # GENERIC_READ|GENERIC_WRITE|DELETE (0xC0010000), share=0, CREATE_NEW (1),
                    # FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT (0x200080).
                    handle = native.create(str(root / stage), 0xc0010000, 0, sa, 1, 0x200080, None)
                if handle in (None, native.INVALID):
                    handle = None
                    raise QuitNoticeError('QUIT_NOTICE_PUBLISH_DENIED')
                native._metadata(handle)
                native.verify_security(handle)
                offset = 0
                while offset < len(raw):
                    chunk = raw[offset:]
                    written = w.DWORD()
                    if not native.write(handle, chunk, len(chunk), c.byref(written), None) or not written.value:
                        raise QuitNoticeError('QUIT_NOTICE_PUBLISH_DENIED')
                    offset += written.value
                if not native.flush(handle):
                    raise QuitNoticeError('QUIT_NOTICE_PUBLISH_DENIED')
                # Same-directory non-replacing rename via NtSetInformationFile (FileRenameInformation=10).
                text = final.encode('utf-16-le')
                buf = c.create_string_buffer(c.sizeof(native.RENAME) + len(text))
                rename = native.RENAME.from_buffer(buf)
                rename.flags = 0
                rename.root = None
                rename.length = len(text)
                c.memmove(c.addressof(buf) + native.RENAME.name.offset, text, len(text))
                io_status = native.IO_STATUS()
                nt_status = native.rename_native(handle, c.byref(io_status), buf, len(buf), 10)
                if nt_status == 0:
                    native._metadata(handle)
                    native.verify_security(handle)
                    if not native.flush(handle):
                        raise QuitNoticeError('QUIT_NOTICE_PUBLISH_DENIED')
                    return record
                if (nt_status & 0xFFFFFFFF) == 0xC0000035:  # STATUS_OBJECT_NAME_COLLISION
                    # Target final seq already exists; remove only our unrenamed stage and advance seq.
                    disposition = native.DISPOSITION(True)
                    if not native.setinfo(handle, 4, c.byref(disposition), c.sizeof(disposition)):
                        raise QuitNoticeError('QUIT_NOTICE_PUBLISH_DENIED')
                    seq += 1
                    continue
                # Any ambiguous rename failure retains the stage for fail-closed reader visibility.
                raise QuitNoticeError('QUIT_NOTICE_PUBLISH_DENIED')
            finally:
                if handle is not None:
                    native.close(handle)
        raise QuitNoticeError('QUIT_NOTICE_CAPACITY_REACHED')


def _durable_publish(root, *, candidate_seq, max_seq, final_fmt, build_payload):
    assert_exclusive_lease(root)
    if sys.platform == 'win32':
        return _win_durable_publish(
            root,
            candidate_seq=candidate_seq,
            max_seq=max_seq,
            final_fmt=final_fmt,
            build_payload=build_payload,
        )
    with _posix_dir(root) as dfd:
        seq = candidate_seq
        while seq <= max_seq:
            record, raw = build_payload(seq)
            if len(raw) > MAX_CONTROL_FILE:
                raise QuitNoticeError('QUIT_NOTICE_SIZE_DENIED')
            stage = 'supervisor.notice.stage-' + secrets.token_hex(8)
            final = final_fmt.format(seq)
            fd = os.open(
                stage,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=dfd,
            )
            try:
                os.fchmod(fd, 0o600)
                offset = 0
                while offset < len(raw):
                    written = os.write(fd, raw[offset:])
                    if written <= 0:
                        raise OSError('QUIT_NOTICE_SHORT_WRITE')
                    offset += written
                full_flush(fd)
            finally:
                os.close(fd)
            try:
                os.link(stage, final, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
            except FileExistsError:
                os.unlink(stage, dir_fd=dfd)
                seq += 1
                continue
            # I3-N3: once os.link succeeds, the notice file exists on disk
            # (with st_nlink==2 until stage unlink). If either flush_directory or
            # os.unlink fails below, publication intentionally still fails
            # closed (raising QUIT_NOTICE_PUBLISH_DENIED -> NOTICE_PERSIST_FAILED)
            # so the owner/lease is retained; a later lease-holding reader
            # accepts the linked notice and completes the stage unlink.
            flush_directory(dfd)
            os.unlink(stage, dir_fd=dfd)
            flush_directory(dfd)
            return record
        raise QuitNoticeError('QUIT_NOTICE_CAPACITY_REACHED')


def _scan_notice_seqs(root, pattern):
    seqs = []
    for entry in Path(root).iterdir():
        match = pattern.fullmatch(entry.name)
        if match is not None:
            seqs.append(int(match.group(1)))
    return seqs


def publish_notice(
    root,
    *,
    profile_id,
    session_kind,
    wallet_outcome,
    core_stop,
    codes=(),
    journal_seq=0,
    created_utc=None,
):
    """Durably publish the next sequential quit notice under exclusive_lease(root)."""
    try:
        assert_exclusive_lease(root)
        seqs = _scan_notice_seqs(root, _RE_NOTICE)
        if len(seqs) >= MAX_NOTICES:
            raise QuitNoticeError('QUIT_NOTICE_CAPACITY_REACHED')
        candidate = max(seqs, default=0) + 1
        if candidate > MAX_NOTICES:
            raise QuitNoticeError('QUIT_NOTICE_CAPACITY_REACHED')

        def make(seq):
            record = build_notice(
                seq=seq,
                profile_id=profile_id,
                session_kind=session_kind,
                wallet_outcome=wallet_outcome,
                core_stop=core_stop,
                codes=codes,
                journal_seq=journal_seq,
                created_utc=created_utc,
            )
            return record, _canonical(record)

        return _durable_publish(
            root,
            candidate_seq=candidate,
            max_seq=MAX_NOTICES,
            final_fmt='supervisor.notice.{:06d}',
            build_payload=make,
        )
    except QuitNoticeError:
        raise
    except (SupervisorStorageError, OSError, ValueError):
        raise QuitNoticeError('QUIT_NOTICE_PUBLISH_DENIED') from None


def publish_ack(root, payload):
    """Durably publish one acknowledgement record under exclusive_lease(root)."""
    try:
        assert_exclusive_lease(root)
        validated = validate_ack_record(payload)
        raw = _canonical(validated)
        seqs = _scan_notice_seqs(root, _RE_ACK)
        if len(seqs) >= MAX_ACKS:
            raise QuitNoticeError('QUIT_NOTICE_ACK_CAPACITY_REACHED')
        candidate = max(seqs, default=0) + 1
        if candidate > MAX_ACKS:
            raise QuitNoticeError('QUIT_NOTICE_ACK_CAPACITY_REACHED')
        try:
            return _durable_publish(
                root,
                candidate_seq=candidate,
                max_seq=MAX_ACKS,
                final_fmt='supervisor.notice-ack.{:06d}',
                build_payload=lambda _seq: (validated, raw),
            )
        except QuitNoticeError as err:
            if err.args == ('QUIT_NOTICE_CAPACITY_REACHED',):
                raise QuitNoticeError('QUIT_NOTICE_ACK_CAPACITY_REACHED') from None
            raise
    except QuitNoticeError:
        raise
    except (SupervisorStorageError, OSError, ValueError):
        raise QuitNoticeError('QUIT_NOTICE_ACK_PUBLISH_DENIED') from None


def _open_and_read_entry(dfd, name, *, allow_nlink_two=False, allow_zero_bytes=False):
    """Inspect metadata and read bounded bytes without following symlinks."""
    info = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        return None, None, 'NOTICE_NON_REGULAR_ARTIFACT'
    fd = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dfd
    )
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            return None, None, 'NOTICE_NON_REGULAR_ARTIFACT'
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600:
            return None, before, 'NOTICE_PERMISSION_DENIED'
        try:
            _check_acl(fd)
        except (OSError, ValueError):
            return None, before, 'NOTICE_ACL_DENIED'
        if any(getattr(before, k) != getattr(info, k) for k in _STAT_FIELDS):
            return None, before, 'NOTICE_CHANGED'
        if before.st_nlink == 1:
            pass
        elif allow_nlink_two and before.st_nlink == 2:
            pass
        else:
            if before.st_size <= MAX_CONTROL_FILE:
                raw = _read_bounded(fd, before)
                return raw, before, 'NOTICE_LINK_COUNT_DENIED'
            return None, before, 'NOTICE_LINK_COUNT_DENIED'
        min_size = 0 if allow_zero_bytes else 1
        if not min_size <= before.st_size <= MAX_CONTROL_FILE:
            return None, before, 'NOTICE_SIZE_DENIED'
        raw = _read_bounded(fd, before)
        return raw, before, None
    finally:
        os.close(fd)


def _read_bounded(fd, before):
    chunks = []
    remaining = before.st_size
    while remaining > 0:
        part = os.read(fd, min(remaining, MAX_CONTROL_FILE))
        if not part:
            raise OSError('QUIT_NOTICE_SHORT_READ')
        chunks.append(part)
        remaining -= len(part)
    extra = os.read(fd, 1)
    if extra:
        raise OSError('QUIT_NOTICE_SIZE_CHANGED')
    after = os.fstat(fd)
    if any(getattr(before, k) != getattr(after, k) for k in _STAT_FIELDS):
        raise OSError('QUIT_NOTICE_CHANGED')
    return b''.join(chunks)


def _unreadable_from_bytes(name, raw, stat_info, reason):
    if raw is not None:
        return {
            'kind': 'unreadable',
            'name': name,
            'raw_sha256': sha256(raw).hexdigest(),
            'size': len(raw),
            'reason': reason,
        }
    size = (
        stat_info.st_size
        if stat_info is not None and 0 <= stat_info.st_size <= MAX_CONTROL_FILE
        else 0
    )
    return {
        'kind': 'unreadable',
        'name': name,
        'raw_sha256': sha256(b'').hexdigest(),
        'size': size,
        'reason': reason,
    }


def _safe_raw_hash_for_unreadable(dfd, name):
    """Best-effort hash of a regular untrusted/oversized artifact without following symlinks."""
    try:
        info = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            return sha256(b'').hexdigest(), 0
        if info.st_size > MAX_CONTROL_FILE:
            return sha256(b'').hexdigest(), 0
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dfd
        )
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_CONTROL_FILE:
                return sha256(b'').hexdigest(), 0
            raw = _read_bounded(fd, st)
            return sha256(raw).hexdigest(), len(raw)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        return sha256(b'').hexdigest(), 0


def _collect_stages(dfd, names):
    """Collect valid stage descriptors keyed by (st_dev, st_ino) and raw info."""
    stage_by_inode = {}
    stage_entries = {}
    for name in names:
        if _RE_STAGE.fullmatch(name) is None:
            continue
        try:
            raw, st, err = _open_and_read_entry(
                dfd, name, allow_nlink_two=True, allow_zero_bytes=True
            )
        except (OSError, ValueError):
            raw, st, err = None, None, 'NOTICE_STAGE_UNREADABLE'
        stage_entries[name] = (raw, st, err)
        if err is None and st is not None:
            key = (st.st_dev, st.st_ino)
            stage_by_inode.setdefault(key, []).append(name)
    return stage_by_inode, stage_entries


def _read_failure_record(dfd):
    try:
        os.stat('supervisor.failure', dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    try:
        raw, st, err = _open_and_read_entry(
            dfd, 'supervisor.failure', allow_nlink_two=False, allow_zero_bytes=False
        )
    except (OSError, ValueError):
        digest, size = _safe_raw_hash_for_unreadable(dfd, 'supervisor.failure')
        return {
            'kind': 'unreadable',
            'name': 'supervisor.failure',
            'raw_sha256': digest,
            'size': size,
            'reason': 'NOTICE_FAILURE_UNREADABLE',
        }
    if err is not None:
        if raw is None:
            digest, size = _safe_raw_hash_for_unreadable(dfd, 'supervisor.failure')
            return {
                'kind': 'unreadable',
                'name': 'supervisor.failure',
                'raw_sha256': digest,
                'size': size,
                'reason': err,
            }
        return _unreadable_from_bytes('supervisor.failure', raw, st, err)
    try:
        obj = json.loads(raw.decode('ascii'), object_pairs_hook=_distinct, parse_constant=_deny_constant)
        if (type(obj) is not dict or set(obj) != {'stage', 'code'}
                or type(obj['stage']) is not str
                or re.fullmatch(r'[a-z0-9_-]{1,32}', obj['stage']) is None
                or type(obj['code']) is not str
                or obj['code'] not in NOTICE_CODE_ALLOWLIST):
            raise ValueError('NOTICE_FAILURE_INVALID')
        return {
            'kind': 'failure',
            'name': 'supervisor.failure',
            'raw_sha256': sha256(raw).hexdigest(),
            'size': len(raw),
            'stage': obj['stage'],
            'code': obj['code'],
        }
    except (UnicodeDecodeError, ValueError, TypeError):
        return _unreadable_from_bytes(
            'supervisor.failure', raw, st, 'NOTICE_FAILURE_UNREADABLE'
        )


def _win_open_and_read_entry(root, name, *, allow_zero_bytes=False):
    """Native Win32 pinned-handle metadata, ACL, and bounded read."""
    import ctypes as c
    from ctypes import wintypes as w
    from . import windows_private_storage as native
    native.require_native()
    handle = None
    path_str = str(root / name)
    for attempt in range(3):
        # GENERIC_READ|READ_CONTROL (0x80020000), FILE_SHARE_READ (1), OPEN_EXISTING (3),
        # FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT (0x200080).
        handle = native.create(path_str, 0x80020000, 1, None, 3, 0x200080, None)
        if handle not in (None, native.INVALID):
            break
        handle = None
        err = c.get_last_error()
        if err == 2:  # ERROR_FILE_NOT_FOUND
            raise FileNotFoundError(name)
        if err == 32 and attempt < 2:  # transient ERROR_SHARING_VIOLATION during rename close
            time.sleep(0.01)
            continue
        return None, None, 'NOTICE_UNREADABLE'
    try:
        try:
            before = native._metadata(handle)
        except ValueError:
            return None, None, 'NOTICE_NON_REGULAR_ARTIFACT'
        try:
            native.verify_security(handle)
        except ValueError:
            return None, before, 'NOTICE_ACL_DENIED'
        size = before[3]
        min_size = 0 if allow_zero_bytes else 1
        if not min_size <= size <= MAX_CONTROL_FILE:
            return None, before, 'NOTICE_SIZE_DENIED'
        chunks = []
        remaining = size
        while remaining > 0:
            chunk_size = min(remaining, MAX_CONTROL_FILE)
            buf = c.create_string_buffer(chunk_size)
            count = w.DWORD()
            if not native.readfile(handle, buf, chunk_size, c.byref(count), None) or not count.value:
                return None, before, 'NOTICE_UNREADABLE'
            chunks.append(buf.raw[:count.value])
            remaining -= count.value
        extra_buf = c.create_string_buffer(1)
        extra_count = w.DWORD()
        if not native.readfile(handle, extra_buf, 1, c.byref(extra_count), None):
            return None, before, 'NOTICE_UNREADABLE'
        if extra_count.value:
            return None, before, 'NOTICE_CHANGED'
        try:
            after = native._metadata(handle)
            native.verify_security(handle)
        except ValueError:
            return None, before, 'NOTICE_CHANGED'
        if before != after:
            return None, before, 'NOTICE_CHANGED'
        return b''.join(chunks), before, None
    finally:
        if handle is not None:
            native.close(handle)


def _win_unreadable_from_meta(name, raw, meta, reason):
    if raw is not None:
        return {
            'kind': 'unreadable',
            'name': name,
            'raw_sha256': sha256(raw).hexdigest(),
            'size': len(raw),
            'reason': reason,
        }
    size = meta[3] if meta is not None and 0 <= meta[3] <= MAX_CONTROL_FILE else 0
    return {
        'kind': 'unreadable',
        'name': name,
        'raw_sha256': sha256(b'').hexdigest(),
        'size': size,
        'reason': reason,
    }


def _win_read_failure_record(root):
    try:
        raw, meta, err = _win_open_and_read_entry(root, 'supervisor.failure', allow_zero_bytes=False)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return _win_unreadable_from_meta('supervisor.failure', None, None, 'NOTICE_FAILURE_UNREADABLE')
    if err is not None:
        return _win_unreadable_from_meta('supervisor.failure', raw, meta, err)
    try:
        obj = json.loads(raw.decode('ascii'), object_pairs_hook=_distinct, parse_constant=_deny_constant)
        if (type(obj) is not dict or set(obj) != {'stage', 'code'}
                or type(obj['stage']) is not str
                or re.fullmatch(r'[a-z0-9_-]{1,32}', obj['stage']) is None
                or type(obj['code']) is not str
                or obj['code'] not in NOTICE_CODE_ALLOWLIST):
            raise ValueError('NOTICE_FAILURE_INVALID')
        return {
            'kind': 'failure',
            'name': 'supervisor.failure',
            'raw_sha256': sha256(raw).hexdigest(),
            'size': len(raw),
            'stage': obj['stage'],
            'code': obj['code'],
        }
    except (UnicodeDecodeError, ValueError, TypeError):
        return _win_unreadable_from_meta('supervisor.failure', raw, meta, 'NOTICE_FAILURE_UNREADABLE')


def _win_read_store(root, *, expected_profile_id=None):
    from . import windows_private_storage as native
    native.require_native()
    notices = []
    acks = []
    unreadable = []
    with native.directory_guard(root):
        names = sorted(
            p.name for p in root.iterdir()
            if p.name.startswith('supervisor.notice')
        )
        for name in names:
            if _RE_STAGE.fullmatch(name) is not None:
                try:
                    raw, meta, err = _win_open_and_read_entry(root, name, allow_zero_bytes=True)
                except FileNotFoundError:
                    continue
                except (OSError, ValueError):
                    raw, meta, err = None, None, 'NOTICE_STAGE_UNREADABLE'
                reason = err if err is not None else 'NOTICE_STAGE_ORPHAN'
                unreadable.append(_win_unreadable_from_meta(name, raw, meta, reason))
                continue

            notice_match = _RE_NOTICE.fullmatch(name)
            ack_match = _RE_ACK.fullmatch(name)
            if notice_match is None and ack_match is None:
                try:
                    raw, meta, _ = _win_open_and_read_entry(root, name, allow_zero_bytes=True)
                except (FileNotFoundError, OSError, ValueError):
                    raw, meta = None, None
                unreadable.append(_win_unreadable_from_meta(name, raw, meta, 'NOTICE_UNKNOWN_NAME'))
                continue

            try:
                raw, meta, err = _win_open_and_read_entry(root, name, allow_zero_bytes=False)
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                raw, meta, err = None, None, 'NOTICE_UNREADABLE'

            if err is not None:
                unreadable.append(_win_unreadable_from_meta(name, raw, meta, err))
                continue

            try:
                if notice_match is not None:
                    seq = int(notice_match.group(1))
                    record = parse_notice_bytes(
                        raw, expected_seq=seq, expected_profile_id=expected_profile_id
                    )
                    notices.append({
                        'kind': 'notice',
                        'name': name,
                        'seq': record['seq'],
                        'body_sha256': record['body_sha256'],
                        'notice': record,
                    })
                else:
                    ack_seq = int(ack_match.group(1))
                    if not 1 <= ack_seq <= MAX_ACKS:
                        raise QuitNoticeError('QUIT_NOTICE_ACK_SEQ_DENIED')
                    record = validate_ack_record(_loads_strict_json(raw))
                    acks.append({
                        'ack_seq': ack_seq,
                        'name': name,
                        **record,
                    })
            except QuitNoticeError as exc:
                unreadable.append(_win_unreadable_from_meta(name, raw, meta, exc.args[0]))

        failure = _win_read_failure_record(root)

    return {
        'notices': tuple(notices),
        'acks': tuple(acks),
        'unreadable': tuple(unreadable),
        'failure': failure,
    }


def read_store(root, *, expected_profile_id=None, complete_staged=None):
    """Read notices, acks, unreadable artifacts, and supervisor.failure.

    complete_staged:
      - None (default): complete st_nlink==2 staged publications iff this process
        holds exclusive_lease(root) on the resolved lock file.
      - True: assert this process holds exclusive_lease(root) and complete staged items.
      - False: never unlink stages.
    """
    root = _root(root)
    if complete_staged is True:
        assert_exclusive_lease(root)
        do_complete = True
    elif complete_staged is False:
        do_complete = False
    elif complete_staged is None:
        do_complete = _lease_held(root)
    else:
        raise QuitNoticeError('QUIT_NOTICE_ARGUMENT_DENIED')

    if sys.platform == 'win32':
        return _win_read_store(root, expected_profile_id=expected_profile_id)

    notices = []
    acks = []
    unreadable = []
    paired_stages = set()
    completed_dir = False

    with _posix_dir(root) as dfd:
        names = sorted(
            p.name for p in root.iterdir()
            if p.name.startswith('supervisor.notice')
        )
        stage_by_inode, stage_entries = _collect_stages(dfd, names)

        for name in names:
            if _RE_STAGE.fullmatch(name) is not None:
                continue

            notice_match = _RE_NOTICE.fullmatch(name)
            ack_match = _RE_ACK.fullmatch(name)
            if notice_match is None and ack_match is None:
                digest, size = _safe_raw_hash_for_unreadable(dfd, name)
                unreadable.append({
                    'kind': 'unreadable',
                    'name': name,
                    'raw_sha256': digest,
                    'size': size,
                    'reason': 'NOTICE_UNKNOWN_NAME',
                })
                continue

            try:
                raw, st, err = _open_and_read_entry(
                    dfd, name, allow_nlink_two=True, allow_zero_bytes=False
                )
            except (OSError, ValueError):
                raw, st, err = None, None, 'NOTICE_UNREADABLE'

            if err is not None:
                if raw is None:
                    digest, size = _safe_raw_hash_for_unreadable(dfd, name)
                    unreadable.append({
                        'kind': 'unreadable',
                        'name': name,
                        'raw_sha256': digest,
                        'size': size,
                        'reason': err,
                    })
                else:
                    unreadable.append(_unreadable_from_bytes(name, raw, st, err))
                continue

            matched_stage = None
            if st.st_nlink == 2:
                matches = stage_by_inode.get((st.st_dev, st.st_ino), ())
                if len(matches) != 1:
                    unreadable.append(
                        _unreadable_from_bytes(name, raw, st, 'NOTICE_STAGE_MISMATCH')
                    )
                    continue
                matched_stage = matches[0]

            try:
                if notice_match is not None:
                    seq = int(notice_match.group(1))
                    record = parse_notice_bytes(
                        raw, expected_seq=seq, expected_profile_id=expected_profile_id
                    )
                    item = {
                        'kind': 'notice',
                        'name': name,
                        'seq': record['seq'],
                        'body_sha256': record['body_sha256'],
                        'notice': record,
                    }
                    notices.append(item)
                else:
                    ack_seq = int(ack_match.group(1))
                    if not 1 <= ack_seq <= MAX_ACKS:
                        raise QuitNoticeError('QUIT_NOTICE_ACK_SEQ_DENIED')
                    record = validate_ack_record(_loads_strict_json(raw))
                    acks.append({
                        'ack_seq': ack_seq,
                        'name': name,
                        **record,
                    })
            except QuitNoticeError as exc:
                unreadable.append(
                    _unreadable_from_bytes(name, raw, st, exc.args[0])
                )
                if matched_stage is not None:
                    # Same inode as the final file: one unreadable artifact,
                    # not a second orphan stage. Preserve the stage name
                    # until the unreadable item is acknowledged.
                    paired_stages.add(matched_stage)
                continue

            if matched_stage is not None:
                paired_stages.add(matched_stage)
                if do_complete:
                    try:
                        stage_now = os.stat(
                            matched_stage, dir_fd=dfd, follow_symlinks=False
                        )
                    except OSError:
                        stage_now = None
                    if (stage_now is not None
                            and (stage_now.st_dev, stage_now.st_ino)
                            == (st.st_dev, st.st_ino)):
                        os.unlink(matched_stage, dir_fd=dfd)
                        completed_dir = True

        if completed_dir:
            flush_directory(dfd)

        for stage_name in sorted(stage_entries):
            if stage_name in paired_stages:
                continue
            raw, st, err = stage_entries[stage_name]
            if err is not None:
                if raw is None:
                    digest, size = _safe_raw_hash_for_unreadable(dfd, stage_name)
                    unreadable.append({
                        'kind': 'unreadable',
                        'name': stage_name,
                        'raw_sha256': digest,
                        'size': size,
                        'reason': err,
                    })
                else:
                    unreadable.append(_unreadable_from_bytes(stage_name, raw, st, err))
            else:
                unreadable.append({
                    'kind': 'unreadable',
                    'name': stage_name,
                    'raw_sha256': sha256(raw).hexdigest(),
                    'size': len(raw),
                    'reason': 'NOTICE_STAGE_ORPHAN',
                })

        failure = _read_failure_record(dfd)

    return {
        'notices': tuple(notices),
        'acks': tuple(acks),
        'unreadable': tuple(unreadable),
        'failure': failure,
    }


def unacknowledged(root, *, expected_profile_id=None, complete_staged=None):
    """Return all unresolved notices, unreadable artifacts, and supervisor.failure."""
    store = read_store(
        root,
        expected_profile_id=expected_profile_id,
        complete_staged=complete_staged,
    )
    acked_notices = {
        (a['seq'], a['body_sha256'])
        for a in store['acks']
        if a['kind'] == 'notice'
    }
    acked_unreadable = {
        (a['name'], a['raw_sha256'], a['size'])
        for a in store['acks']
        if a['kind'] == 'unreadable'
    }
    unresolved = []
    for item in store['notices']:
        if (item['seq'], item['body_sha256']) not in acked_notices:
            unresolved.append(item)
    for item in store['unreadable']:
        if (item['name'], item['raw_sha256'], item['size']) not in acked_unreadable:
            unresolved.append(item)
    failure = store['failure']
    if failure is not None:
        key = (failure['name'], failure['raw_sha256'], failure['size'])
        if key not in acked_unreadable:
            unresolved.append(failure)
    return tuple(unresolved)


def acknowledge_unresolved(root, *, expected_profile_id=None):
    """Acknowledge all currently unresolved items under exclusive_lease(root)."""
    assert_exclusive_lease(root)
    unresolved = unacknowledged(
        root, expected_profile_id=expected_profile_id, complete_staged=True
    )
    published = []
    for item in unresolved:
        if item['kind'] == 'notice':
            payload = {
                'kind': 'notice',
                'seq': item['seq'],
                'body_sha256': item['body_sha256'],
            }
        else:
            payload = {
                'kind': 'unreadable',
                'name': item['name'],
                'raw_sha256': item['raw_sha256'],
                'size': item['size'],
            }
        published.append(publish_ack(root, payload))
    return tuple(published)
