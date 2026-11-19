"""Backup acknowledgement sidecar and challenge core.

Wallet domain. May import foundation, custody/security and WSP adapters.
Must not import PySide6, presentation or qualification modules.

The on-disk path, JSON schema, MAC input and error codes are unchanged.
Command routing stays on Bip39ReadOnlyBackend.
"""
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

from wam_regtest import fullflush
from wam_regtest.domain.errors import Q06ReadOnlyError


# ---- Backup-acknowledgement sidecar storage (CUR-003 + CDX-AUD-003) -------
# GUI metadata only: never spending authority, never a seed. The JSON/HMAC
# format is unchanged; only publication and reading are hardened:
#   * the ack directory is reached by native no-follow private-directory
#     walkers (macOS/Linux) or the NTFS DACL guard (Windows);
#   * an unpredictable O_EXCL|O_NOFOLLOW 0600 stage file is written, fsynced,
#     atomically renamed over the target (dir-fd relative on POSIX) and the
#     directory is fsynced where supported;
#   * an existing target that is not a single-link regular owned file
#     without group/other write is refused, never replaced or followed;
#   * reads are bounded and the decoded record is validated strictly.
# Retained profiles are never modified, repaired or migrated.
_ACK_LIMIT = 4096
_ACK_REQUIRED = frozenset(("version", "acknowledged", "deferred", "seed_id"))
_ACK_DENIED = "Q06_GUI_BACKUP_ACK_STORAGE_DENIED"


def _ack_name(folder):
    if (type(folder) is not type(Path())
            or re.fullmatch(r"bip39-12-[0-9a-f]{32}", folder.name) is None):
        raise Q06ReadOnlyError(_ACK_DENIED)
    return folder.name + ".json"


def _ack_file_ok(info):
    return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and (sys.platform == "win32" or info.st_uid == os.geteuid()
                 and not stat.S_IMODE(info.st_mode) & 0o022
                 and stat.S_IMODE(info.st_mode) & 0o600 == 0o600))


def _ack_posix_directory(directory):
    if sys.platform == "darwin":
        from wam_regtest.private_directory import open_macos_private_directory
        return open_macos_private_directory(directory)
    from wam_regtest.linux_private_storage import open_linux_private_directory
    return open_linux_private_directory(directory)


def _ack_absent(path):
    """Lenient no-follow absence probe; presence is then verified strictly."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    return False


def _ack_read(directory, name):
    for component in (directory.parent, directory):
        if _ack_absent(component):
            return None
        if not stat.S_ISDIR(os.lstat(component).st_mode):
            raise Q06ReadOnlyError(_ACK_DENIED)  # symlink/junction or file
    if _ack_absent(directory / name):
        return None
    if sys.platform == "win32":
        from wam_regtest.windows_private_storage import directory_guard
        with directory_guard(directory):
            before = os.lstat(directory / name)
            if getattr(before, "st_file_attributes", 0) & 0x400 or not _ack_file_ok(before):
                raise Q06ReadOnlyError(_ACK_DENIED)
            with open(directory / name, "rb") as handle:
                info = os.fstat(handle.fileno())
                if (info.st_ino, info.st_dev) != (before.st_ino, before.st_dev):
                    raise Q06ReadOnlyError(_ACK_DENIED)
                raw = handle.read(_ACK_LIMIT + 1)
    else:
        dfd = _ack_posix_directory(directory)
        fd = None
        try:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=dfd)
            except FileNotFoundError:
                return None
            before = os.fstat(fd)
            if not _ack_file_ok(before) or not 1 <= before.st_size <= _ACK_LIMIT:
                raise Q06ReadOnlyError(_ACK_DENIED)
            raw = os.read(fd, _ACK_LIMIT + 1)
            after = os.fstat(fd)
            if ((before.st_ino, before.st_size, before.st_mtime_ns)
                    != (after.st_ino, after.st_size, after.st_mtime_ns)):
                raise Q06ReadOnlyError(_ACK_DENIED)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(dfd)
    if not 1 <= len(raw) <= _ACK_LIMIT:
        raise Q06ReadOnlyError(_ACK_DENIED)
    return raw


def _ack_create_private_directory(directory):
    """Native owner-only directory creation; no runtime/witness policy needed.

    Never repairs or chmods an existing directory; callers re-validate.
    """
    if sys.platform == "darwin":
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        fullflush.flush_parent_after_mkdir(directory.parent)
        from wam_regtest.private_directory import open_macos_private_directory
        os.close(open_macos_private_directory(directory))
    elif sys.platform == "linux":
        from wam_regtest.linux_private_storage import create_private_directory
        create_private_directory(directory)
    elif sys.platform == "win32":
        from wam_regtest.windows_private_storage import create_private_directory
        create_private_directory(directory)
    else:
        raise Q06ReadOnlyError(_ACK_DENIED)


def _ack_ensure_directories(root):
    state = root / "q06-gui-state"
    for directory in (state, state / "ack"):
        if _ack_absent(directory):
            _ack_create_private_directory(directory)
    return state / "ack"


def _ack_write(root, name, payload):
    directory = _ack_ensure_directories(root)
    stage = ".ack-" + secrets.token_hex(16) + ".tmp"
    if sys.platform == "win32":
        # NOT EXECUTED on Windows in this remediation. Win32 rename reopens
        # the target directory, which conflicts with the guard's share mode,
        # so the guard validates before and after an exclusive stage+replace.
        from wam_regtest.windows_private_storage import validate_directory
        validate_directory(directory)
        target = directory / name
        try:
            existing = os.lstat(target)
        except FileNotFoundError:
            existing = None
        if existing is not None and (getattr(existing, "st_file_attributes", 0) & 0x400
                                     or not _ack_file_ok(existing)):
            raise Q06ReadOnlyError(_ACK_DENIED)
        fd = os.open(directory / stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0), 0o600)
        try:
            try:
                offset = 0
                while offset < len(payload):
                    count = os.write(fd, payload[offset:])
                    if count <= 0:
                        raise Q06ReadOnlyError(_ACK_DENIED)
                    offset += count
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(directory / stage, target)
        except BaseException:
            try:
                os.unlink(directory / stage)
            except OSError:
                pass
            raise
        validate_directory(directory)
        return
    dfd = _ack_posix_directory(directory)
    fd = None
    staged = False
    primary = False
    try:
        try:
            existing = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not _ack_file_ok(existing):
            raise Q06ReadOnlyError(_ACK_DENIED)
        fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        staged = True
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise Q06ReadOnlyError(_ACK_DENIED)
        offset = 0
        while offset < len(payload):
            count = os.write(fd, payload[offset:])
            if count <= 0:
                raise Q06ReadOnlyError(_ACK_DENIED)
            offset += count
        fullflush.full_flush(fd)
        os.close(fd)
        fd = None
        os.rename(stage, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        staged = False
        fullflush.flush_directory(dfd)
    except BaseException:
        primary = True
        raise
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                if not primary:
                    raise
        try:
            if staged:
                os.unlink(stage, dir_fd=dfd)
        except OSError:
            pass
        finally:
            try:
                os.close(dfd)
            except OSError:
                if not primary:
                    raise


def ack_dir(root):
    return root / "q06-gui-state" / "ack"


def ack_path(root, folder):
    return ack_dir(root) / _ack_name(folder)


def read_ack(root, folder, secret=None):
    """Return (acknowledged, deferred, integrity).

    - (None, None, True) when no sidecar exists.
    - (False, True, True) for a legitimate deferred marker.
    - (True, False, True) for a verified acknowledged marker.
    - integrity=False for malformed, tampered or replaced sidecars.

    If `secret` is supplied and the sidecar claims acknowledgement, the
    stored MAC is verified; a bad MAC yields integrity=False.
    """
    try:
        raw = _ack_read(ack_dir(root), _ack_name(folder))
        if raw is None:
            return None, None, True
        data = json.loads(raw.decode("utf-8"))
        if (type(data) is not dict or not _ACK_REQUIRED <= set(data)
                or not set(data) <= _ACK_REQUIRED | {"mac"}
                or type(data["version"]) is not int or data["version"] != 1
                or data["seed_id"] != folder.name
                or type(data["acknowledged"]) is not bool
                or type(data["deferred"]) is not bool
                or data["acknowledged"] and data["deferred"]):
            return False, True, False
        acknowledged, deferred = data["acknowledged"], data["deferred"]
        mac = data.get("mac")
        if mac is not None and (not acknowledged or type(mac) is not str
                                or re.fullmatch("[0-9a-f]{64}", mac) is None):
            return False, True, False
        if acknowledged and secret is not None:
            expected = hmac.new(secret, f"{folder.name}:acknowledged".encode(),
                                "sha256").hexdigest()
            if mac is None or not hmac.compare_digest(mac, expected):
                return False, True, False
        return acknowledged, deferred, True
    except Exception:
        return False, True, False


def write_ack(root, folder, acknowledged, deferred=False, secret=None):
    name = _ack_name(folder)
    data = {"version": 1, "acknowledged": bool(acknowledged),
            "deferred": bool(deferred), "seed_id": folder.name}
    if acknowledged and secret is not None:
        data["mac"] = hmac.new(secret, f"{folder.name}:acknowledged".encode(),
                               "sha256").hexdigest()
    try:
        _ack_write(root, name, json.dumps(data, separators=(',', ':')).encode())
    except Exception:
        # Not recorded: the caller fails closed and onboarding asks again.
        raise Q06ReadOnlyError(_ACK_DENIED) from None


def ack_authenticated(root, folder, password, open_owner, source, keychain):
    """True only for an acknowledgement whose MAC verifies for this open seed.

    A sidecar that merely claims acknowledgement is never trusted: without
    a valid MAC under the seed's own key this returns False.
    """
    acknowledged, _deferred, integrity = read_ack(root, folder)
    if acknowledged is not True or not integrity or password is None:
        return False
    try:
        from wam_regtest.bip39_seed_vault import open_owned_seed_container
        with open_owned_seed_container(
                open_owner(), folder, source, bytes(password),
                authorized=True, keychain=keychain) as keys:
            secret = keys.backup_ack_key()
        verified, _deferred, integrity = read_ack(root, folder, secret)
        return verified is True and integrity is True
    except Exception:
        return False


def invalidate_backup_challenge(epoch):
    return None, epoch + 1


def new_backup_challenge(epoch, secret, seed_folder, clock):
    # Serialized owner-session memory only. No mnemonic/answers persisted.
    if secret is None or seed_folder is None:
        raise Q06ReadOnlyError('Q06_GUI_BACKUP_VERIFY_LOCKED')
    positions = tuple(sorted(secrets.SystemRandom().sample(range(1, 13), 3)))
    identifier = secrets.token_hex(32)
    challenge = (identifier, positions, seed_folder, epoch, clock() + 120)
    return challenge, {'challenge_id': identifier, 'positions': positions,
                       'expires_in_seconds': 120}


def defer_unless_authenticated(is_authenticated, write_deferred):
    """Never downgrade a MAC-verified acknowledgement to deferred."""
    if not is_authenticated:
        write_deferred()


def verify_backup_challenge(challenge, identifier, answers, *, seed_folder, epoch,
                            secret, open_owner, source, keychain, clock, write_ack):
    if seed_folder is None or secret is None:
        raise Q06ReadOnlyError('Q06_GUI_BACKUP_VERIFY_LOCKED')
    if (challenge is None or not hmac.compare_digest(identifier, challenge[0])
            or challenge[2] != seed_folder or challenge[3] != epoch
            or clock() >= challenge[4]):
        raise Q06ReadOnlyError('Q06_GUI_BACKUP_CHALLENGE_DENIED')
    positions = challenge[1]
    from wam_regtest.bip39_seed_vault import (
        _owner_binding, open_owned_seed_container, read_seed_phrase)
    owner = open_owner()
    decoded_password = bytes(secret).decode("utf-8")
    phrase = read_seed_phrase(
        seed_folder, source, decoded_password,
        keychain=keychain, owner_binding=_owner_binding(owner))
    words = phrase.split()
    phrase = None
    try:
        if len(words) != 12:
            raise Q06ReadOnlyError("Q06_GUI_BACKUP_VERIFY_PHRASE_DENIED")
        normalized = [a.strip().lower() for a in answers]
        if any(normalized[i] != words[positions[i] - 1].lower()
               for i in range(len(positions))):
            return False
        with open_owned_seed_container(
                owner, seed_folder, source,
                bytes(secret), authorized=True,
                keychain=keychain) as keys:
            ack_secret = keys.backup_ack_key()
        if clock() >= challenge[4]:
            raise Q06ReadOnlyError('Q06_GUI_BACKUP_CHALLENGE_DENIED')
        write_ack(seed_folder, True, secret=ack_secret)
        return True
    except Exception:
        raise Q06ReadOnlyError("Q06_GUI_BACKUP_VERIFY_DENIED") from None
