"""Native owner-only persistent control state for T05, separate from wallet custody.

Do not use the chain datadir for IPC secrets. No chmod/ACL repair, symlink
following, deletion on failure, or pre-existing user wallet adoption.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import threading

from .fullflush import flush_after_mkdir, flush_directory, full_flush

MAX_CONTROL_FILE=4096
CONTROL_NAMES=frozenset({"supervisor.token","supervisor.profile","supervisor.lock",
                         "supervisor.failure","supervisor.wallet"})
# DUR-02 (macOS only): records are staged in this private subdirectory and
# published with renameatx_np(RENAME_EXCL). Residue is never read or deleted.
STAGE_DIRECTORY=".wam-stage"
MAX_STAGE_RESIDUE=64
_RENAME_EXCL=0x00000004


class SupervisorStorageError(ValueError):pass


def _name(name):
    if (type(name) is not str or name not in CONTROL_NAMES and not
            re.fullmatch(
                r'supervisor\.(?:event|recovery|notice|notice-ack)\.[0-9]{6}'
                r'|supervisor\.notice\.stage-[0-9a-f]{16}',
                name)):
        raise SupervisorStorageError("SUPERVISOR_STORAGE_NAME_DENIED")


def _root(root):
    if (type(root) is not type(Path()) or not root.is_absolute()
            or ".." in root.parts or not re.fullmatch(
                r"wam-fusion-core-[0-9a-f]{16}",root.name)):
        raise SupervisorStorageError("SUPERVISOR_STORAGE_ROOT_DENIED")
    return root


@contextmanager
def _posix_dir(root):
    if sys.platform=="darwin":
        from .private_directory import open_macos_private_directory as private
    elif sys.platform=="linux":
        from .linux_private_storage import open_linux_private_directory as private
    else:raise SupervisorStorageError("SUPERVISOR_NATIVE_STORE_REQUIRED")
    try:fd=private(root)
    except (OSError,ValueError):
        raise SupervisorStorageError("SUPERVISOR_STORAGE_ROOT_UNTRUSTED") from None
    if sys.platform=="darwin":
        with _owned(fd):yield fd
    else:
        try:yield fd
        finally:os.close(fd)


def _posix_file(fd,name,*,create=False,nonblocking=True):
    flags=os.O_RDWR if create else os.O_RDONLY
    flags|=os.O_NOFOLLOW|os.O_CLOEXEC
    if nonblocking: flags|=os.O_NONBLOCK
    if create:flags|=os.O_CREAT|os.O_EXCL
    descriptor=os.open(name,flags,0o600,dir_fd=fd)
    try:
        info=os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600):
            raise SupervisorStorageError("SUPERVISOR_STORAGE_FILE_UNTRUSTED")
        if sys.platform=="darwin":
            from .private_directory import _require_absent_acl
            _require_absent_acl(descriptor)
        else:
            from .linux_private_storage import _no_acl
            _no_acl(descriptor)
    except BaseException:
        os.close(descriptor);raise
    return descriptor


def _win_open(root,name,*,create=False,exclusive=False):
    from . import windows_private_storage as native
    native.require_native()
    context=native.directory_guard(root)
    context.__enter__()
    handle=None
    try:
        if create:
            with native.security_attributes() as sa:
                handle=native.create(str(root/name),0xc0000000,0,sa,1,0x200080,None)
        else:
            handle=native.create(str(root/name),0xc0000000 if exclusive else 0x80000000,
                                 0 if exclusive else 1,None,3,0x200080,None)
        if handle in (None,native.INVALID):
            raise SupervisorStorageError("SUPERVISOR_STORAGE_FILE_BUSY_OR_DENIED")
        native._metadata(handle)
        native.verify_security(handle)
        return native,handle,context
    except BaseException:
        if handle not in (None,native.INVALID):native.close(handle)
        context.__exit__(None,None,None)
        raise


def _win_read(native,handle,limit):
    import ctypes
    before=native._metadata(handle)
    if not 1<=before[3]<=limit:
        raise SupervisorStorageError("SUPERVISOR_STORAGE_SIZE_DENIED")
    chunks=[];left=before[3]
    while left:
        size=min(65536,left)
        buf=ctypes.create_string_buffer(size);got=native.w.DWORD()
        if not native.readfile(handle,buf,size,ctypes.byref(got),None) or not got.value:
            raise SupervisorStorageError("SUPERVISOR_STORAGE_READ_DENIED")
        chunks.append(buf.raw[:got.value]);left-=got.value
    if native._metadata(handle)!=before:
        raise SupervisorStorageError("SUPERVISOR_STORAGE_CHANGED")
    native.verify_security(handle)
    return b"".join(chunks)


@contextmanager
def _owned(descriptor):
    """Close on exit; a close error never replaces an in-flight primary failure."""
    try:yield descriptor
    except BaseException:
        try:os.close(descriptor)
        except OSError:pass
        raise
    else:os.close(descriptor)


def _stage_name(name):
    """Private stage-name validator; stage names are never public record names."""
    if type(name) is not str or not re.fullmatch(r"[0-9a-f]{16}\.tmp",name):
        raise SupervisorStorageError("SUPERVISOR_STORAGE_STAGE_NAME_DENIED")
    return name


def _component(name):
    """One relative path component as bytes: never absolute, dot, '..', '/' or NUL."""
    if (type(name) is not str or name in ("",".","..") or "/" in name or "\0" in name
            or not name.isascii()):
        raise SupervisorStorageError("SUPERVISOR_STORAGE_NAME_DENIED")
    return name.encode("ascii")


def _renameatx_np():
    """Darwin-only binding with the frozen ABI (DUR-02 N1). Missing symbol refuses."""
    if sys.platform!="darwin":
        raise SupervisorStorageError("SUPERVISOR_NATIVE_STORE_REQUIRED")
    import ctypes
    try:function=ctypes.CDLL(None,use_errno=True).renameatx_np
    except (OSError,AttributeError):
        raise SupervisorStorageError("SUPERVISOR_STORAGE_RENAME_UNAVAILABLE") from None
    function.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    function.restype=ctypes.c_int
    return function


def _rename_exclusive(stage_directory,stage,root_directory,final):
    """renameatx_np(RENAME_EXCL) between two held descriptors; no fallback or retry.

    errno is read immediately after a failing call. EEXIST keeps the existing
    create-once refusal; every other failure (ENOTSUP, EINVAL, EXDEV, EIO,
    any nonzero result) is a fixed refusal with no plain rename, copy or
    overwrite. The source must still be the staged inode: see _verify_stage.
    """
    import ctypes
    import errno
    _name(final)
    if final=="supervisor.lock":
        raise SupervisorStorageError("SUPERVISOR_STORAGE_CREATE_DENIED")
    if (type(stage_directory) is not int or stage_directory<0
            or type(root_directory) is not int or root_directory<0
            or stage_directory==root_directory):
        raise SupervisorStorageError("SUPERVISOR_STORAGE_RENAME_DENIED")
    source=_component(_stage_name(stage));target=_component(final)
    function=_renameatx_np()
    ctypes.set_errno(0)
    result=function(stage_directory,source,root_directory,target,_RENAME_EXCL)
    error=ctypes.get_errno()
    if result==0:return
    if result==-1 and error==errno.EEXIST:
        raise SupervisorStorageError("SUPERVISOR_STORAGE_CREATE_DENIED")
    raise SupervisorStorageError("SUPERVISOR_STORAGE_RENAME_DENIED")


def _verify_stage_directory(root_directory,stage_directory,error_code):
    """Validate held stage_directory metadata and its no-follow root binding."""
    from .private_directory import validate_macos_private_directory
    try:
        validate_macos_private_directory(stage_directory)
        stage_info=os.fstat(stage_directory)
        root_info=os.fstat(root_directory)
        linked=os.stat(STAGE_DIRECTORY,dir_fd=root_directory,follow_symlinks=False)
        if (stage_info.st_dev!=root_info.st_dev
                or (linked.st_dev,linked.st_ino)!=(stage_info.st_dev,stage_info.st_ino)
                or not stat.S_ISDIR(linked.st_mode)
                or linked.st_uid!=os.geteuid()
                or stat.S_IMODE(linked.st_mode)!=0o700):
            raise SupervisorStorageError(error_code)
    except SupervisorStorageError:raise
    except (OSError,ValueError):
        raise SupervisorStorageError(error_code) from None
    return stage_info


def _open_stage_directory(root_directory,*,create):
    """root/.wam-stage opened no-follow through the held root descriptor (N2).

    Owner, mode 0700, absent ACL, non-inheritable descriptor, same device as
    the root and the name still bound to the opened inode. Pre-existing
    metadata is never repaired. Returns None only when absent and create=False.
    """
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    try:
        try:directory=os.open(STAGE_DIRECTORY,flags,dir_fd=root_directory)
        except FileNotFoundError:
            if not create:return None
            try:os.mkdir(STAGE_DIRECTORY,0o700,dir_fd=root_directory)
            except FileExistsError:pass
            flush_after_mkdir(root_directory)
            directory=os.open(STAGE_DIRECTORY,flags,dir_fd=root_directory)
    except OSError:
        raise SupervisorStorageError("SUPERVISOR_STORAGE_STAGE_UNTRUSTED") from None
    try:
        _verify_stage_directory(root_directory,directory,"SUPERVISOR_STORAGE_STAGE_UNTRUSTED")
    except BaseException:
        try:os.close(directory)
        except OSError:pass
        raise
    return directory


def _residue_count(stage_directory,limit):
    """Count every entry of any type, stopping after limit+1 (bounded enumeration)."""
    count=0
    with os.scandir(stage_directory) as entries:
        for _entry in entries:
            count+=1
            if count>limit:break
    return count


def _verify_stage(root_directory,stage_directory,stage,handle,size):
    """Bind the source name to the held, complete, flushed staged inode (N2).

    This narrows, but cannot remove, a same-UID race: renameatx_np renames
    whatever the source name denotes at call time. The published final and
    stage-directory binding are therefore re-verified after the rename.
    """
    from .private_directory import _require_absent_acl
    try:
        entry=os.stat(stage,dir_fd=stage_directory,follow_symlinks=False)
        _require_absent_acl(handle)
        held=os.fstat(handle)
        if (not stat.S_ISREG(held.st_mode) or held.st_uid!=os.geteuid()
                or held.st_nlink!=1 or stat.S_IMODE(held.st_mode)!=0o600
                or held.st_size!=size
                or not stat.S_ISREG(entry.st_mode) or entry.st_uid!=os.geteuid()
                or entry.st_nlink!=1 or stat.S_IMODE(entry.st_mode)!=0o600
                or entry.st_size!=size
                or (entry.st_dev,entry.st_ino)!=(held.st_dev,held.st_ino)):
            raise SupervisorStorageError("SUPERVISOR_STORAGE_STAGE_CHANGED")
        stage_info=_verify_stage_directory(
            root_directory,stage_directory,"SUPERVISOR_STORAGE_STAGE_CHANGED")
        if stage_info.st_dev!=held.st_dev:
            raise SupervisorStorageError("SUPERVISOR_STORAGE_STAGE_CHANGED")
    except SupervisorStorageError:raise
    except (OSError,ValueError):
        raise SupervisorStorageError("SUPERVISOR_STORAGE_STAGE_CHANGED") from None
    return held.st_dev,held.st_ino


def _create_darwin(root,name,data):
    """DUR-02 + DUR-01a: stage -> write -> full_flush -> verify -> rename -> verify -> flush_directory(root).

    Atomic publication against process interruption with best-effort file-data
    F_FULLFSYNC hardening. Namespace persistence on power loss remains
    UNVERIFIED. Before the rename a failure leaves no final; after it, any
    failure is raised while the complete final may exist (never removed,
    replayed or reported as success). Residue is retained.
    """
    from .private_directory import _require_absent_acl
    with _posix_dir(root) as directory:
        # Ordinary duplicates (e.g. the first-failure record) refuse here,
        # before staging, so they never accumulate residue.
        try:os.stat(name,dir_fd=directory,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise SupervisorStorageError("SUPERVISOR_STORAGE_CREATE_DENIED")
        with _owned(_open_stage_directory(directory,create=True)) as stage_directory:
            # At most MAX_STAGE_RESIDUE entries including the pending stage.
            if _residue_count(stage_directory,MAX_STAGE_RESIDUE-1)>=MAX_STAGE_RESIDUE:
                raise SupervisorStorageError("SUPERVISOR_STORAGE_STAGE_RESIDUE_LIMIT")
            stage=_stage_name(secrets.token_hex(8)+".tmp")
            with _owned(_posix_file(stage_directory,stage,create=True)) as handle:
                offset=0
                while offset<len(data):
                    n=os.write(handle,data[offset:])
                    if n<=0:raise SupervisorStorageError("SUPERVISOR_STORAGE_WRITE_DENIED")
                    offset+=n
                full_flush(handle)
                staged=_verify_stage(directory,stage_directory,stage,handle,len(data))
                _rename_exclusive(stage_directory,stage,directory,name)
                try:
                    published=os.stat(name,dir_fd=directory,follow_symlinks=False)
                    after=os.fstat(handle)
                    _require_absent_acl(handle)
                except (OSError,ValueError):
                    raise SupervisorStorageError("SUPERVISOR_STORAGE_PUBLISH_UNVERIFIED") from None
                if ((published.st_dev,published.st_ino)!=staged
                        or (after.st_dev,after.st_ino)!=staged
                        or not stat.S_ISREG(published.st_mode)
                        or published.st_uid!=os.geteuid()
                        or published.st_nlink!=1
                        or stat.S_IMODE(published.st_mode)!=0o600
                        or published.st_size!=len(data)):
                    raise SupervisorStorageError("SUPERVISOR_STORAGE_PUBLISH_UNVERIFIED")
                stage_info=_verify_stage_directory(
                    directory,stage_directory,"SUPERVISOR_STORAGE_PUBLISH_UNVERIFIED")
                if stage_info.st_dev!=staged[0]:
                    raise SupervisorStorageError("SUPERVISOR_STORAGE_PUBLISH_UNVERIFIED")
        flush_directory(directory)


def stage_namespace(root):
    """macOS R1 helper: 'absent', 'empty' or 'occupied' for root/.wam-stage.

    Validates through descriptors without following links; never creates,
    reads or deletes anything. An untrusted stage directory refuses.
    """
    root=_root(root)
    if sys.platform!="darwin":raise SupervisorStorageError("SUPERVISOR_NATIVE_STORE_REQUIRED")
    try:
        with _posix_dir(root) as directory:
            stage=_open_stage_directory(directory,create=False)
            if stage is None:return "absent"
            with _owned(stage):
                return "empty" if _residue_count(stage,0)==0 else "occupied"
    except SupervisorStorageError:raise
    except (OSError,ValueError):
        raise SupervisorStorageError("SUPERVISOR_STORAGE_STAGE_UNTRUSTED") from None


def create_once(root,name,data):
    root=_root(root);_name(name)
    if name=="supervisor.lock" or type(data) is not bytes or not 1<=len(data)<=MAX_CONTROL_FILE:
        raise SupervisorStorageError("SUPERVISOR_STORAGE_CREATE_DENIED")
    try:
        if sys.platform=="darwin":
            _create_darwin(root,name,data)
        elif sys.platform=="win32":
            native,handle,guard=_win_open(root,name,create=True)
            try:
                import ctypes
                offset=0
                while offset<len(data):
                    segment=data[offset:offset+65536]
                    buf=ctypes.create_string_buffer(segment);n=native.w.DWORD()
                    if not native.write(handle,buf,len(segment),ctypes.byref(n),None) or n.value!=len(segment):
                        raise SupervisorStorageError("SUPERVISOR_STORAGE_WRITE_DENIED")
                    offset+=n.value
                if not native.flush(handle):
                    raise SupervisorStorageError("SUPERVISOR_STORAGE_FSYNC_DENIED")
            finally:native.close(handle);guard.__exit__(None,None,None)
        else:
            with _posix_dir(root) as directory:
                handle=_posix_file(directory,name,create=True)
                try:
                    offset=0
                    while offset<len(data):
                        n=os.write(handle,data[offset:])
                        if n<=0:raise SupervisorStorageError("SUPERVISOR_STORAGE_WRITE_DENIED")
                        offset+=n
                    os.fsync(handle)
                finally:os.close(handle)
                os.fsync(directory)
    except SupervisorStorageError:raise
    except (OSError,ValueError):
        raise SupervisorStorageError("SUPERVISOR_STORAGE_CREATE_UNVERIFIED") from None


def read_exact(root,name,*,length=None):
    root=_root(root);_name(name)
    if name=="supervisor.lock":raise SupervisorStorageError("SUPERVISOR_STORAGE_READ_DENIED")
    try:
        if sys.platform=="win32":
            native,handle,guard=_win_open(root,name)
            try:raw=_win_read(native,handle,MAX_CONTROL_FILE)
            finally:native.close(handle);guard.__exit__(None,None,None)
        else:
            with _posix_dir(root) as directory:
                handle=_posix_file(directory,name,nonblocking=True)
                try:
                    before=os.fstat(handle)
                    if not 1<=before.st_size<=MAX_CONTROL_FILE:
                        raise SupervisorStorageError("SUPERVISOR_STORAGE_SIZE_DENIED")
                    raw=os.read(handle,MAX_CONTROL_FILE+1);after=os.fstat(handle)
                    fields=("st_dev","st_ino","st_mode","st_uid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
                    if len(raw)!=before.st_size or any(getattr(before,k)!=getattr(after,k) for k in fields):
                        raise SupervisorStorageError("SUPERVISOR_STORAGE_CHANGED")
                    linked=os.stat(name,dir_fd=directory,follow_symlinks=False)
                    if any(getattr(after,k)!=getattr(linked,k) for k in fields):
                        raise SupervisorStorageError("SUPERVISOR_STORAGE_CHANGED")
                finally:os.close(handle)
        if length is not None and (type(length) is not int or len(raw)!=length):
            raise SupervisorStorageError("SUPERVISOR_STORAGE_LENGTH_DENIED")
        return raw
    except SupervisorStorageError:raise
    except (OSError,ValueError):
        raise SupervisorStorageError("SUPERVISOR_STORAGE_READ_UNVERIFIED") from None


_LEASE_LOCK = threading.Lock()
_OWNED_LEASES = {}


def held_lease(root):
    """Return a copy of the in-process exclusive_lease record for root, or None."""
    root=_root(root)
    with _LEASE_LOCK:
        record=_OWNED_LEASES.get(root)
        if record is None or record.get("pid")!=os.getpid():
            return None
        return dict(record)


@contextmanager
def exclusive_lease(root):
    """One native descriptor-held lock; never remove or steal stale lock paths."""
    root=_root(root)
    if sys.platform=="win32":
        from . import windows_private_storage as native
        with native.directory_guard(root) as dir_handle:
            dir_info=native._metadata(dir_handle,directory=True)
            # OPEN_ALWAYS, no sharing: crash closes kernel handle.
            with native.security_attributes() as sa:
                handle=native.create(str(root/"supervisor.lock"),0xc0000000,0,sa,4,0x200080,None)
            if handle in (None,native.INVALID):
                raise SupervisorStorageError("SUPERVISOR_STORAGE_LEASE_BUSY")
            try:
                info=native._metadata(handle);native.verify_security(handle)
                if info[3]!=0:raise SupervisorStorageError("SUPERVISOR_STORAGE_LEASE_INVALID")
                # In-process only: never serialized or adopted across processes.
                lease_record={
                    "pid":os.getpid(),
                    "platform":"win32",
                    "handle":handle,
                    "file_id":info[:3],
                    "dir_id":dir_info[:3],
                }
                with _LEASE_LOCK:
                    _OWNED_LEASES[root]=lease_record
                try:yield
                finally:
                    with _LEASE_LOCK:
                        if _OWNED_LEASES.get(root) is lease_record:
                            del _OWNED_LEASES[root]
                    after=native._metadata(handle)
                    if after[:3]!=info[:3] or after[3]!=0:
                        raise SupervisorStorageError("SUPERVISOR_STORAGE_LEASE_CHANGED")
            finally:native.close(handle)
    else:
        import fcntl
        with _posix_dir(root) as directory:
            dir_info=os.fstat(directory)
            try:handle=_posix_file(directory,"supervisor.lock",create=True)
            except FileExistsError:handle=_posix_file(directory,"supervisor.lock")
            try:
                info=os.fstat(handle)
                if info.st_size!=0:raise SupervisorStorageError("SUPERVISOR_STORAGE_LEASE_INVALID")
                try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:
                    raise SupervisorStorageError("SUPERVISOR_STORAGE_LEASE_BUSY") from None
                after=os.stat("supervisor.lock",dir_fd=directory,follow_symlinks=False)
                if after.st_ino!=info.st_ino or after.st_dev!=info.st_dev:
                    raise SupervisorStorageError("SUPERVISOR_STORAGE_LEASE_CHANGED")
                lease_record={
                    "pid":os.getpid(),
                    "dir_dev":dir_info.st_dev,
                    "dir_ino":dir_info.st_ino,
                    "dev":info.st_dev,
                    "ino":info.st_ino,
                    "fd":handle,
                }
                with _LEASE_LOCK:
                    _OWNED_LEASES[root]=lease_record
                try:yield
                finally:
                    with _LEASE_LOCK:
                        if _OWNED_LEASES.get(root) is lease_record:
                            del _OWNED_LEASES[root]
                    after=os.stat("supervisor.lock",dir_fd=directory,follow_symlinks=False)
                    try:
                        if after.st_ino!=info.st_ino or after.st_dev!=info.st_dev:
                            raise SupervisorStorageError("SUPERVISOR_STORAGE_LEASE_CHANGED")
                    finally:fcntl.flock(handle,fcntl.LOCK_UN)
            finally:os.close(handle)
