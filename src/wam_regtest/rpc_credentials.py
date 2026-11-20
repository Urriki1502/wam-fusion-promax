"""Bounded native credential custody for an explicitly owned REGTEST process.

Core-generated cookie files can inherit the strictly private parent DACL; only
that cookie path allows inheritance, while retaining exact owner/one-ACE checks.
Existing encrypted-vault and config custody rules are unchanged.
"""
from hashlib import sha256
import errno
import os
from pathlib import Path
import re
import stat
import sys


class CredentialError(ValueError):
    def __init__(self, token, *, cookie_bootstrap=False):
        super().__init__(token)
        # True only for a cookie that is still being created or renamed.
        # route() may treat that as bootstrap before the first successful RPC.
        # Mode, owner, ACL, symlink and format observations leave this false.
        self.cookie_bootstrap=bool(cookie_bootstrap)


_COOKIE_ACL=frozenset((
    'MACOS_PRIVATE_DIRECTORY_ACL_DENIED','LINUX_PRIVATE_ACL_DENIED',
    'LINUX_PRIVATE_ACL_INSPECTION_DENIED'))
_COOKIE_ABSENT=frozenset((
    'MACOS_PRIVATE_DIRECTORY_OPEN_DENIED','LINUX_PRIVATE_DIRECTORY_OPEN_DENIED'))


def _cookie_still_publishing(before, current):
    """True when a private cookie's inode, links, size or timestamps moved.

    Owner, mode, file type and a second hard link are not publication.
    """
    return (stat.S_ISREG(current.st_mode) and current.st_uid==before.st_uid
            and stat.S_IMODE(current.st_mode)==stat.S_IMODE(before.st_mode)
            and current.st_nlink<=1)


def _cookie_open_refusal(error):
    """Classify a cookie open failure. None keeps the caller's existing token."""
    if isinstance(error, OSError) and error.errno==errno.ELOOP:
        return CredentialError('RPC_CREDENTIAL_CUSTODY_DENIED')
    if isinstance(error, OSError) and error.errno==errno.ENOENT:
        return CredentialError('RPC_CREDENTIAL_MISSING_OR_UNSAFE', cookie_bootstrap=True)
    token=error.args[0] if error.args and type(error.args[0]) is str else ''
    if token in _COOKIE_ACL:
        return CredentialError('RPC_CREDENTIAL_CUSTODY_DENIED')
    if token in _COOKIE_ABSENT:
        return CredentialError('RPC_CREDENTIAL_MISSING_OR_UNSAFE', cookie_bootstrap=True)
    return None


def private_bytes(directory, name, limit, *, core_cookie=False):
    if name not in ('wam.conf','.cookie') or core_cookie != (name=='.cookie'):
        raise CredentialError('RPC_CREDENTIAL_PATH_DENIED')
    if sys.platform=='win32':
        from .windows_private_storage import WindowsCustodyError
        try:return _windows_private_bytes(directory,name,limit,core_cookie=core_cookie)
        except WindowsCustodyError:
            raise CredentialError('RPC_CREDENTIAL_CUSTODY_DENIED') from None
    if sys.platform=='darwin':
        from .private_directory import open_macos_private_directory as open_dir,_require_absent_acl as no_acl
    elif sys.platform=='linux':
        from .linux_private_storage import open_linux_private_directory as open_dir,_no_acl as no_acl
    else:raise CredentialError('RPC_NATIVE_CUSTODY_REQUIRED')
    dfd=fd=None
    try:
        dfd=open_dir(directory)
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=dfd)
        before=os.fstat(fd);no_acl(fd)
        fields=('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid()
                or stat.S_IMODE(before.st_mode)!=0o600):
            raise CredentialError('RPC_CREDENTIAL_CUSTODY_DENIED')
        if before.st_nlink!=1 or not 1<=before.st_size<=limit:
            # nlink 0 is the inode Core just unlinked. Size 0 is the file Core
            # has not finished publishing. A second link or an oversize file is not.
            publishing=core_cookie and (before.st_nlink==0 or (before.st_size==0 and before.st_nlink==1))
            raise CredentialError('RPC_CREDENTIAL_CUSTODY_DENIED', cookie_bootstrap=publishing)
        raw=os.read(fd,limit+1);after=os.fstat(fd)
        identity=tuple(getattr(before,k) for k in fields)
        if identity!=tuple(getattr(after,k) for k in fields) or len(raw)!=before.st_size:
            publishing=core_cookie and _cookie_still_publishing(before, after) and len(raw)<=limit+1
            raise CredentialError('RPC_CREDENTIAL_CHANGED', cookie_bootstrap=publishing)
        linked=os.stat(name,dir_fd=dfd,follow_symlinks=False)
        if identity!=tuple(getattr(linked,k) for k in fields):
            publishing=core_cookie and _cookie_still_publishing(before, linked)
            raise CredentialError('RPC_CREDENTIAL_CHANGED', cookie_bootstrap=publishing)
        return raw,identity
    except CredentialError:raise
    except Exception as caught:
        if core_cookie:
            refused=_cookie_open_refusal(caught)
            if refused is not None:raise refused from None
        raise CredentialError('RPC_CREDENTIAL_MISSING_OR_UNSAFE') from None
    finally:
        if fd is not None:os.close(fd)
        if dfd is not None:os.close(dfd)


def _windows_private_bytes(directory,name,limit,*,core_cookie):
    from . import windows_private_storage as s
    import ctypes as c
    # Cookie directory was created by Core beneath a protected datadir.
    root=directory.parent if core_cookie else directory
    with s.directory_guard(root),s.directory_guard(directory,private=not core_cookie) as dfd:
        if core_cookie:s.verify_security(dfd,protected=False)
        h=s.create(str(directory/name),0x80020080,1,None,3,0x200080,None)
        if h in (None,s.INVALID):raise CredentialError('RPC_CREDENTIAL_MISSING_OR_UNSAFE')
        try:
            before=s._metadata(h);s.verify_security(h,protected=not core_cookie)
            if not 1<=before[3]<=limit:
                raise CredentialError('RPC_CREDENTIAL_SIZE_DENIED',
                    cookie_bootstrap=core_cookie and before[3]==0)
            buf=c.create_string_buffer(limit+1);count=s.w.DWORD()
            if not s.readfile(h,buf,limit+1,c.byref(count),None):
                raise CredentialError('RPC_CREDENTIAL_READ_DENIED')
            if before!=s._metadata(h) or count.value!=before[3]:
                raise CredentialError('RPC_CREDENTIAL_CHANGED', cookie_bootstrap=core_cookie)
            s.verify_security(h,protected=not core_cookie)
            return buf.raw[:count.value],before
        finally:s.close(h)


def parse_profile(raw,mode,*,shared_profile=None):
    from .network_policy import parse_local_config,_FIXED
    if type(raw) is not bytes or not 1<=len(raw)<=4096 or mode not in ('config','cookie'):
        raise CredentialError('RPC_AUTH_MODE_DENIED')
    if shared_profile is not None:
        from .shared_regtest import SharedRegtestProfile
        if type(shared_profile) is not SharedRegtestProfile:
            raise CredentialError('SHARED_EXPLICIT_PROFILE_REQUIRED')
    try:
        if mode=='config':
            port=parse_local_config(raw, shared_profile=shared_profile)
            values=dict(line.split('=',1) for line in raw.decode('ascii').splitlines()[3:])
            return port,(values['rpcuser']+':'+values['rpcpassword']).encode('ascii')
        lines=raw.decode('ascii').splitlines()
        if lines[:3]!=['regtest=1','server=1','[regtest]']:raise ValueError
        pairs=[line.split('=',1) for line in lines[3:]]
        values=dict(pairs)
        fixed = _FIXED if shared_profile is None else shared_profile.settings()
        if len(values)!=len(pairs) or set(values)!=set(fixed)-{'rpcuser','rpcpassword'}:raise ValueError
        # Reuse the exact existing protected network profile. Dummy values
        # validate its shape only; they are never sent or written to Core.
        check=raw.rstrip(b'\r\n')+b'\nrpcuser=disposable_'+b'0'*16+b'\nrpcpassword='+b'0'*64+b'\n'
        port=parse_local_config(check, shared_profile=shared_profile)
        return port,None
    except Exception:raise CredentialError('RPC_CONFIG_PROFILE_DENIED') from None


class CredentialSource:
    """Snapshot private CLI credential files, without retaining cleartext auth.

    The signed CLI reads the original private config/cookie itself. No secret
    enters argv, diagnostics or a persistent Python HTTP connection.
    """
    def __init__(self,directory,*,shared_profile=None):
        if type(directory) is not type(Path()) or not directory.is_absolute():
            raise CredentialError('RPC_CREDENTIAL_PATH_DENIED')
        self.directory=directory
        raw,identity=private_bytes(directory,'wam.conf',4096)
        self.mode='config' if b'rpcuser=' in raw or b'rpcpassword=' in raw else 'cookie'
        self.port,_=parse_profile(raw,self.mode, shared_profile=shared_profile)
        self._config=(sha256(raw).digest(),identity)
        self._cookie=None
        if self.mode=='cookie':
            cookie,cookie_identity=private_bytes(directory/'regtest','.cookie',256,core_cookie=True)
            if not re.fullmatch(rb'__cookie__:[0-9a-f]{64}(?:\r?\n)?',cookie):
                raise CredentialError('RPC_COOKIE_FORMAT_DENIED')
            self._cookie=(sha256(cookie).digest(),cookie_identity)

    def __repr__(self):return '<CredentialSource redacted>'

    def attest(self):
        raw,identity=private_bytes(self.directory,'wam.conf',4096)
        if (sha256(raw).digest(),identity)!=self._config:
            raise CredentialError('RPC_CONFIG_CHANGED')
        if self.mode=='cookie':
            raw,identity=private_bytes(self.directory/'regtest','.cookie',256,core_cookie=True)
            if (sha256(raw).digest(),identity)!=self._cookie:
                raise CredentialError('RPC_COOKIE_CHANGED', cookie_bootstrap=True)
