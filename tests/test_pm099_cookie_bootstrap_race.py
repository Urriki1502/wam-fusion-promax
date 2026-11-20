"""PM-099: a cookie Core is still creating or rotating is bootstrap, not a latch.

No genuine Core. A not-yet-ready owned scope must treat a cookie that is
missing, empty, short, unlinked, or replaced by rename as the existing
RPC_CREDENTIAL_MISSING_OR_UNSAFE bootstrap observation. The same change after
the first successful RPC still latches. Wrong mode, owner, ACL, symlink,
oversize and format stay latching before that first success.
"""
import os
import stat
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from wam_regtest import rpc_credentials as credentials
from wam_regtest import rpc_scope
from wam_regtest.cli_rpc import CliRpcError
from wam_regtest.core import _port, _write_private_config
from wam_regtest.custody import create_directory, private_temporary_directory
from wam_regtest.private_directory import MacosPrivateDirectoryError
from wam_regtest.rpc_credentials import CredentialSource


_COOKIE = b'__cookie__:' + b'ab' * 32 + b'\n'


class _StatView:
    def __init__(self, real, **overrides):
        self._real = real
        self._overrides = overrides

    def __getattr__(self, name):
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._real, name)


class CookieBootstrapRace(unittest.TestCase):
    def setUp(self):
        self.tmp = private_temporary_directory(prefix='wam-pm099-')
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name).resolve() / 'chain'
        create_directory(self.directory)
        create_directory(self.directory / 'regtest')
        rpc = _port()
        peer = _port()
        if rpc == peer:
            peer = _port()
        _write_private_config(self.directory, rpc, peer)
        self.conf = self.directory / 'wam.conf'
        kept = [line for line in self.conf.read_bytes().splitlines()
                if not line.startswith((b'rpcuser=', b'rpcpassword='))]
        self.conf.write_bytes(b'\n'.join(kept) + b'\n')
        self.cookie = self.directory / 'regtest' / '.cookie'
        fd = os.open(self.cookie, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, _COOKIE)
        finally:
            os.close(fd)
        self.binary = self.directory / 'wam-cli'
        self.binary.write_bytes(b'not-executed')
        self.context = SimpleNamespace(
            binding=SimpleNamespace(cli=self.binary, _assert_image=Mock()),
            shared_profile=None, authorized=True, credentials=None, faulted=False,
            ready=False, lock=threading.RLock(), assert_endpoint=Mock())
        self._previous = dict(rpc_scope._contexts)
        rpc_scope._contexts.clear()
        rpc_scope._contexts[str(self.directory.resolve(strict=True))] = self.context
        self.addCleanup(self._restore_scopes)
        # A credential that then reads cleanly must not reach a fake CLI. Warmup
        # is already a bootstrap token, so the second poll stays unlatched.
        self._execute = patch(
            'wam_regtest.rpc_scope.execute', side_effect=CliRpcError('CORE_RPC_WARMUP'))
        self._execute.start()
        self.addCleanup(self._execute.stop)

    def _restore_scopes(self):
        rpc_scope._contexts.clear()
        rpc_scope._contexts.update(self._previous)

    def _route(self):
        return rpc_scope.route(self.binary, self.directory, ['getblockcount'])

    def _assert_bootstrap(self):
        with self.assertRaises(CliRpcError) as caught:
            self._route()
        self.assertEqual(caught.exception.args, ('CORE_RPC_CREDENTIAL_CHANGED_OR_UNSAFE',))
        self.assertFalse(self.context.faulted)
        self.assertIsNone(self.context.credentials)
        with self.assertRaises(CliRpcError) as again:
            self._route()
        self.assertNotEqual(again.exception.args, ('CORE_RPC_SCOPE_FAULTED',))
        self.assertFalse(self.context.faulted)

    def _assert_latched(self):
        with self.assertRaises(CliRpcError) as caught:
            self._route()
        self.assertEqual(caught.exception.args, ('CORE_RPC_CREDENTIAL_CHANGED_OR_UNSAFE',))
        self.assertTrue(self.context.faulted)
        with self.assertRaises(CliRpcError) as again:
            self._route()
        self.assertEqual(again.exception.args, ('CORE_RPC_SCOPE_FAULTED',))

    def _patch_cookie_fstat(self, **overrides):
        ino = self.cookie.stat().st_ino
        real = credentials.os.fstat
        seen = {'n': 0}

        def fstat(fd):
            info = real(fd)
            if info.st_ino != ino:
                return info
            seen['n'] += 1
            if seen['n'] == 1:
                return _StatView(info, **overrides) if overrides else info
            if overrides:
                return info
            return _StatView(info, st_ino=info.st_ino + 1)

        return patch.object(credentials.os, 'fstat', fstat), seen

    def test_inode_replaced_during_read_before_ready_is_bootstrap(self):
        # open -> fstat -> read -> fstat: the second stat sees a new inode.
        patcher, seen = self._patch_cookie_fstat()
        with patcher:
            self._assert_bootstrap()
        self.assertGreaterEqual(seen['n'], 2)

    def test_path_stat_inode_replaced_by_rename_before_ready_is_bootstrap(self):
        real = credentials.os.stat

        def stat(path, *args, **kwargs):
            info = real(path, *args, **kwargs)
            if path == '.cookie':
                return _StatView(info, st_ino=info.st_ino + 1)
            return info

        with patch.object(credentials.os, 'stat', stat):
            self._assert_bootstrap()

    def test_empty_cookie_before_ready_is_bootstrap(self):
        self.cookie.write_bytes(b'')
        self.assertEqual(stat.S_IMODE(self.cookie.stat().st_mode), 0o600)
        self._assert_bootstrap()

    def test_short_read_before_ready_is_bootstrap(self):
        ino = self.cookie.stat().st_ino
        real = credentials.os.read

        def read(fd, size):
            if os.fstat(fd).st_ino == ino:
                return b''
            return real(fd, size)

        with patch.object(credentials.os, 'read', read):
            self._assert_bootstrap()

    def test_unlinked_cookie_before_ready_is_bootstrap(self):
        patcher, _seen = self._patch_cookie_fstat(st_nlink=0)
        with patcher:
            self._assert_bootstrap()

    def test_rename_after_snapshot_before_ready_drops_cache(self):
        self.context.credentials = CredentialSource(self.directory)
        replacement = self.cookie.with_name('.cookie.next')
        fd = os.open(replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, b'__cookie__:' + b'cd' * 32 + b'\n')
        finally:
            os.close(fd)
        os.rename(replacement, self.cookie)
        self._assert_bootstrap()

    def test_same_inode_replacement_after_ready_latches(self):
        self.context.credentials = CredentialSource(self.directory)
        self.context.ready = True
        patcher, _seen = self._patch_cookie_fstat()
        with patcher:
            self._assert_latched()
        self.assertIsNotNone(self.context.credentials)

    def test_rename_after_snapshot_after_ready_latches(self):
        self.context.credentials = CredentialSource(self.directory)
        self.context.ready = True
        replacement = self.cookie.with_name('.cookie.next')
        fd = os.open(replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, b'__cookie__:' + b'ef' * 32 + b'\n')
        finally:
            os.close(fd)
        os.rename(replacement, self.cookie)
        self._assert_latched()
        self.assertIsNotNone(self.context.credentials)

    def test_wrong_mode_before_ready_latches(self):
        self.cookie.chmod(0o644)
        self._assert_latched()

    def test_wrong_uid_before_ready_latches(self):
        patcher, _seen = self._patch_cookie_fstat(st_uid=os.geteuid() + 1)
        with patcher:
            self._assert_latched()

    def test_hardlink_before_ready_latches(self):
        patcher, _seen = self._patch_cookie_fstat(st_nlink=2)
        with patcher:
            self._assert_latched()

    def test_oversize_cookie_before_ready_latches(self):
        self.cookie.write_bytes(b'x' * 300)
        self._assert_latched()

    def test_acl_before_ready_latches(self):
        ino = self.cookie.stat().st_ino
        real = credentials.os.fstat

        def no_acl(fd):
            if real(fd).st_ino == ino:
                raise MacosPrivateDirectoryError('MACOS_PRIVATE_DIRECTORY_ACL_DENIED')

        with patch('wam_regtest.private_directory._require_absent_acl', no_acl):
            self._assert_latched()

    def test_symlink_before_ready_latches(self):
        self.cookie.unlink()
        self.cookie.symlink_to(self.conf.name)
        self._assert_latched()

    def test_wrong_format_before_ready_latches(self):
        self.cookie.write_bytes(b'unsafe\n')
        self._assert_latched()

    def test_config_inode_change_before_ready_latches(self):
        ino = self.conf.stat().st_ino
        real = credentials.os.fstat
        seen = {'n': 0}

        def fstat(fd):
            info = real(fd)
            if info.st_ino != ino:
                return info
            seen['n'] += 1
            if seen['n'] >= 2:
                return _StatView(info, st_ino=info.st_ino + 1)
            return info

        with patch.object(credentials.os, 'fstat', fstat):
            self._assert_latched()

    def test_bootstrap_set_is_unchanged(self):
        source = Path(rpc_scope.__file__).read_text()
        self.assertIn(
            "('CORE_RPC_UNAVAILABLE',),('CORE_RPC_WARMUP',),\n"
            "                ('RPC_CREDENTIAL_MISSING_OR_UNSAFE',))",
            source)
        clause=source.split('bootstrap=', 1)[1].split('if not bootstrap', 1)[0]
        self.assertNotIn('RPC_CREDENTIAL_CHANGED', clause)
        self.assertNotIn('RPC_COOKIE_CHANGED', clause)
        self.assertNotIn('RPC_COOKIE_FORMAT_DENIED', clause)
