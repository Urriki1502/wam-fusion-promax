"""DUR-01a: shared full-flush primitive, site ordering, race/failure invariants, and child-process kills.

Contract: evidence/DUR-01-durability/CONTRACT-DOSSIER.md Revision 6c (FINAL)
= DRAFT-REV6b-DUR01a-hermes.md + Revision 6/6b Lead decisions + R2-1/R2-2/R2-3.

Scope note (C5 / §2 / §5-L):
  DUR-01a proves best-effort FILE-DATA hardening (F_FULLFSYNC on darwin) and
  ordering logic under injected errors and real process death. Power-loss /
  hardware durability and APFS namespace (link/rename/mkdir) persistence across
  power loss remain explicitly UNVERIFIED.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, nullcontext
import ctypes
import errno
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from mnemonic import Mnemonic

DARWIN = sys.platform == "darwin"
SRC = Path(__file__).resolve().parents[1] / "src"
SOURCE = Path(importlib.util.find_spec("wam_sp").origin).resolve().parents[2]
PASSWORD = b"dur01a-disposable-test-password"
PHRASE = Mnemonic("english").to_mnemonic(bytes(16))
PROFILE_ID = "a" * 32


class Cut(BaseException):
    """Unrecoverable process-death stand-in for cut-point tests."""


def _chain_and_funding(keys):
    from wam_sp.core import Input, pub, send
    from wam_sp.transaction import p2wpkh
    from wam_sp.watcher import GENESIS

    account = keys.accounts()[0]
    funding_input = Input(
        "05" * 32, 0, p2wpkh(91),
        witness=(bytes(72), pub(91)), secret=91,
    )
    output = send([funding_input], [account.payment_code()])[0]
    tx = {
        "txid": "ab" * 32,
        "vin": [{
            "txid": funding_input.txid,
            "vout": 0,
            "scriptSig": {"hex": ""},
            "txinwitness": [v.hex() for v in funding_input.witness],
            "prevout": {"scriptPubKey": {"hex": funding_input.script.hex()}},
        }],
        "vout": [{
            "n": 0,
            "value": 0.001,
            "scriptPubKey": {"hex": (b"\x51\x20" + output).hex()},
        }],
    }
    block = {
        "height": 1,
        "hash": sha256(b"dur01a synthetic signer chain").hexdigest(),
        "previousblockhash": GENESIS,
        "tx": [tx],
    }

    class Chain:
        def attest(self):
            return None

        def call(self, method, params=None):
            if method == "getbestblockhash":
                return block["hash"]
            if method == "getblockcount":
                return 1
            if method == "getblockhash":
                return GENESIS if params[0] == 0 else block["hash"]
            if method == "getblock":
                return block
            raise ValueError("DUR01A_SYNTHETIC_RPC_METHOD_DENIED")

    return Chain(), block


class FullFlushPrimitiveContracts(unittest.TestCase):
    def test_darwin_uses_f_fullfsync_and_never_calls_fsync(self):
        from wam_regtest import fullflush
        import fcntl

        seen = []

        def fake_fcntl(fd, cmd, *args):
            seen.append((fd, cmd, args))
            return 0

        with patch.object(fullflush.sys, "platform", "darwin"), \
                patch.object(fullflush.os, "fsync", side_effect=AssertionError("os.fsync forbidden on darwin file")), \
                patch.object(fcntl, "fcntl", fake_fcntl):
            fullflush.full_flush(42)
        expected_code = getattr(fcntl, "F_FULLFSYNC", 51)
        self.assertEqual(seen, [(42, expected_code, ())])

    def test_darwin_uses_fallback_constant_51_when_fcntl_attr_absent(self):
        from wam_regtest import fullflush
        import fcntl

        seen = []
        fake_fcntl_mod = SimpleNamespace(
            fcntl=lambda fd, cmd: seen.append((fd, cmd)) or 0
        )
        with patch.object(fullflush.sys, "platform", "darwin"), \
                patch.object(fullflush.os, "fsync", side_effect=AssertionError("os.fsync forbidden")), \
                patch.dict(sys.modules, {"fcntl": fake_fcntl_mod}):
            fullflush.full_flush(17)
        self.assertEqual(seen, [(17, 51)])
        self.assertTrue(hasattr(fcntl, "fcntl"))

    def test_darwin_unsupported_or_failing_fcntl_raises_without_fsync_fallback(self):
        from wam_regtest import fullflush
        import fcntl

        for err_no in (errno.ENOTTY, errno.EINVAL, errno.ENOTSUP, errno.EIO):
            with self.subTest(errno=err_no):
                with patch.object(fullflush.sys, "platform", "darwin"), \
                        patch.object(fullflush.os, "fsync", side_effect=AssertionError("no fsync fallback")), \
                        patch.object(fcntl, "fcntl", side_effect=OSError(err_no, "unsupported")):
                    with self.assertRaises(OSError) as ctx:
                        fullflush.full_flush(9)
                    self.assertEqual(ctx.exception.errno, err_no)

    def test_non_darwin_calls_os_fsync_without_fcntl(self):
        from wam_regtest import fullflush
        import fcntl

        seen = []
        with patch.object(fullflush.sys, "platform", "linux"), \
                patch.object(fcntl, "fcntl", side_effect=AssertionError("fcntl forbidden on linux")), \
                patch.object(fullflush.os, "fsync", side_effect=lambda fd: seen.append(fd)):
            fullflush.full_flush(21)
            fullflush.flush_directory(22)
            fullflush.flush_after_mkdir(23)
        self.assertEqual(seen, [21, 22, 23])

    def test_flush_directory_and_flush_after_mkdir_semantics(self):
        from wam_regtest import fullflush
        import fcntl

        events = []
        with patch.object(fullflush.sys, "platform", "darwin"), \
                patch.object(fullflush.os, "fsync", side_effect=lambda fd: events.append(("fsync", fd))), \
                patch.object(fcntl, "fcntl", side_effect=lambda fd, cmd: events.append(("fullfsync", fd, cmd)) or 0):
            fullflush.flush_directory(11)
            fullflush.flush_after_mkdir(12)
        expected_code = getattr(fcntl, "F_FULLFSYNC", 51)
        self.assertEqual(events, [
            ("fsync", 11), ("fullfsync", 11, expected_code),
            ("fsync", 12), ("fullfsync", 12, expected_code),
        ])

    def test_flush_path_helpers_preserve_primary_error_over_cleanup_close(self):
        from wam_regtest import fullflush

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve()
            real_close = os.close

            def bad_close(fd):
                real_close(fd)
                raise OSError(errno.EBADF, "cleanup-close")

            with patch.object(fullflush, "flush_directory", side_effect=OSError(errno.EIO, "primary-flush")), \
                    patch.object(fullflush.os, "close", side_effect=bad_close):
                with self.assertRaises(OSError) as ctx:
                    fullflush.flush_path_directory(path)
                self.assertEqual(ctx.exception.errno, errno.EIO)

            # When flush succeeds, cleanup close failure must raise.
            def bad_close_after_ok(fd):
                real_close(fd)
                raise OSError(errno.EIO, "close-after-ok")

            with patch.object(fullflush.os, "close", side_effect=bad_close_after_ok):
                with self.assertRaises(OSError) as ctx:
                    fullflush.flush_parent_after_mkdir(path)
                self.assertEqual(ctx.exception.errno, errno.EIO)

    def test_quit_notice_converges_into_shared_fullflush(self):
        from wam_regtest import fullflush, quit_notice

        self.assertFalse(hasattr(quit_notice, "_fullfsync"))
        self.assertFalse(hasattr(quit_notice, "_F_FULLFSYNC_DARWIN"))
        self.assertIs(quit_notice.full_flush, fullflush.full_flush)
        self.assertIs(quit_notice.flush_directory, fullflush.flush_directory)


@unittest.skipUnless(DARWIN, "macOS darwin durability sites")
class SiteCallOrderAndPlatformContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wam-dur01a-sites-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_pa_encrypted_storage_publish_call_order(self):
        from wam_regtest import encrypted_storage, fullflush

        events = []
        real_write = encrypted_storage.os.write
        real_close = encrypted_storage.os.close
        real_link = encrypted_storage.os.link
        real_unlink = encrypted_storage.os.unlink
        real_full_flush = fullflush.full_flush
        real_flush_dir = fullflush.flush_directory

        def spy_write(fd, data):
            events.append("write")
            return real_write(fd, data)

        def spy_full_flush(fd):
            events.append("full_flush")
            return real_full_flush(fd)

        def spy_close(fd):
            if "write" in events:
                events.append("close")
            return real_close(fd)

        def spy_link(*args, **kwargs):
            events.append("link")
            return real_link(*args, **kwargs)

        def spy_unlink(*args, **kwargs):
            events.append("unlink")
            return real_unlink(*args, **kwargs)

        def spy_flush_dir(dfd):
            events.append("flush_directory")
            return real_flush_dir(dfd)

        target = self.root / "pa"
        target.mkdir(mode=0o700)
        with patch.object(encrypted_storage.os, "write", spy_write), \
                patch.object(encrypted_storage, "full_flush", spy_full_flush), \
                patch.object(encrypted_storage.os, "close", spy_close), \
                patch.object(encrypted_storage.os, "link", spy_link), \
                patch.object(encrypted_storage.os, "unlink", spy_unlink), \
                patch.object(encrypted_storage, "flush_directory", spy_flush_dir):
            encrypted_storage.publish(target, "item.enc", b"WAMSP02\x00" + bytes(64))

        # close(dfd) happens in finally after flush_directory
        self.assertEqual(
            events,
            ["write", "full_flush", "close", "link", "unlink", "flush_directory", "close"],
        )

    def test_pb_supervisor_store_darwin_call_order_with_and_without_stage_dir_creation(self):
        from wam_regtest import fullflush, supervisor_store as store

        events = []
        real_mkdir = store.os.mkdir
        real_write = store.os.write
        real_rename = store._rename_exclusive
        real_after_mkdir = fullflush.flush_after_mkdir
        real_full_flush = fullflush.full_flush
        real_flush_dir = fullflush.flush_directory

        root = self.root / "wam-fusion-core-0123456789abcdef"
        root.mkdir(mode=0o700)

        with patch.object(store.os, "mkdir", lambda *a, **k: (events.append("mkdir"), real_mkdir(*a, **k))[1]), \
                patch.object(store, "flush_after_mkdir", lambda fd: (events.append("flush_after_mkdir"), real_after_mkdir(fd))[1]), \
                patch.object(store.os, "write", lambda fd, d: (events.append("write"), real_write(fd, d))[1]), \
                patch.object(store, "full_flush", lambda fd: (events.append("full_flush"), real_full_flush(fd))[1]), \
                patch.object(store, "_rename_exclusive", lambda *a: (events.append("rename"), real_rename(*a))[1]), \
                patch.object(store, "flush_directory", lambda fd: (events.append("flush_directory"), real_flush_dir(fd))[1]):
            store.create_once(root, "supervisor.token", b"t" * 32)
            first_events = list(events)
            events.clear()
            store.create_once(root, "supervisor.profile", b"p" * 32)
            second_events = list(events)

        self.assertEqual(
            first_events,
            ["mkdir", "flush_after_mkdir", "write", "full_flush", "rename", "flush_directory"],
        )
        self.assertEqual(
            second_events,
            ["write", "full_flush", "rename", "flush_directory"],
        )

    def test_backup_ack_call_order_nested_first_write_and_subsequent_write(self):
        from wam_regtest import fullflush
        from wam_regtest.domain import backup_ack

        events = []
        real_mkdir = Path.mkdir
        real_write = backup_ack.os.write
        real_rename = backup_ack.os.rename
        real_after_mkdir = fullflush.flush_after_mkdir
        real_full_flush = fullflush.full_flush
        real_flush_dir = fullflush.flush_directory

        def spy_mkdir(path_obj, *args, **kwargs):
            events.append(("mkdir", path_obj.name))
            return real_mkdir(path_obj, *args, **kwargs)

        root = self.root / "ack-profile"
        root.mkdir(mode=0o700)
        folder = root / ("bip39-12-" + "a" * 32)
        payload = json.dumps({"version": 1, "acknowledged": False, "deferred": True, "seed_id": folder.name}).encode()

        depth = [0]

        def spy_after(fd):
            events.append("flush_after_mkdir")
            depth[0] += 1
            try:
                return real_after_mkdir(fd)
            finally:
                depth[0] -= 1

        def spy_ff(fd):
            if depth[0] == 0:
                events.append("full_flush")
            return real_full_flush(fd)

        def spy_fd(fd):
            events.append("flush_directory")
            depth[0] += 1
            try:
                return real_flush_dir(fd)
            finally:
                depth[0] -= 1

        with patch.object(Path, "mkdir", spy_mkdir), \
                patch.object(fullflush, "flush_after_mkdir", spy_after), \
                patch.object(backup_ack.os, "write", lambda fd, d: (events.append("write"), real_write(fd, d))[1]), \
                patch.object(fullflush, "full_flush", spy_ff), \
                patch.object(backup_ack.os, "rename", lambda *a, **k: (events.append("rename"), real_rename(*a, **k))[1]), \
                patch.object(fullflush, "flush_directory", spy_fd):
            backup_ack._ack_write(root, folder.name + ".json", payload)
            first_events = list(events)
            events.clear()
            backup_ack._ack_write(root, folder.name + ".json", payload)
            second_events = list(events)

        self.assertEqual(
            first_events,
            [
                ("mkdir", "q06-gui-state"), "flush_after_mkdir",
                ("mkdir", "ack"), "flush_after_mkdir",
                "write", "full_flush", "rename", "flush_directory",
            ],
        )
        self.assertEqual(
            second_events,
            ["write", "full_flush", "rename", "flush_directory"],
        )

    def test_config_writers_call_full_flush_then_flush_directory_never_flush_after_mkdir(self):
        from wam_regtest import core, fullflush, shared_regtest

        d1 = self.root / "cfg1"
        d1.mkdir(mode=0o700)
        d2 = self.root / "cfg2"
        d2.mkdir(mode=0o700)

        events = []
        real_full_flush = fullflush.full_flush
        real_flush_dir = fullflush.flush_directory

        def spy_full_flush(fd):
            events.append(("full_flush", stat.S_ISDIR(os.fstat(fd).st_mode)))
            return real_full_flush(fd)

        def spy_flush_dir(fd):
            events.append(("flush_directory", stat.S_ISDIR(os.fstat(fd).st_mode)))
            return real_flush_dir(fd)

        with patch.object(core, "full_flush", spy_full_flush), \
                patch.object(fullflush, "flush_directory", spy_flush_dir), \
                patch.object(fullflush, "flush_after_mkdir", side_effect=AssertionError("config writer must not call flush_after_mkdir")):
            core._write_private_config(d1, 28443, 28444)
        self.assertEqual(events, [("full_flush", False), ("flush_directory", True)])

        events.clear()
        profile = shared_regtest.SharedRegtestProfile(
            coordinator=True, bind_host="127.0.0.1", p2p_port=28445,
            rpc_port=28446, peer_host="127.0.0.1", peer_port=28447,
        )
        with patch.object(shared_regtest, "full_flush", spy_full_flush), \
                patch.object(fullflush, "flush_directory", spy_flush_dir), \
                patch.object(fullflush, "flush_after_mkdir", side_effect=AssertionError("config writer must not call flush_after_mkdir")):
            shared_regtest.write_config(d2, profile)
        self.assertEqual(events, [("full_flush", False), ("flush_directory", True)])

    def test_quit_notice_call_order(self):
        from wam_regtest import fullflush, quit_notice
        from wam_regtest.supervisor_store import exclusive_lease

        qroot = self.root / "wam-fusion-core-1111111111111111"
        qroot.mkdir(mode=0o700)
        events = []
        real_full_flush = fullflush.full_flush
        real_flush_dir = fullflush.flush_directory
        real_link = quit_notice.os.link
        real_unlink = quit_notice.os.unlink

        with exclusive_lease(qroot), \
                patch.object(quit_notice, "full_flush", lambda fd: (events.append("full_flush"), real_full_flush(fd))[1]), \
                patch.object(quit_notice, "flush_directory", lambda fd: (events.append("flush_directory"), real_flush_dir(fd))[1]), \
                patch.object(quit_notice.os, "link", lambda *a, **k: (events.append("link"), real_link(*a, **k))[1]), \
                patch.object(quit_notice.os, "unlink", lambda *a, **k: (events.append("unlink"), real_unlink(*a, **k))[1]):
            quit_notice.publish_notice(
                qroot,
                profile_id=PROFILE_ID,
                session_kind="Q05",
                wallet_outcome="RUNTIME_PRESERVED",
                core_stop="CLEAN",
                codes=("WALLET_MANAGED_RUNTIME_PRESERVED",),
                journal_seq=1,
            )
        self.assertEqual(events, ["full_flush", "link", "flush_directory", "unlink", "flush_directory"])

    def test_windows_and_linux_preservation(self):
        from wam_regtest import fullflush, shared_regtest, supervisor_store as store
        from wam_regtest.domain import backup_ack

        # 1. supervisor_store.create_once on win32 -> native.flush, never fullflush
        written = []

        class Native:
            class w:
                DWORD = ctypes.c_ulong
            write = staticmethod(lambda handle, buf, size, count, ov: (
                written.append(buf.raw[:size]),
                setattr(ctypes.cast(count, ctypes.POINTER(ctypes.c_ulong)).contents, "value", size),
                True,
            )[-1])
            flush = staticmethod(MagicMock(return_value=True))
            close = staticmethod(lambda handle: None)

        guard = MagicMock()
        win_root = self.root / "wam-fusion-core-0000000000000001"
        win_root.mkdir(mode=0o700)
        with patch.object(store.sys, "platform", "win32"), \
                patch.object(store, "_win_open", return_value=(Native, 7, guard)), \
                patch.object(fullflush, "full_flush", side_effect=AssertionError("win32 must not call full_flush")), \
                patch.object(fullflush, "flush_directory", side_effect=AssertionError("win32 must not call flush_directory")), \
                patch.object(fullflush, "flush_after_mkdir", side_effect=AssertionError("win32 must not call flush_after_mkdir")):
            store.create_once(win_root, "supervisor.token", b"w" * 32)
        Native.flush.assert_called_once_with(7)
        self.assertEqual(b"".join(written), b"w" * 32)

        # 2. supervisor_store.create_once on linux -> os.fsync, never fullflush or fcntl
        linux_root = self.root / "wam-fusion-core-0000000000000002"
        linux_root.mkdir(mode=0o700)

        @contextmanager
        def fake_dir(path):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                yield fd
            finally:
                os.close(fd)

        from wam_regtest import linux_private_storage
        import fcntl
        fsync_calls = []
        real_fsync = os.fsync
        with patch.object(store.sys, "platform", "linux"), \
                patch.object(store, "_posix_dir", fake_dir), \
                patch.object(linux_private_storage, "_no_acl", lambda fd: None), \
                patch.object(fullflush, "full_flush", side_effect=AssertionError("linux create_once keeps os.fsync")), \
                patch.object(fcntl, "fcntl", side_effect=AssertionError("linux create_once must not call fcntl")), \
                patch.object(store.os, "fsync", side_effect=lambda fd: (fsync_calls.append(fd), real_fsync(fd))[1]):
            store.create_once(linux_root, "supervisor.token", b"l" * 32)
        self.assertEqual(len(fsync_calls), 2)

        # 3. backup_ack._ack_write on win32 -> os.fsync + os.replace, never fullflush
        win_ack = self.root / "win-ack"
        (win_ack / "q06-gui-state" / "ack").mkdir(parents=True)
        with patch.object(backup_ack.sys, "platform", "win32"), \
                patch.dict(sys.modules, {"wam_regtest.windows_private_storage": SimpleNamespace(validate_directory=lambda d: None)}), \
                patch.object(fullflush, "full_flush", side_effect=AssertionError("win32 backup_ack must not call full_flush")), \
                patch.object(backup_ack.os, "fsync", wraps=os.fsync) as ack_fsync:
            backup_ack._ack_write(win_ack, "bip39-12-" + "a" * 32 + ".json", b"{}")
        self.assertEqual(ack_fsync.call_count, 1)

        # 4. shared_regtest.write_config on win32 -> windows_core_transport.write_new, never fullflush
        profile = shared_regtest.SharedRegtestProfile(
            coordinator=True, bind_host="127.0.0.1", p2p_port=28450,
            rpc_port=28451, peer_host="127.0.0.1", peer_port=28452,
        )
        fake_wct = SimpleNamespace(write_new=MagicMock())
        with patch.object(shared_regtest.sys, "platform", "win32"), \
                patch("wam_regtest.custody.storage", return_value=SimpleNamespace(validate_directory=lambda d: None)), \
                patch.dict(sys.modules, {"wam_regtest.windows_core_transport": fake_wct}), \
                patch.object(fullflush, "full_flush", side_effect=AssertionError("win32 write_config must not call full_flush")):
            shared_regtest.write_config(self.root, profile)
        fake_wct.write_new.assert_called_once()


@unittest.skipUnless(DARWIN, "macOS darwin mkdir sites")
class MkdirNestedAndRaceContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wam-dur01a-mkdir-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_m1_custody_create_directory_flushes_parent(self):
        from wam_regtest import custody, fullflush

        target = self.root / "m1-evidence"
        flushed = []
        real_after = fullflush.flush_after_mkdir

        def spy(pfd):
            flushed.append(os.fstat(pfd).st_ino)
            return real_after(pfd)

        with patch.object(fullflush, "flush_after_mkdir", spy):
            custody.create_directory(target)
        self.assertEqual(flushed, [os.stat(self.root).st_ino])

    def test_m2_private_temporary_directory_race_winner_and_loser_both_flush(self):
        from wam_regtest import custody, fullflush

        work = self.root / "cwd-m2"
        work.mkdir(mode=0o700)
        parent_ino = os.stat(work).st_ino
        barrier = threading.Barrier(2)
        original_mkdir = Path.mkdir
        results = []
        lock = threading.Lock()
        real_after = fullflush.flush_after_mkdir

        def synchronized_mkdir(path_obj, *args, **kwargs):
            if path_obj.name == ".wam-regtest-temp":
                barrier.wait(timeout=5)
            return original_mkdir(path_obj, *args, **kwargs)

        def spy_after(pfd):
            ino = os.fstat(pfd).st_ino
            with lock:
                results.append(ino)
            return real_after(pfd)

        old_cwd = os.getcwd()
        os.chdir(work)
        self.addCleanup(os.chdir, old_cwd)
        with patch.object(Path, "mkdir", synchronized_mkdir), \
                patch.object(fullflush, "flush_after_mkdir", spy_after):
            t1 = threading.Thread(target=lambda: custody.private_temporary_directory("a-").cleanup())
            t2 = threading.Thread(target=lambda: custody.private_temporary_directory("b-").cleanup())
            t1.start()
            t2.start()
            t1.join(timeout=10)
            t2.join(timeout=10)

        self.assertEqual(results, [parent_ino, parent_ino])

    def test_m3_backup_ack_nested_state_and_ack_both_flush_parent(self):
        from wam_regtest import fullflush
        from wam_regtest.domain import backup_ack

        profile = self.root / "m3-profile"
        profile.mkdir(mode=0o700)
        flushed_inos = []
        real_after = fullflush.flush_after_mkdir

        def spy(pfd):
            flushed_inos.append(os.fstat(pfd).st_ino)
            return real_after(pfd)

        with patch.object(fullflush, "flush_after_mkdir", spy):
            ack_dir = backup_ack._ack_ensure_directories(profile)
            # Second call finds existing directories -> 0 flushes
            backup_ack._ack_ensure_directories(profile)

        self.assertEqual(
            flushed_inos,
            [os.stat(profile).st_ino, os.stat(profile / "q06-gui-state").st_ino],
        )
        self.assertTrue(ack_dir.is_dir())

    def test_m4_vault_ensure_private_directory_nested_and_race_winner_and_loser_both_flush(self):
        from wam_regtest import fullflush, vault

        nested = self.root / "lvl1" / "lvl2" / "lvl3"
        flushed = []
        real_after = fullflush.flush_after_mkdir

        def spy(pfd):
            flushed.append(os.fstat(pfd).st_ino)
            return real_after(pfd)

        with patch.object(fullflush, "flush_after_mkdir", spy):
            vault._ensure_private_directory(nested)
        self.assertEqual(
            flushed,
            [
                os.stat(self.root).st_ino,
                os.stat(self.root / "lvl1").st_ino,
                os.stat(self.root / "lvl1" / "lvl2").st_ino,
            ],
        )

        # Race on missing leaf: winner creates it, loser catches FileExistsError; BOTH flush parent!
        race_parent = self.root / "race-m4"
        race_parent.mkdir(mode=0o700)
        race_leaf = race_parent / "leaf"
        barrier = threading.Barrier(2)
        orig_mkdir = Path.mkdir
        race_flushed = []
        lock = threading.Lock()

        def sync_mkdir(path_obj, *args, **kwargs):
            if path_obj == race_leaf:
                barrier.wait(timeout=5)
            return orig_mkdir(path_obj, *args, **kwargs)

        def spy_race(pfd):
            ino = os.fstat(pfd).st_ino
            with lock:
                race_flushed.append(ino)
            return real_after(pfd)

        with patch.object(Path, "mkdir", sync_mkdir), \
                patch.object(fullflush, "flush_after_mkdir", spy_race):
            t1 = threading.Thread(target=lambda: vault._ensure_private_directory(race_leaf))
            t2 = threading.Thread(target=lambda: vault._ensure_private_directory(race_leaf))
            t1.start()
            t2.start()
            t1.join(timeout=10)
            t2.join(timeout=10)

        self.assertEqual(race_flushed, [os.stat(race_parent).st_ino, os.stat(race_parent).st_ino])

    def test_m5_supervisor_stage_directory_race_winner_and_loser_both_flush(self):
        from wam_regtest import fullflush, supervisor_store as store

        root = self.root / "wam-fusion-core-2222222222222222"
        root.mkdir(mode=0o700)
        root_ino = os.stat(root).st_ino
        barrier = threading.Barrier(2)
        orig_mkdir = store.os.mkdir
        flushed = []
        lock = threading.Lock()
        real_after = fullflush.flush_after_mkdir

        def sync_mkdir(name, mode=0o777, *, dir_fd=None):
            if name == store.STAGE_DIRECTORY:
                barrier.wait(timeout=5)
            return orig_mkdir(name, mode, dir_fd=dir_fd)

        def spy_after(pfd):
            ino = os.fstat(pfd).st_ino
            with lock:
                flushed.append(ino)
            return real_after(pfd)

        def open_stage():
            with store._posix_dir(root) as dfd:
                sfd = store._open_stage_directory(dfd, create=True)
                os.close(sfd)

        with patch.object(store.os, "mkdir", sync_mkdir), \
                patch.object(store, "flush_after_mkdir", spy_after):
            t1 = threading.Thread(target=open_stage)
            t2 = threading.Thread(target=open_stage)
            t1.start()
            t2.start()
            t1.join(timeout=10)
            t2.join(timeout=10)

        self.assertEqual(flushed, [root_ino, root_ino])


@unittest.skipUnless(DARWIN, "macOS darwin config writer startup gate")
class ConfigWriterStartupFailClosedContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wam-dur01a-cfg-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def test_core_supervisor_startup_cannot_proceed_after_config_write_or_flush_failure(self):
        from wam_regtest import core, core_supervisor as module, fullflush, shared_regtest

        core_dir = self.base / "core"
        for idx, (mode, shared) in enumerate((
            ("write", False),
            ("full_flush", False),
            ("flush_directory", False),
            ("write", True),
            ("full_flush", True),
            ("flush_directory", True),
        )):
            with self.subTest(mode=mode, shared=shared):
                root = self.base / f"wam-fusion-core-{idx:016x}"
                root.mkdir(mode=0o700)
                stack = ExitStack()
                self.addCleanup(stack.close)
                stack.enter_context(patch.object(
                    module, "verified_core_paths",
                    return_value=(core_dir / "wamd", core_dir / "wam-cli",
                                  {"wamd_sha256": "a" * 64, "wam_cli_sha256": "b" * 64}),
                ))
                stack.enter_context(patch.object(module, "_metadata", return_value=("fixture",)))
                stack.enter_context(patch.object(module, "storage", return_value=Mock()))
                stack.enter_context(patch.object(module, "create_directory", side_effect=lambda p: p.mkdir(mode=0o700)))
                if mode == "write":
                    real_fdopen = os.fdopen

                    def bad_fdopen(fd, *args, **kwargs):
                        stream = real_fdopen(fd, *args, **kwargs)
                        stream.write = Mock(side_effect=OSError(errno.ENOSPC, "disk full"))
                        return stream

                    stack.enter_context(patch.object(core.os if not shared else shared_regtest.os, "fdopen", bad_fdopen))
                elif mode == "full_flush":
                    target_mod = shared_regtest if shared else core
                    stack.enter_context(patch.object(target_mod, "full_flush", side_effect=OSError(errno.EIO, "flush fail")))
                else:
                    stack.enter_context(patch.object(fullflush, "flush_directory", side_effect=OSError(errno.EIO, "dir flush fail")))

                shared_profile = None
                if shared:
                    shared_profile = shared_regtest.SharedRegtestProfile(
                        coordinator=True, bind_host="127.0.0.1", p2p_port=28500 + idx * 2,
                        rpc_port=28501 + idx * 2, peer_host="127.0.0.1", peer_port=28599,
                    )
                with self.assertRaises(OSError):
                    module.CoreSupervisor(root, core_dir, authorized=True, shared_profile=shared_profile)
                # Startup aborted before creating profile/token/journal
                self.assertFalse((root / "supervisor.profile").exists())
                self.assertFalse((root / "supervisor.token").exists())
                stack.close()


@unittest.skipUnless(DARWIN, "macOS darwin cross-chain failure invariants")
class CrossChainFlushFailureInvariants(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wam-dur01a-chain-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_a_flush_failure_in_vault_save_and_native_checkpoint_never_advances_anchor(self):
        from wam_regtest import bip39_native_checkpoint, custody, encrypted_storage
        from wam_regtest.bip39_12 import Bip39Regtest12Keys
        from wam_regtest.vault import CheckpointVault, KeychainAnchor
        from wam_sp.keystore import Keyring
        from wam_sp.scanner import Scanner

        vault_keys = Keyring()
        self.addCleanup(vault_keys.close)
        chain, _ = _chain_and_funding(vault_keys)
        scanner = Scanner(self.root / "sc.sqlite", vault_keys.accounts())
        self.addCleanup(scanner.close)
        scanner.sync(chain)

        for failure_target in ("full_flush", "flush_directory"):
            with self.subTest(vault_failure=failure_target):
                vdir = self.root / f"vault-{failure_target}"
                vdir.mkdir(mode=0o700)
                anchor = KeychainAnchor("0" * 32)
                called = [0]

                def fail_vault(fd):
                    called[0] += 1
                    raise OSError(errno.EIO, "injected")

                with patch.object(anchor, "read", return_value=None), \
                        patch.object(anchor, "lease", return_value=ExitStack()), \
                        patch.object(anchor, "_advance_unlocked") as adv_mock:
                    vault = CheckpointVault(vdir, anchor, SOURCE)
                    with patch.object(encrypted_storage, failure_target, side_effect=fail_vault):
                        with self.assertRaises(encrypted_storage.EncryptedStorageError):
                            vault.save(vault_keys, scanner, PASSWORD)
                    self.assertEqual(called[0], 1)
                    adv_mock.assert_not_called()

        keys = Bip39Regtest12Keys(PHRASE, source=SOURCE, authorized_disposable=True)
        self.addCleanup(keys.close)

        # Also bip39_native_checkpoint.publish_owned_candidate
        for failure_target in ("full_flush", "flush_directory"):
            with self.subTest(native_checkpoint_failure=failure_target):
                owner_dir = self.root / f"owner-{failure_target}"
                owner_dir.mkdir(mode=0o700)
                seed_folder = owner_dir / ("bip39-12-" + "1" * 32)
                seed_folder.mkdir(mode=0o700)
                owner = SimpleNamespace(directory=owner_dir)
                anchor = KeychainAnchor("1" * 32)
                ckpt_scanner = SimpleNamespace(store=SimpleNamespace(tip=lambda: (1, "c" * 64)))
                called = [0]

                def fail_ckpt(fd):
                    called[0] += 1
                    raise OSError(errno.EIO, "injected")

                with patch.object(anchor, "read", return_value=None), \
                        patch.object(anchor, "lease", return_value=ExitStack()), \
                        patch.object(anchor, "_advance_unlocked") as adv_mock, \
                        patch.object(bip39_native_checkpoint, "_owned_password", return_value=PASSWORD.decode()), \
                        patch.object(bip39_native_checkpoint, "open_owned_seed_container", return_value=nullcontext(keys)), \
                        patch.object(bip39_native_checkpoint, "_owner_binding", return_value="b"), \
                        patch.object(bip39_native_checkpoint, "_owned_tip", return_value=(1, "c" * 64)), \
                        patch.object(bip39_native_checkpoint, "encode_candidate", return_value=b"candidate-bytes"), \
                        patch("wam_regtest.managed_wallet_checkpoint.durable_core_checkpoint"), \
                        patch.object(bip39_native_checkpoint, "_native", return_value=(encrypted_storage, anchor)), \
                        patch.object(bip39_native_checkpoint, "_exact_namespace"), \
                        patch.object(custody, "storage", return_value=encrypted_storage), \
                        patch.object(custody, "create_directory", side_effect=lambda p: p.mkdir(mode=0o700)), \
                        patch.object(encrypted_storage, failure_target, side_effect=fail_ckpt):
                    with self.assertRaisesRegex(bip39_native_checkpoint.SeededNativeCheckpointError, "Q06_NATIVE_CHECKPOINT_PUBLISH_DENIED"):
                        bip39_native_checkpoint.publish_owned_candidate(
                            owner, seed_folder, ckpt_scanner, SOURCE, PASSWORD, authorized=True,
                        )
                self.assertEqual(called[0], 1)
                adv_mock.assert_not_called()

    def test_b_signed_evidence_flush_failure_latches_and_raises_r2_3(self):
        from wam_regtest import encrypted_storage
        from wam_regtest.bip39_12 import Bip39Regtest12Keys
        from wam_regtest.bip39_spend_session import Q06OwnedSpendSession, Q06SpendSessionError
        from wam_regtest.wallet_session import PaymentReview
        from wam_sp.scanner import Scanner
        from wam_sp.wallet import Intent, Wallet

        keys = Bip39Regtest12Keys(PHRASE, source=SOURCE, authorized_disposable=True)
        recipient = Bip39Regtest12Keys(Mnemonic("english").to_mnemonic(bytes([1] * 16)), source=SOURCE, authorized_disposable=True)
        self.addCleanup(keys.close)
        self.addCleanup(recipient.close)
        chain, block = _chain_and_funding(keys)
        scanner = Scanner(self.root / "sign-ev.sqlite", keys.accounts())
        self.addCleanup(scanner.close)
        scanner.sync(chain)
        wallet = Wallet(scanner)
        intent = Intent(recipient.accounts()[0].payment_code(), 50_000)
        proposal = wallet.propose((intent,), 1000)

        for failure_target in ("full_flush", "flush_directory"):
            with self.subTest(failure=failure_target):
                owner_dir = self.root / f"ev-owner-{failure_target}"
                owner_dir.mkdir(mode=0o700)
                session = object.__new__(Q06OwnedSpendSession)
                session._lock = threading.RLock()
                session.vault = SimpleNamespace(anchor=SimpleNamespace(lease=lambda: ExitStack()), save=lambda *a: None)
                session.scanner = scanner
                session.ring = keys
                session._password = PASSWORD
                session._tip = (1, block["hash"])
                session._rpc = lambda: chain
                session._require_fresh_fee_quote = lambda rpc: None
                session._save = lambda: None
                session._q06_owner = SimpleNamespace(directory=owner_dir)
                session._q06_guard = SimpleNamespace(check=lambda: None)
                session._q06_uncertain = False
                session.faulted = False
                session._signed = None
                from wam_sp.wallet import Signer
                prepared = Signer(keys).prepare(proposal)
                session._prepared = prepared
                commitment = "ab" * 32
                session._review = PaymentReview(intent.code, 50_000, 1000, 49_000, 1, commitment)

                called = [0]

                def fail_ev(fd):
                    called[0] += 1
                    raise OSError(errno.EIO, "ev-flush-fail")

                # Reset reservation to draft for each subtest via fresh scanner if needed
                with patch("wam_regtest.bip39_spend_session._owned"), \
                        patch("wam_regtest.bip39_spend_session._owner_binding", return_value="binding"), \
                        patch.object(session, "_unchanged_inputs"), \
                        patch.object(encrypted_storage, failure_target, side_effect=fail_ev):
                    with self.assertRaisesRegex(Q06SpendSessionError, "^Q06_PAYMENT_EVIDENCE_PRESERVED_NO_RETRY$"):
                        session.sign(commitment)
                # R2-3: asserts latch + raise only; no claim on concurrent _signed use (LIFE-05 out of scope).
                self.assertEqual(called[0], 1)
                self.assertTrue(session.faulted)
                self.assertTrue(session._q06_uncertain)
                # Restore scanner for second subtest
                scanner.store.db.execute("UPDATE reservations SET state='draft'")
                scanner.store.db.commit()

    def test_c_flush_failure_at_pre_rpc_checkpoint_never_calls_broadcast_rpc(self):
        from wam_regtest import encrypted_storage
        from wam_regtest.bip39_spend_session import Q06OwnedSpendSession
        from wam_regtest.vault import CheckpointVault, KeychainAnchor
        from wam_regtest.wallet_session import PaymentReview, WalletSessionError
        from wam_sp.keystore import Keyring
        from wam_sp.scanner import Scanner
        from wam_sp.wallet import Intent, Signer, Wallet

        keys = Keyring()
        keys.public_metadata = lambda: {"account_id": "0" * 64}
        recipient = Keyring()
        self.addCleanup(keys.close)
        self.addCleanup(recipient.close)
        chain, block = _chain_and_funding(keys)

        for failure_target in ("full_flush", "flush_directory"):
            with self.subTest(pre_rpc_save_failure=failure_target):
                sdir = self.root / f"bcast-{failure_target}"
                sdir.mkdir(mode=0o700)
                scanner = Scanner(sdir / "sc.sqlite", keys.accounts())
                self.addCleanup(scanner.close)
                scanner.sync(chain)
                wallet = Wallet(scanner)
                intent = Intent(recipient.accounts()[0].payment_code(), 50_000)
                proposal = wallet.propose((intent,), 1000)
                wallet.mark_signed(proposal.token)
                signed = Signer(keys).sign(Signer(keys).prepare(proposal), (intent,), 1000)

                vdir = sdir / "vault"
                vdir.mkdir(mode=0o700)
                anchor = KeychainAnchor("2" * 32)
                with patch.object(anchor, "read", return_value=None), \
                        patch.object(anchor, "lease", return_value=ExitStack()), \
                        patch.object(anchor, "_advance_unlocked"):
                    vault = CheckpointVault(vdir, anchor, SOURCE)

                    session = object.__new__(Q06OwnedSpendSession)
                    session._lock = threading.RLock()
                    session.vault = vault
                    session.scanner = scanner
                    session.ring = keys
                    session._password = PASSWORD
                    session._tip = (1, block["hash"])
                    session._rpc = lambda: chain
                    session._managed_owner = None
                    session._q06_owner = SimpleNamespace(directory=sdir)
                    session._q06_guard = SimpleNamespace(check=lambda: None)
                    session._q06_uncertain = False
                    session.faulted = False
                    session._signed = signed
                    session._prepared = SimpleNamespace(proposal=proposal)
                    commitment = "cd" * 32
                    session._review = PaymentReview(intent.code, 50_000, 1000, 49_000, 1, commitment)

                    # Let uncertain evidence publish succeed, then fail the pre-RPC checkpoint _save() flush.
                    real_target = getattr(encrypted_storage, failure_target)
                    calls = [0]

                    def fail_on_checkpoint_save(fd):
                        calls[0] += 1
                        # 1st call = uncertain evidence; 2nd call = pre-RPC checkpoint save
                        if calls[0] == 2:
                            raise OSError(errno.EIO, "pre-rpc-save-fail")
                        return real_target(fd)

                    with patch("wam_regtest.bip39_spend_session._owned"), \
                            patch("wam_regtest.bip39_spend_session._owner_binding", return_value="binding"), \
                            patch.object(session, "_unchanged_inputs"), \
                            patch.object(session, "_preflight_not_submitted"), \
                            patch("wam_sp.wallet.Wallet.broadcast", side_effect=AssertionError("broadcast RPC must not run")) as rpc_mock, \
                            patch.object(encrypted_storage, failure_target, fail_on_checkpoint_save):
                        with self.assertRaises(WalletSessionError):
                            session.broadcast(commitment)
                    self.assertEqual(calls[0], 2)
                    rpc_mock.assert_not_called()
                    self.assertTrue(session.faulted)

    def test_d_flush_failure_in_stop_journal_never_releases_lease_and_quit_ack_exception(self):
        from wam_regtest import core_supervisor as cs_mod, supervisor_store as store
        from wam_regtest.core_supervisor import CoreSupervisor, ManagedCoreError
        from wam_regtest.wallet_executor import ManagedWalletBackend, WalletExecutor, WalletExecutorError
        from wam_regtest.wallet_session import WalletSessionError

        for idx, (fail_stage, failure_target) in enumerate((("STOPPING", "full_flush"), ("CLEAN", "flush_directory"))):
            with self.subTest(stage=fail_stage, target=failure_target):
                sroot = self.root / f"wam-fusion-core-{idx:016x}"
                sroot.mkdir(mode=0o700)
                core_dir = self.root / "core"
                with patch.object(cs_mod, "verified_core_paths", return_value=(
                    core_dir / "wamd", core_dir / "wam-cli",
                    {"wamd_sha256": "a" * 64, "wam_cli_sha256": "b" * 64},
                )), patch.object(cs_mod, "_metadata", return_value=("fixture",)), \
                        patch.object(cs_mod, "storage", return_value=Mock()), \
                        patch.object(cs_mod, "create_directory", side_effect=lambda p: p.mkdir(mode=0o700)):
                    owner = CoreSupervisor(sroot, core_dir, authorized=True)
                    self.addCleanup(owner.close)
                    owner.process = Mock()
                    owner.process.pid = 23456
                    owner.process.poll.return_value = None
                    owner.journal.append("STARTING")
                    owner.journal.append("RUNNING", owner.process.pid)
                    owner.binding = Mock()
                    owner.read = Mock()

                    with patch.object(cs_mod, "_read_cli") as cli_mock, \
                            patch.object(cs_mod, "unregister") as unreg_mock:
                        if fail_stage == "STOPPING":
                            with patch.object(store, failure_target, side_effect=OSError(errno.EIO, "stop-journal-fail")):
                                with self.assertRaises(Exception):
                                    owner.shutdown()
                            cli_mock.assert_not_called()
                            unreg_mock.assert_not_called()
                            self.assertIsNotNone(owner.process)
                            self.assertIsNotNone(store.held_lease(sroot))
                        else:
                            owner.process.wait.return_value = 0
                            with patch.object(store, failure_target, side_effect=OSError(errno.EIO, "clean-journal-fail")):
                                with self.assertRaises(Exception):
                                    owner.shutdown()
                            unreg_mock.assert_not_called()
                            self.assertIsNotNone(owner.process)
                            self.assertIsNotNone(store.held_lease(sroot))
                    owner.process = None

        # Exception 3(b): quit_ack_unrecorded documented escape hatch
        qroot = self.root / "wam-fusion-core-3333333333333333"
        qroot.mkdir(mode=0o700)
        backend = ManagedWalletBackend(qroot, self.root / "core", SOURCE)
        owner = Mock()
        owner.root = qroot
        owner.directory = qroot / "chain"
        owner.directory.mkdir(mode=0o700)
        owner.profile = {"profile_id": PROFILE_ID}
        owner.journal = SimpleNamespace(events=[{"seq": 1, "state": "RUNNING"}])
        owner.process = Mock()
        owner.process.poll.return_value = None
        owner._faulted = True
        owner.recover_stop.side_effect = ValueError("CORE_RPC_PROCESS_IDENTITY_DENIED")
        backend.owner = owner
        session = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
        session.lock.side_effect = WalletSessionError("WALLET_MANAGED_RUNTIME_PRESERVED")
        backend.session = session
        executor = WalletExecutor(lambda: backend)
        self.addCleanup(lambda: (executor.request("quit") if not executor.closed else None, executor.join(5)))
        executor.request("core_status", timeout=5)

        with store.exclusive_lease(qroot), \
                patch("wam_regtest.rpc_scope.identity", return_value=SimpleNamespace(faulted=False)), \
                patch("wam_regtest.quit_notice.publish_notice", side_effect=OSError(errno.EIO, "notice-flush-fail")):
            with self.assertRaisesRegex(WalletExecutorError, "^NOTICE_PERSIST_FAILED$"):
                executor.request("quit", timeout=5)
        self.assertTrue(backend._notice_persist_failed)
        with self.assertRaisesRegex(WalletExecutorError, "^NOTICE_PERSIST_FAILED$"):
            executor.request("control", "release", timeout=5)
        with self.assertRaisesRegex(WalletExecutorError, "^MANAGED_LIVE_OWNER_CLOSE_DENIED$"):
            executor.request("quit_ack_unrecorded", acknowledged=True, timeout=5)
        owner.release.assert_not_called()
        owner.process = None
        with self.assertRaisesRegex(WalletExecutorError, "^QUIT_ACK_UNRECORDED_ARGUMENTS_DENIED$"):
            executor.request("quit_ack_unrecorded", acknowledged=False, timeout=5)
        res = executor.request("quit_ack_unrecorded", acknowledged=True, timeout=5)
        self.assertTrue(res["unrecorded_acknowledged"])
        owner.release.assert_called_once_with()
        owner.close.assert_called_once_with()


@unittest.skipUnless(DARWIN, "macOS darwin helper-call counts and latency evidence")
class HelperCallCountsAndLatencyEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wam-dur01a-counts-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    @staticmethod
    @contextmanager
    def _meter():
        from wam_regtest import (
            core, custody, encrypted_storage, fullflush, quit_notice,
            shared_regtest, supervisor_store as store, vault,
        )
        from wam_regtest.domain import backup_ack
        import fcntl

        counts = {
            "full_flush": 0,
            "flush_directory": 0,
            "flush_after_mkdir": 0,
            "syscall_fsync": 0,
            "syscall_f_fullfsync": 0,
        }
        real_ff = fullflush.full_flush
        real_fd = fullflush.flush_directory
        real_am = fullflush.flush_after_mkdir
        real_fsync = os.fsync
        real_fcntl = fcntl.fcntl
        f_fullfsync_code = getattr(fcntl, "F_FULLFSYNC", 51)
        depth = [0]

        def wrap_ff(fd):
            if depth[0] == 0:
                counts["full_flush"] += 1
            depth[0] += 1
            try:
                return real_ff(fd)
            finally:
                depth[0] -= 1

        def wrap_fd(dfd):
            counts["flush_directory"] += 1
            depth[0] += 1
            try:
                return real_fd(dfd)
            finally:
                depth[0] -= 1

        def wrap_am(pfd):
            counts["flush_after_mkdir"] += 1
            depth[0] += 1
            try:
                return real_am(pfd)
            finally:
                depth[0] -= 1

        def wrap_fsync(fd):
            counts["syscall_fsync"] += 1
            return real_fsync(fd)

        def wrap_fcntl(fd, cmd, *args):
            if cmd == f_fullfsync_code:
                counts["syscall_f_fullfsync"] += 1
            return real_fcntl(fd, cmd, *args)

        with ExitStack() as stack:
            for mod, attr in (
                (fullflush, "full_flush"),
                (encrypted_storage, "full_flush"),
                (store, "full_flush"),
                (quit_notice, "full_flush"),
                (core, "full_flush"),
                (shared_regtest, "full_flush"),
            ):
                stack.enter_context(patch.object(mod, attr, wrap_ff))
            for mod, attr in (
                (fullflush, "flush_directory"),
                (encrypted_storage, "flush_directory"),
                (store, "flush_directory"),
                (quit_notice, "flush_directory"),
            ):
                stack.enter_context(patch.object(mod, attr, wrap_fd))
            for mod, attr in (
                (fullflush, "flush_after_mkdir"),
                (store, "flush_after_mkdir"),
            ):
                stack.enter_context(patch.object(mod, attr, wrap_am))
            stack.enter_context(patch.object(os, "fsync", wrap_fsync))
            stack.enter_context(patch.object(fcntl, "fcntl", wrap_fcntl))
            yield counts

    @staticmethod
    def _latency_stats(samples_ms):
        ordered = sorted(samples_ms)
        n = len(ordered)
        def pct(p):
            idx = min(n - 1, int(p * (n - 1)))
            return round(ordered[idx], 3)
        return {"n": n, "p50_ms": pct(0.50), "p95_ms": pct(0.95), "p99_ms": pct(0.99), "max_ms": round(ordered[-1], 3)}

    def test_deterministic_helper_call_counts_and_record_latency_evidence(self):
        from wam_regtest import (
            bip39_native_checkpoint, core, encrypted_storage, quit_notice,
            shared_regtest, supervisor_store as store, vault,
        )
        from wam_regtest.bip39_spend_session import Q06OwnedSpendSession
        from wam_regtest.domain import backup_ack
        from wam_regtest.supervisor_journal import LifecycleJournal
        from wam_regtest.vault import CheckpointVault, KeychainAnchor
        from wam_regtest.wallet_session import PaymentReview
        from wam_sp.keystore import Keyring
        from wam_sp.scanner import Scanner
        from wam_sp.wallet import Intent, Wallet

        keys = Keyring()
        keys.public_metadata = lambda: {"account_id": "0" * 64}
        recipient = Keyring()
        self.addCleanup(keys.close)
        self.addCleanup(recipient.close)
        chain, block = _chain_and_funding(keys)

        report = {}

        # 1. Sign + Broadcast (Q06OwnedSpendSession)
        sdir = self.root / "spend"
        sdir.mkdir(mode=0o700)
        scanner = Scanner(sdir / "sc.sqlite", keys.accounts())
        self.addCleanup(scanner.close)
        scanner.sync(chain)
        wallet = Wallet(scanner)
        intent = Intent(recipient.accounts()[0].payment_code(), 50_000)
        proposal = wallet.propose((intent,), 1000)
        vdir = sdir / "vault"
        vdir.mkdir(mode=0o700)
        anchor = KeychainAnchor("4" * 32)
        anchor_state = [None]

        def advance_unlocked(prev, curr):
            anchor_state[0] = curr

        with patch.object(anchor, "read", side_effect=lambda: anchor_state[0]), \
                patch.object(anchor, "lease", return_value=ExitStack()), \
                patch.object(anchor, "_advance_unlocked", side_effect=advance_unlocked):
            ckpt_vault = CheckpointVault(vdir, anchor, SOURCE)

            session = object.__new__(Q06OwnedSpendSession)
            session._lock = threading.RLock()
            session.vault = ckpt_vault
            session.scanner = scanner
            session.ring = keys
            session._password = PASSWORD
            session._tip = (1, block["hash"])
            session._rpc = lambda: chain
            session._require_fresh_fee_quote = lambda rpc: None
            session._managed_owner = None
            session._q06_owner = SimpleNamespace(directory=sdir)
            session._q06_guard = SimpleNamespace(check=lambda: None)
            session._q06_uncertain = False
            session.faulted = False
            session._signed = None
            from wam_sp.wallet import Signer
            session._prepared = Signer(keys).prepare(proposal)
            commitment = "ef" * 32
            session._review = PaymentReview(intent.code, 50_000, 1000, 49_000, 1, commitment)

            with patch("wam_regtest.bip39_spend_session._owned"), \
                    patch("wam_regtest.bip39_spend_session._owner_binding", return_value="binding"), \
                    patch.object(session, "_unchanged_inputs"), \
                    patch.object(session, "_preflight_not_submitted"), \
                    patch("wam_sp.wallet.Wallet.broadcast", return_value="11" * 32):
                with self._meter() as sign_counts:
                    t0 = time.perf_counter()
                    session.sign(commitment)
                    sign_ms = (time.perf_counter() - t0) * 1000.0
                self.assertEqual(
                    (sign_counts["full_flush"], sign_counts["flush_directory"], sign_counts["flush_after_mkdir"]),
                    (2, 2, 1),  # checkpoint + signed evidence + first evidence dir mkdir
                )
                report["sign_initial"] = {"counts": dict(sign_counts), "ms": round(sign_ms, 3)}

                with self._meter() as bcast_counts:
                    t0 = time.perf_counter()
                    session.broadcast(commitment)
                    bcast_ms = (time.perf_counter() - t0) * 1000.0
                self.assertEqual(
                    (bcast_counts["full_flush"], bcast_counts["flush_directory"], bcast_counts["flush_after_mkdir"]),
                    (4, 4, 0),  # uncertain evid + pre-RPC save + post-RPC save + broadcast evid
                )
                report["broadcast"] = {"counts": dict(bcast_counts), "ms": round(bcast_ms, 3)}

            # 2. Checkpoint steady-state (vault.save; repeated samples for latency evidence)
            ckpt_samples = []
            for idx in range(5):
                with self._meter() as ckpt_counts:
                    t0 = time.perf_counter()
                    ckpt_vault.save(keys, scanner, PASSWORD)
                    ckpt_samples.append((time.perf_counter() - t0) * 1000.0)
                self.assertEqual(
                    (ckpt_counts["full_flush"], ckpt_counts["flush_directory"], ckpt_counts["flush_after_mkdir"]),
                    (1, 1, 0),
                )
            report["checkpoint_vault_save"] = {"counts": dict(ckpt_counts), "latency": self._latency_stats(ckpt_samples)}

        # 3. Journal (LifecycleJournal initial CLEAN vs steady-state STOPPING/CLEAN)
        jroot = self.root / "wam-fusion-core-4444444444444444"
        jroot.mkdir(mode=0o700)
        jdir = jroot / "chain"
        jdir.mkdir(mode=0o700)
        with self._meter() as j_init_counts:
            journal = LifecycleJournal(jroot, {"profile_id": PROFILE_ID}, b"s" * 32, jdir, fresh=True)
        self.assertEqual(
            (j_init_counts["full_flush"], j_init_counts["flush_directory"], j_init_counts["flush_after_mkdir"]),
            (1, 1, 1),  # first create_once creates .wam-stage
        )
        report["journal_initial_clean"] = {"counts": dict(j_init_counts)}

        j_samples = []
        for st_name, pid in (("STARTING", None), ("RUNNING", 123), ("STOPPING", 123), ("CLEAN", None)):
            with self._meter() as j_counts:
                t0 = time.perf_counter()
                journal.append(st_name, pid)
                j_samples.append((time.perf_counter() - t0) * 1000.0)
            self.assertEqual(
                (j_counts["full_flush"], j_counts["flush_directory"], j_counts["flush_after_mkdir"]),
                (1, 1, 0),
            )
        report["journal_append_steady"] = {"counts": dict(j_counts), "latency": self._latency_stats(j_samples)}

        # 4. quit_notice.publish_notice
        qn_samples = []
        with store.exclusive_lease(jroot):
            for _ in range(5):
                with self._meter() as qn_counts:
                    t0 = time.perf_counter()
                    quit_notice.publish_notice(
                        jroot, profile_id=PROFILE_ID, session_kind="Q05",
                        wallet_outcome="RUNTIME_PRESERVED", core_stop="CLEAN",
                        codes=("WALLET_MANAGED_RUNTIME_PRESERVED",), journal_seq=2,
                    )
                    qn_samples.append((time.perf_counter() - t0) * 1000.0)
                self.assertEqual(
                    (qn_counts["full_flush"], qn_counts["flush_directory"], qn_counts["flush_after_mkdir"]),
                    (1, 2, 0),
                )
        report["quit_notice_publish"] = {"counts": dict(qn_counts), "latency": self._latency_stats(qn_samples)}

        # 5. Config writers
        cdir = self.root / "cfg-ev"
        cdir.mkdir(mode=0o700)
        with self._meter() as cfg_counts:
            t0 = time.perf_counter()
            core._write_private_config(cdir, 28600, 28601)
            cfg_ms = (time.perf_counter() - t0) * 1000.0
        self.assertEqual(
            (cfg_counts["full_flush"], cfg_counts["flush_directory"], cfg_counts["flush_after_mkdir"]),
            (1, 1, 0),
        )
        report["config_writer"] = {"counts": dict(cfg_counts), "ms": round(cfg_ms, 3)}

        s_cdir = self.root / "shared-cfg-ev"
        s_cdir.mkdir(mode=0o700)
        shared_profile = shared_regtest.SharedRegtestProfile(
            coordinator=True, bind_host="127.0.0.1", p2p_port=28610,
            rpc_port=28611, peer_host="127.0.0.1", peer_port=28612,
        )
        with self._meter() as scfg_counts:
            t0 = time.perf_counter()
            shared_regtest.write_config(s_cdir, shared_profile)
            scfg_ms = (time.perf_counter() - t0) * 1000.0
        self.assertEqual(
            (scfg_counts["full_flush"], scfg_counts["flush_directory"], scfg_counts["flush_after_mkdir"]),
            (1, 1, 0),
        )
        report["shared_config_writer"] = {"counts": dict(scfg_counts), "ms": round(scfg_ms, 3)}

        # 6. backup_ack initial + steady
        ack_root = self.root / "ack-ev"
        ack_root.mkdir(mode=0o700)
        with self._meter() as ack_init_counts:
            backup_ack._ack_write(ack_root, "bip39-12-" + "a" * 32 + ".json", b'{"v":1}')
        self.assertEqual(
            (ack_init_counts["full_flush"], ack_init_counts["flush_directory"], ack_init_counts["flush_after_mkdir"]),
            (1, 1, 2),
        )
        with self._meter() as ack_steady_counts:
            backup_ack._ack_write(ack_root, "bip39-12-" + "a" * 32 + ".json", b'{"v":2}')
        self.assertEqual(
            (ack_steady_counts["full_flush"], ack_steady_counts["flush_directory"], ack_steady_counts["flush_after_mkdir"]),
            (1, 1, 0),
        )
        report["backup_ack_initial"] = {"counts": dict(ack_init_counts)}
        report["backup_ack_steady"] = {"counts": dict(ack_steady_counts)}

        if os.environ.get("DUR01A_PRINT_EVIDENCE") == "1":
            print("DUR01A_EVIDENCE_JSON=" + json.dumps(report, sort_keys=True))


CHILD_PA = r"""
import os, sys, time
from pathlib import Path
from wam_regtest import encrypted_storage, fullflush
target, phase, marker = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
def hold():
    marker.write_text("ready")
    time.sleep(120)
real_ff = encrypted_storage.full_flush
real_link = encrypted_storage.os.link
real_unlink = encrypted_storage.os.unlink
def cut_ff(fd):
    if phase == "at-full-flush":
        hold()
    return real_ff(fd)
def cut_link(*a, **k):
    res = real_link(*a, **k)
    if phase == "after-link":
        hold()
    return res
def cut_unlink(*a, **k):
    res = real_unlink(*a, **k)
    if phase == "after-unlink":
        hold()
    return res
encrypted_storage.full_flush = cut_ff
encrypted_storage.os.link = cut_link
encrypted_storage.os.unlink = cut_unlink
encrypted_storage.publish(target, "item.enc", b"WAMSP02\x00" + b"x" * 64)
"""

CHILD_PB = r"""
import sys, time
from pathlib import Path
from wam_regtest import supervisor_store as store
root, phase, marker = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
def hold():
    marker.write_text("ready")
    time.sleep(120)
real_ff = store.full_flush
real_rename = store._rename_exclusive
def cut_ff(fd):
    if phase == "at-full-flush":
        hold()
    return real_ff(fd)
def cut_rename(*a):
    res = real_rename(*a)
    if phase == "after-rename":
        hold()
    return res
store.full_flush = cut_ff
store._rename_exclusive = cut_rename
store.create_once(root, "supervisor.token", b"t" * 32)
"""

CHILD_ACK = r"""
import sys, time
from pathlib import Path
from wam_regtest import fullflush
from wam_regtest.domain import backup_ack
root, name, phase, marker = Path(sys.argv[1]), sys.argv[2], sys.argv[3], Path(sys.argv[4])
def hold():
    marker.write_text("ready")
    time.sleep(120)
real_ff = fullflush.full_flush
real_rename = backup_ack.os.rename
def cut_ff(fd):
    if phase == "at-full-flush":
        hold()
    return real_ff(fd)
def cut_rename(*a, **k):
    res = real_rename(*a, **k)
    if phase == "after-rename":
        hold()
    return res
fullflush.full_flush = cut_ff
backup_ack.os.rename = cut_rename
backup_ack._ack_write(root, name, b'{"new":true}')
"""

CHILD_NOTICE = r"""
import sys, time
from pathlib import Path
from wam_regtest import quit_notice
from wam_regtest.supervisor_store import exclusive_lease
root, phase, marker = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
def hold():
    marker.write_text("ready")
    time.sleep(120)
real_ff = quit_notice.full_flush
real_link = quit_notice.os.link
real_unlink = quit_notice.os.unlink
def cut_ff(fd):
    if phase == "at-full-flush":
        hold()
    return real_ff(fd)
def cut_link(*a, **k):
    res = real_link(*a, **k)
    if phase == "after-link":
        hold()
    return res
def cut_unlink(*a, **k):
    res = real_unlink(*a, **k)
    if phase == "after-unlink":
        hold()
    return res
quit_notice.full_flush = cut_ff
quit_notice.os.link = cut_link
quit_notice.os.unlink = cut_unlink
with exclusive_lease(root):
    quit_notice.publish_notice(
        root, profile_id="a" * 32, session_kind="Q05",
        wallet_outcome="RUNTIME_PRESERVED", core_stop="CLEAN",
        codes=("WALLET_MANAGED_RUNTIME_PRESERVED",), journal_seq=1,
    )
"""


@unittest.skipUnless(DARWIN, "macOS darwin child-process kill and error matrix")
class RealChildProcessKillAndErrorMatrix(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wam-dur01a-kill-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def _run_and_sigkill(self, script, *args):
        marker = self.base / f"marker-{secrets.token_hex(4)}"
        env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONDONTWRITEBYTECODE="1")
        child = subprocess.Popen(
            [sys.executable, "-c", script, *args, str(marker)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 30
            while not marker.exists():
                self.assertIsNone(child.poll(), child.stderr.read() if child.poll() is not None else b"")
                self.assertLess(time.monotonic(), deadline, "child never reached cut")
                time.sleep(0.02)
            os.kill(child.pid, signal.SIGKILL)
        finally:
            child.wait(timeout=30)
            child.stderr.close()
        self.assertEqual(child.returncode, -signal.SIGKILL)

    def test_real_child_sigkill_cuts_pa_pb_backup_ack_and_quit_notice(self):
        from wam_regtest import encrypted_storage, quit_notice, supervisor_store as store
        from wam_regtest.domain import backup_ack

        # P-A cuts
        pa1 = self.base / "pa1"
        pa1.mkdir(mode=0o700)
        self._run_and_sigkill(CHILD_PA, str(pa1), "at-full-flush")
        self.assertFalse((pa1 / "item.enc").exists())
        pa2 = self.base / "pa2"
        pa2.mkdir(mode=0o700)
        self._run_and_sigkill(CHILD_PA, str(pa2), "after-link")
        self.assertEqual((pa2 / "item.enc").read_bytes(), b"WAMSP02\x00" + b"x" * 64)
        self.assertEqual((pa2 / "item.enc").lstat().st_nlink, 2)
        pa3 = self.base / "pa3"
        pa3.mkdir(mode=0o700)
        self._run_and_sigkill(CHILD_PA, str(pa3), "after-unlink")
        self.assertEqual(encrypted_storage.read(pa3, "item.enc"), b"WAMSP02\x00" + b"x" * 64)

        # P-B cuts at full_flush and after-rename-before-dir-flush
        pb = self.base / "wam-fusion-core-5555555555555555"
        pb.mkdir(mode=0o700)
        self._run_and_sigkill(CHILD_PB, str(pb), "at-full-flush")
        self.assertFalse((pb / "supervisor.token").exists())
        residue = list((pb / store.STAGE_DIRECTORY).iterdir())
        self.assertEqual(len(residue), 1)
        self.assertEqual(residue[0].read_bytes(), b"t" * 32)
        pb2 = self.base / "wam-fusion-core-5555555555555556"
        pb2.mkdir(mode=0o700)
        self._run_and_sigkill(CHILD_PB, str(pb2), "after-rename")
        self.assertEqual(store.read_exact(pb2, "supervisor.token"), b"t" * 32)
        self.assertEqual(list((pb2 / store.STAGE_DIRECTORY).iterdir()), [])

        # backup_ack cuts
        ack_root = self.base / "ack-kill"
        ack_root.mkdir(mode=0o700)
        ack_name = "bip39-12-" + "a" * 32 + ".json"
        backup_ack._ack_write(ack_root, ack_name, b'{"old":true}')
        self._run_and_sigkill(CHILD_ACK, str(ack_root), ack_name, "at-full-flush")
        self.assertEqual(backup_ack._ack_read(backup_ack.ack_dir(ack_root), ack_name), b'{"old":true}')
        self._run_and_sigkill(CHILD_ACK, str(ack_root), ack_name, "after-rename")
        self.assertEqual(backup_ack._ack_read(backup_ack.ack_dir(ack_root), ack_name), b'{"new":true}')

        # quit_notice cuts
        qn1 = self.base / "wam-fusion-core-6666666666666666"
        qn1.mkdir(mode=0o700)
        self._run_and_sigkill(CHILD_NOTICE, str(qn1), "at-full-flush")
        self.assertFalse((qn1 / "supervisor.notice.000001").exists())
        qn2 = self.base / "wam-fusion-core-7777777777777777"
        qn2.mkdir(mode=0o700)
        self._run_and_sigkill(CHILD_NOTICE, str(qn2), "after-link")
        with store.exclusive_lease(qn2):
            items = quit_notice.unacknowledged(qn2, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["seq"], 1)
        qn3 = self.base / "wam-fusion-core-8888888888888888"
        qn3.mkdir(mode=0o700)
        self._run_and_sigkill(CHILD_NOTICE, str(qn3), "after-unlink")
        with store.exclusive_lease(qn3):
            items3 = quit_notice.unacknowledged(qn3, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items3), 1)
        self.assertEqual(items3[0]["seq"], 1)

    def test_error_matrix_and_primary_error_preservation(self):
        from wam_regtest import encrypted_storage, fullflush
        from wam_regtest.domain import backup_ack

        # P-A error matrix + primary error preserved when cleanup fails
        pa = self.base / "pa-err"
        pa.mkdir(mode=0o700)
        envelope = b"WAMSP02\x00" + bytes(64)

        for label, target, attr, effect in (
            ("enospc", encrypted_storage.os, "write", OSError(errno.ENOSPC, "full")),
            ("zero-write", encrypted_storage.os, "write", 0),
            ("eintr", encrypted_storage.os, "write", InterruptedError(errno.EINTR, "eintr")),
            ("eio-full-flush", encrypted_storage, "full_flush", OSError(errno.EIO, "eio")),
            ("enotty-full-flush", encrypted_storage, "full_flush", OSError(errno.ENOTTY, "enotty")),
            ("failed-link", encrypted_storage.os, "link", OSError(errno.EIO, "link-fail")),
        ):
            with self.subTest(pa_case=label):
                kwargs = {"return_value": effect} if type(effect) is int else {"side_effect": effect}
                with patch.object(target, attr, **kwargs):
                    with self.assertRaisesRegex(encrypted_storage.EncryptedStorageError, "ENCRYPTED_STORAGE_PUBLISH_DENIED"):
                        encrypted_storage.publish(pa, "x.enc", envelope)
                self.assertFalse((pa / "x.enc").exists())

        # Positive short write completes in P-A
        real_write = os.write
        with patch.object(encrypted_storage.os, "write", lambda fd, data: real_write(fd, bytes(data[:7]))):
            encrypted_storage.publish(pa, "short-ok.enc", envelope)
        self.assertEqual(encrypted_storage.read(pa, "short-ok.enc"), envelope)

        # Post-link flush_directory / unlink error in P-A still fails closed with final present
        with patch.object(encrypted_storage, "flush_directory", side_effect=OSError(errno.EIO, "dir-eio")):
            with self.assertRaisesRegex(encrypted_storage.EncryptedStorageError, "ENCRYPTED_STORAGE_PUBLISH_DENIED"):
                encrypted_storage.publish(pa, "post-link-err.enc", envelope)
        self.assertEqual(encrypted_storage.read(pa, "post-link-err.enc"), envelope)

        # P-A primary typed error preserved when cleanup unlink also fails
        with patch.object(encrypted_storage, "full_flush", side_effect=OSError(errno.EIO, "primary-pa")), \
                patch.object(encrypted_storage.os, "unlink", side_effect=OSError(errno.EPERM, "cleanup-unlink")):
            with self.assertRaisesRegex(encrypted_storage.EncryptedStorageError, "ENCRYPTED_STORAGE_PUBLISH_DENIED"):
                encrypted_storage.publish(pa, "cleanup-fail.enc", envelope)
        self.assertFalse((pa / "cleanup-fail.enc").exists())

        # backup_ack primary error preserved when cleanup unlink also fails
        ack_root = self.base / "ack-err"
        ack_root.mkdir(mode=0o700)
        ack_name = "bip39-12-" + "b" * 32 + ".json"
        with patch.object(fullflush, "full_flush", side_effect=OSError(errno.EIO, "primary-ack-flush")), \
                patch.object(backup_ack.os, "unlink", side_effect=OSError(errno.EPERM, "cleanup-unlink-fail")):
            with self.assertRaises(OSError) as ctx:
                backup_ack._ack_write(ack_root, ack_name, b'{"v":1}')
            self.assertEqual(ctx.exception.errno, errno.EIO)


if __name__ == "__main__":
    unittest.main()
