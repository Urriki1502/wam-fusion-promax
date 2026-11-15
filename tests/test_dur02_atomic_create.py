"""DUR-02: macOS create_once publishes atomically via renameatx_np(RENAME_EXCL).

Contract: evidence/DUR-01-durability/CONTRACT-DOSSIER.md Rev 4 + Rev 5 and
RECHECK2-DUR02-codex.md N1-N3 and the R1 implementation constraint. Disposable
temporary roots only; no Core, wallet, key or profile. Durability (power loss,
F_FULLFSYNC) is NOT tested or claimed here.
"""
from contextlib import contextmanager, ExitStack
import ctypes
import errno
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

from wam_regtest import supervisor_store as store
from wam_regtest.supervisor_store import (
    MAX_STAGE_RESIDUE, STAGE_DIRECTORY, SupervisorStorageError, create_once,
    exclusive_lease, read_exact, stage_namespace,
)

DATA = b"d" * 32
NAME = "supervisor.token"
ROOT_NAME = "wam-fusion-core-1234567890abcdef"
SRC = Path(__file__).resolve().parents[1] / "src"
DARWIN = sys.platform == "darwin"


class Cut(BaseException):
    """A process-death stand-in that no storage handler may swallow."""


def _user():
    return pwd.getpwuid(os.geteuid()).pw_name


def _add_acl(path):
    subprocess.run(["/bin/chmod", "+a", _user() + " allow read", str(path)],
                   check=True, capture_output=True)


@unittest.skipUnless(DARWIN, "DUR-02 publication is Darwin-only; Linux/Windows have their own tests below")
class DarwinPublication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wam-dur02-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / ROOT_NAME
        self.root.mkdir(mode=0o700)
        self.stage = self.root / STAGE_DIRECTORY

    def residue(self):
        return sorted(p.name for p in self.stage.iterdir()) if self.stage.exists() else []

    def stage_name(self):
        names = self.residue()
        self.assertEqual(len(names), 1)
        return names[0]

    # --- positive and create-once -------------------------------------------

    def test_publication_is_complete_private_and_leaves_no_stage(self):
        create_once(self.root, NAME, DATA)
        self.assertEqual(read_exact(self.root, NAME, length=32), DATA)
        info = os.stat(self.root / NAME, follow_symlinks=False)
        self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink), (0o600, 1))
        self.assertEqual(stat.S_IMODE(os.stat(self.stage).st_mode), 0o700)
        self.assertEqual(self.residue(), [])
        self.assertEqual(stage_namespace(self.root), "empty")

    def test_duplicate_refuses_with_create_denied_and_leaves_no_residue(self):
        create_once(self.root, NAME, DATA)
        for data in (DATA, b"e" * 32):  # equal bytes are NOT idempotent success
            with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_CREATE_DENIED"):
                create_once(self.root, NAME, data)
        self.assertEqual(read_exact(self.root, NAME), DATA)
        self.assertEqual(self.residue(), [])

    def test_rename_eexist_race_refuses_and_retains_the_stage_residue(self):
        real_fsync = os.fsync
        calls = []

        def racer(fd):
            real_fsync(fd)
            if not calls:  # the stage-file fsync: a competitor publishes first
                calls.append(fd)
                (self.root / NAME).write_bytes(b"r" * 32)
                os.chmod(self.root / NAME, 0o600)

        with patch.object(os, "fsync", racer):
            with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_CREATE_DENIED"):
                create_once(self.root, NAME, DATA)
        self.assertEqual((self.root / NAME).read_bytes(), b"r" * 32)
        self.assertEqual((self.stage / self.stage_name()).read_bytes(), DATA)

    # --- cut points (BaseException) -----------------------------------------

    def assert_no_final(self):
        self.assertFalse(os.path.lexists(self.root / NAME))
        with self.assertRaises(SupervisorStorageError):
            read_exact(self.root, NAME)

    def test_cut_at_stage_create_leaves_no_final_and_no_stage_file(self):
        real = store._posix_file

        def cut(fd, name, **kwargs):
            if kwargs.get("create"):
                raise Cut()
            return real(fd, name, **kwargs)

        with patch.object(store, "_posix_file", cut), self.assertRaises(Cut):
            create_once(self.root, NAME, DATA)
        self.assert_no_final()
        self.assertEqual(self.residue(), [])

    def test_cut_during_partial_write_leaves_partial_residue_only(self):
        real = os.write
        calls = []

        def partial(fd, data):
            calls.append(fd)
            if len(calls) == 1:
                return real(fd, bytes(data[:7]))
            raise Cut()

        with patch.object(os, "write", partial), self.assertRaises(Cut):
            create_once(self.root, NAME, DATA)
        self.assert_no_final()
        self.assertEqual((self.stage / self.stage_name()).read_bytes(), DATA[:7])

    def test_cut_at_stage_fsync_and_before_rename_never_publish(self):
        for target, attribute in ((os, "fsync"), (store, "_rename_exclusive")):
            with self.subTest(cut=attribute):
                with patch.object(target, attribute, Mock(side_effect=Cut())), self.assertRaises(Cut):
                    create_once(self.root, NAME, DATA)
                self.assert_no_final()
                self.assertEqual((self.stage / self.residue()[-1]).read_bytes()[:7], DATA[:7])
        self.assertEqual(len(self.residue()), 2)  # both retained, never deleted

    def test_cut_after_rename_before_root_fsync_leaves_the_complete_final(self):
        real = store._rename_exclusive

        def cut(*args):
            real(*args)
            raise Cut()

        with patch.object(store, "_rename_exclusive", cut), self.assertRaises(Cut):
            create_once(self.root, NAME, DATA)
        self.assertEqual(read_exact(self.root, NAME, length=32), DATA)
        self.assertEqual(self.residue(), [])

    # --- N3: pre- vs post-publication errors -------------------------------

    def test_root_fsync_and_close_errors_after_rename_raise_with_final_present(self):
        real_fsync = os.fsync
        calls = []

        def failing_fsync(fd):
            calls.append(fd)
            if len(calls) == 2:  # 1 = stage file, 2 = final root directory
                raise OSError(errno.EIO, "injected")
            return real_fsync(fd)

        with patch.object(os, "fsync", failing_fsync):
            with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_CREATE_UNVERIFIED"):
                create_once(self.root, NAME, DATA)
        self.assertEqual(len(calls), 2)
        self.assertEqual(read_exact(self.root, NAME, length=32), DATA)  # not removed
        with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_CREATE_DENIED"):
            create_once(self.root, NAME, DATA)  # retry still errors

        # Close failure on the final root directory after rename + fsync also raises and retains final.
        real_close = os.close
        root_fds = set()

        def track_fsync(fd):
            real_fsync(fd)
            if len(calls) == 1:
                root_fds.add(fd)
            calls.append(fd)

        def failing_root_close(fd):
            real_close(fd)
            if fd in root_fds:
                raise OSError(errno.EIO, "close-injected")

        calls.clear()
        with patch.object(os, "fsync", track_fsync), patch.object(os, "close", failing_root_close):
            with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_CREATE_UNVERIFIED"):
                create_once(self.root, "supervisor.profile", DATA)
        self.assertEqual(read_exact(self.root, "supervisor.profile", length=32), DATA)
        with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_CREATE_DENIED"):
            create_once(self.root, "supervisor.profile", DATA)

    def test_primary_failure_is_preserved_when_cleanup_close_also_fails(self):
        real_close = os.close
        seen = []

        def failing_close(fd):
            real_close(fd)
            if seen and fd in (seen[0][0], seen[0][2]):
                raise OSError(errno.EIO, "cleanup-close")

        with patch.object(store, "_renameatx_np", self.fake_binding(-1, errno.EIO, seen)):
            with patch.object(os, "close", failing_close):
                with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_RENAME_DENIED"):
                    create_once(self.root, NAME, DATA)
        self.assert_no_final()

    def test_prepublication_io_errors_raise_and_never_publish(self):
        cases = (
            ("enospc-write", os, "write", OSError(errno.ENOSPC, "x")),
            ("eintr-write", os, "write", InterruptedError(errno.EINTR, "x")),
            ("eio-stage-fsync", os, "fsync", OSError(errno.EIO, "x")),
        )
        for label, target, attribute, error in cases:
            with self.subTest(label):
                with patch.object(target, attribute, Mock(side_effect=error)):
                    with self.assertRaises(SupervisorStorageError):
                        create_once(self.root, NAME, DATA)
                self.assert_no_final()

    def test_zero_write_refuses_and_short_writes_complete(self):
        with patch.object(os, "write", Mock(return_value=0)):
            with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_WRITE_DENIED"):
                create_once(self.root, NAME, DATA)
        self.assert_no_final()
        real = os.write
        with patch.object(os, "write", lambda fd, data: real(fd, bytes(data[:5]))):
            create_once(self.root, NAME, DATA)
        self.assertEqual(read_exact(self.root, NAME), DATA)

    # --- N1: frozen ABI, errno and no fallback ------------------------------

    def test_binding_has_the_frozen_abi(self):
        function = store._renameatx_np()
        self.assertEqual(function.argtypes, [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                                             ctypes.c_char_p, ctypes.c_uint])
        self.assertIs(function.restype, ctypes.c_int)
        self.assertEqual(store._RENAME_EXCL, 0x4)

    def fake_binding(self, result, code, seen):
        def call(*args):
            seen.append(args)
            ctypes.set_errno(code)
            return result
        return lambda: call

    @contextmanager
    def no_fallback(self):
        with ExitStack() as stack:
            for name in ("rename", "replace", "link"):
                stack.enter_context(patch.object(os, name, Mock(side_effect=AssertionError(name))))
            yield

    def test_failing_rename_maps_errno_to_fixed_errors_without_fallback(self):
        cases = ((-1, errno.EEXIST, "SUPERVISOR_STORAGE_CREATE_DENIED"),
                 (-1, errno.ENOTSUP, "SUPERVISOR_STORAGE_RENAME_DENIED"),
                 (-1, errno.EINVAL, "SUPERVISOR_STORAGE_RENAME_DENIED"),
                 (-1, errno.EXDEV, "SUPERVISOR_STORAGE_RENAME_DENIED"),
                 (-1, errno.EIO, "SUPERVISOR_STORAGE_RENAME_DENIED"),
                 (1, 0, "SUPERVISOR_STORAGE_RENAME_DENIED"))
        for result, code, expected in cases:
            with self.subTest(result=result, errno=code):
                seen = []
                with patch.object(store, "_renameatx_np", self.fake_binding(result, code, seen)), \
                        self.no_fallback():
                    with self.assertRaisesRegex(SupervisorStorageError, expected):
                        create_once(self.root, NAME, DATA)
                self.assert_no_final()
                stage_fd, source, root_fd, target, flags = seen[0]
                self.assertTrue(type(stage_fd) is int and type(root_fd) is int and stage_fd != root_fd)
                self.assertRegex(source, rb"\A[0-9a-f]{16}\.tmp\Z")
                self.assertEqual((target, flags), (NAME.encode(), 0x4))

    def test_missing_symbol_or_library_refuses_without_fallback(self):
        real_cdll = ctypes.CDLL
        for missing in (lambda *a, **kw: object(), Mock(side_effect=OSError("no libc"))):
            def cdll(name, *args, **kwargs):
                if name is None:
                    return missing(name, *args, **kwargs)
                return real_cdll(name, *args, **kwargs)
            with self.subTest(missing=missing), patch.object(ctypes, "CDLL", cdll), self.no_fallback():
                with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_RENAME_UNAVAILABLE"):
                    create_once(self.root, NAME, DATA)
            self.assert_no_final()

    def test_operands_are_single_relative_components(self):
        for bad in ("", ".", "..", "/abs", "a/b", "a\0b", "é"):
            with self.subTest(bad=bad), self.assertRaises(SupervisorStorageError):
                store._component(bad)
        for bad in ("../x.tmp", "0123456789abcdef", "0123456789ABCDEF.tmp", "supervisor.token"):
            with self.subTest(stage=bad), self.assertRaises(SupervisorStorageError):
                store._stage_name(bad)
        with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_NAME_DENIED"):
            store._rename_exclusive(3, "0123456789abcdef.tmp", 4, "../evil")
        with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_CREATE_DENIED"):
            store._rename_exclusive(3, "0123456789abcdef.tmp", 4, "supervisor.lock")
        for bad_pair in ((-1, 4), (3, -1), (3, 3), ("3", 4)):
            with self.subTest(fds=bad_pair):
                with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_RENAME_DENIED"):
                    store._rename_exclusive(bad_pair[0], "0123456789abcdef.tmp", bad_pair[1], NAME)

    # --- residue bound ------------------------------------------------------

    def test_residue_bound_counts_every_entry_and_includes_the_pending_stage(self):
        self.stage.mkdir(mode=0o700)
        (self.stage / "sub").mkdir()
        os.symlink("/nonexistent", self.stage / "link")
        for index in range(MAX_STAGE_RESIDUE - 3):
            (self.stage / ("x%02d" % index)).write_bytes(b"")
        self.assertEqual(len(self.residue()), MAX_STAGE_RESIDUE - 1)
        create_once(self.root, NAME, DATA)  # 63 retained + 1 pending = 64: allowed
        (self.stage / "last").write_bytes(b"")
        self.assertEqual(len(self.residue()), MAX_STAGE_RESIDUE)
        with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_STAGE_RESIDUE_LIMIT"):
            create_once(self.root, "supervisor.profile", DATA)
        self.assertFalse(os.path.lexists(self.root / "supervisor.profile"))
        self.assertEqual(len(self.residue()), MAX_STAGE_RESIDUE)  # nothing deleted

    # --- N2: malicious stage directory --------------------------------------

    def assert_stage_refused(self):
        with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_STAGE_UNTRUSTED"):
            create_once(self.root, NAME, DATA)
        self.assert_no_final()

    def test_stage_directory_type_symlink_mode_and_acl_are_refused_without_repair(self):
        self.stage.write_bytes(b"keep")
        self.assert_stage_refused()
        self.assertEqual(self.stage.read_bytes(), b"keep")
        self.stage.unlink()
        target = self.root.parent / "elsewhere"
        target.mkdir(mode=0o700)
        self.stage.symlink_to(target)
        self.assert_stage_refused()
        self.assertEqual(list(target.iterdir()), [])
        self.stage.unlink()
        self.stage.mkdir(mode=0o700)
        os.chmod(self.stage, 0o755)
        self.assert_stage_refused()
        self.assertEqual(stat.S_IMODE(os.stat(self.stage).st_mode), 0o755)  # not repaired
        os.chmod(self.stage, 0o700)
        _add_acl(self.stage)
        self.assert_stage_refused()

    def test_stage_directory_owner_refusal_from_the_native_validator(self):
        from wam_regtest import private_directory
        self.stage.mkdir(mode=0o700)
        stage_inode = os.stat(self.stage).st_ino
        real = private_directory.validate_macos_private_directory

        def foreign_owner(fd):
            if os.fstat(fd).st_ino == stage_inode:
                raise private_directory.MacosPrivateDirectoryError("MACOS_PRIVATE_DIRECTORY_METADATA_DENIED")
            return real(fd)

        with patch.object(private_directory, "validate_macos_private_directory", foreign_owner):
            self.assert_stage_refused()

    # --- N2: staged-inode binding and replacement races ---------------------

    def race_at_stage_fsync(self, action):
        real = os.fsync
        calls = []

        def racing(fd):
            real(fd)
            if not calls:
                calls.append(fd)
                action(self.stage / self.stage_name())

        with patch.object(os, "fsync", racing):
            with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_STAGE_CHANGED"):
                create_once(self.root, NAME, DATA)
        self.assert_no_final()

    def test_replaced_stage_file_is_refused_and_both_entries_retained(self):
        def replace(path):
            os.rename(path, path.with_name("moved"))
            path.write_bytes(b"attacker")
            os.chmod(path, 0o600)
        self.race_at_stage_fsync(replace)
        self.assertEqual(sorted(self.residue())[-1], "moved")
        self.assertEqual(len(self.residue()), 2)

    def test_stage_symlink_hardlink_mode_size_and_acl_are_refused(self):
        def symlink(path):
            os.rename(path, path.with_name("moved-s"))
            os.symlink(path.with_name("moved-s"), path)

        def hardlink(path):
            os.link(path, path.with_name("second-link"))

        def bad_mode(path):
            os.chmod(path, 0o644)

        def bad_size(path):
            with open(path, "ab") as f:
                f.write(b"x")

        for action in (symlink, hardlink, bad_mode, bad_size, _add_acl):
            with self.subTest(action=getattr(action, "__name__", "acl")):
                self.race_at_stage_fsync(action)
                for entry in list(self.stage.iterdir()):  # test-owned fixture reset only
                    entry.unlink()

    def test_replaced_stage_directory_is_refused(self):
        def swap(_path):
            os.rename(self.stage, self.root.parent / "old-stage")
            self.stage.mkdir(mode=0o700)
        self.race_at_stage_fsync(swap)
        self.assertEqual(len(list((self.root.parent / "old-stage").iterdir())), 1)

    def test_post_rename_identity_mismatch_raises_and_deletes_nothing(self):
        real = store._rename_exclusive

        def swap_final(*args):
            real(*args)
            os.rename(self.root / NAME, self.root.parent / "published")
            (self.root / NAME).write_bytes(b"other-bytes-of-length-thirty-two!"[:32])
            os.chmod(self.root / NAME, 0o600)

        with patch.object(store, "_rename_exclusive", swap_final):
            with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_PUBLISH_UNVERIFIED"):
                create_once(self.root, NAME, DATA)
        self.assertEqual((self.root.parent / "published").read_bytes(), DATA)
        self.assertTrue((self.root / NAME).exists())

    def test_post_rename_hardlink_and_acl_tamper_raise_unverified_without_deleting(self):
        real = store._rename_exclusive

        def link_final(*args):
            real(*args)
            os.link(self.root / NAME, self.root / "extra-link")

        with patch.object(store, "_rename_exclusive", link_final):
            with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_PUBLISH_UNVERIFIED"):
                create_once(self.root, NAME, DATA)
        self.assertTrue((self.root / NAME).exists())
        self.assertTrue((self.root / "extra-link").exists())
        (self.root / "extra-link").unlink()
        (self.root / NAME).unlink()

        def acl_final(*args):
            real(*args)
            _add_acl(self.root / NAME)

        with patch.object(store, "_rename_exclusive", acl_final):
            with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_PUBLISH_UNVERIFIED"):
                create_once(self.root, NAME, DATA)
        self.assertTrue((self.root / NAME).exists())

    # --- names, enumeration and lock unchanged ------------------------------

    def test_stage_entries_are_never_public_records_or_enumerated(self):
        create_once(self.root, "supervisor.event.000001", DATA)
        (self.stage / "0123456789abcdef.tmp").write_bytes(DATA)
        os.chmod(self.stage / "0123456789abcdef.tmp", 0o600)
        root_names = {p.name for p in self.root.iterdir()}
        self.assertEqual(root_names, {"supervisor.event.000001", STAGE_DIRECTORY})
        self.assertEqual([n for n in root_names if n.startswith("supervisor.event.")],
                         ["supervisor.event.000001"])
        self.assertFalse([n for n in root_names if n.startswith("supervisor.recovery.")])
        for name in (STAGE_DIRECTORY, "0123456789abcdef.tmp", STAGE_DIRECTORY + "/0123456789abcdef.tmp"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_NAME_DENIED"):
                    create_once(self.root, name, DATA)
                with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_NAME_DENIED"):
                    read_exact(self.root, name)
        with self.assertRaises(SupervisorStorageError):
            create_once(self.root, "supervisor.lock", DATA)
        with exclusive_lease(self.root):
            with self.assertRaises(SupervisorStorageError):
                with exclusive_lease(self.root):
                    pass
        self.assertEqual(stage_namespace(self.root), "occupied")

    def test_stage_namespace_never_creates_and_refuses_untrusted(self):
        self.assertEqual(stage_namespace(self.root), "absent")
        self.assertFalse(self.stage.exists())
        self.stage.symlink_to(self.root.parent)
        with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_STAGE_UNTRUSTED"):
            stage_namespace(self.root)


CHILD = r"""
import sys, time
from pathlib import Path
from wam_regtest import supervisor_store as store
root, phase, marker = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
real = store._rename_exclusive
def hold():
    marker.write_text("ready")
    time.sleep(120)
def cut(*args):
    if phase == "before-rename":
        hold()
    real(*args)
    if phase == "after-rename":
        hold()
store._rename_exclusive = cut
store.create_once(root, "supervisor.token", b"k" * 32)
"""


@unittest.skipUnless(DARWIN, "Darwin-only publication")
class RealProcessKill(unittest.TestCase):
    """A real disposable child process is SIGKILLed at each rename boundary."""

    def run_and_kill(self, phase):
        temp = tempfile.TemporaryDirectory(prefix="wam-dur02-kill-")
        self.addCleanup(temp.cleanup)
        base = Path(temp.name).resolve()
        root = base / ROOT_NAME
        root.mkdir(mode=0o700)
        marker = base / "marker"
        env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONDONTWRITEBYTECODE="1")
        child = subprocess.Popen([sys.executable, "-c", CHILD, str(root), phase, str(marker)],
                                 env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 30
            while not marker.exists():
                self.assertIsNone(child.poll(), child.stderr.read() if child.poll() is not None else b"")
                self.assertLess(time.monotonic(), deadline, "child never reached the cut")
                time.sleep(0.02)
            os.kill(child.pid, signal.SIGKILL)
        finally:
            child.wait(timeout=30)
            child.stderr.close()
        self.assertEqual(child.returncode, -signal.SIGKILL)
        return root

    def test_kill_before_rename_leaves_only_complete_stage_residue(self):
        root = self.run_and_kill("before-rename")
        self.assertFalse(os.path.lexists(root / "supervisor.token"))
        residue = list((root / STAGE_DIRECTORY).iterdir())
        self.assertEqual(len(residue), 1)
        self.assertEqual(residue[0].read_bytes(), b"k" * 32)

    def test_kill_after_rename_leaves_the_complete_final_only(self):
        root = self.run_and_kill("after-rename")
        self.assertEqual(read_exact(root, "supervisor.token", length=32), b"k" * 32)
        self.assertEqual(list((root / STAGE_DIRECTORY).iterdir()), [])


class OtherPlatformsUnchanged(unittest.TestCase):
    """Linux/Windows keep their exact previous branches and never touch the binding."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wam-dur02-platform-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / ROOT_NAME
        self.root.mkdir(mode=0o700)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("_renameatx_np", "_rename_exclusive", "_open_stage_directory", "_create_darwin"):
            self.stack.enter_context(patch.object(store, name, Mock(side_effect=AssertionError(name))))

    @unittest.skipUnless(DARWIN, "uses the native descriptor helper to stand in for Linux custody")
    def test_linux_branch_writes_the_final_directly_and_duplicates_still_error(self):
        from wam_regtest import linux_private_storage

        @contextmanager
        def directory(root):
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                yield fd
            finally:
                os.close(fd)

        self.stack.enter_context(patch.object(store.sys, "platform", "linux"))
        self.stack.enter_context(patch.object(store, "_posix_dir", directory))
        self.stack.enter_context(patch.object(linux_private_storage, "_no_acl", lambda fd: None))
        create_once(self.root, NAME, DATA)
        self.assertEqual((self.root / NAME).read_bytes(), DATA)
        self.assertFalse((self.root / STAGE_DIRECTORY).exists())
        with self.assertRaises(SupervisorStorageError):
            create_once(self.root, NAME, DATA)
        with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_NATIVE_STORE_REQUIRED"):
            stage_namespace(self.root)

    def test_windows_branch_uses_the_native_handle_path_only(self):
        written = []

        class Native:
            class w:
                DWORD = ctypes.c_ulong
            INVALID = object()

            @staticmethod
            def write(handle, buf, size, count, overlapped):
                written.append(buf.raw[:size])
                ctypes.cast(count, ctypes.POINTER(ctypes.c_ulong)).contents.value = size
                return True

            flush = staticmethod(lambda handle: True)
            close = staticmethod(lambda handle: None)

        guard = MagicMock()
        self.stack.enter_context(patch.object(store.sys, "platform", "win32"))
        self.stack.enter_context(patch.object(store, "_win_open", Mock(return_value=(Native, 7, guard))))
        create_once(self.root, NAME, DATA)
        self.assertEqual(b"".join(written), DATA)
        guard.__exit__.assert_called_once()
        self.assertFalse((self.root / STAGE_DIRECTORY).exists())

    def test_binding_refuses_off_darwin(self):
        self.stack.close()
        with patch.object(store.sys, "platform", "linux"):
            with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_NATIVE_STORE_REQUIRED"):
                store._renameatx_np()


@unittest.skipUnless(DARWIN, "R1 initialization tolerance is Darwin-only")
class SupervisorInitialization(unittest.TestCase):
    """R1: '.wam-stage' tolerated only when validated; the empty-root rule is not weakened."""

    def setUp(self):
        from wam_regtest import core_supervisor as module
        self.module = module
        self.temp = tempfile.TemporaryDirectory(prefix="wam-dur02-init-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "wam-fusion-core-0123456789abcdef"
        self.root.mkdir(mode=0o700)
        self.stage = self.root / STAGE_DIRECTORY
        self.core = self.root.parent / "core"
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(module, "verified_core_paths", return_value=(
            self.core / "wamd", self.core / "wam-cli",
            {"wamd_sha256": "a" * 64, "wam_cli_sha256": "b" * 64})))
        self.stack.enter_context(patch.object(module, "_metadata", return_value=("fixture-only",)))
        self.stack.enter_context(patch.object(module, "storage", return_value=Mock()))
        self.stack.enter_context(patch.object(module, "create_directory",
                                              side_effect=lambda p: p.mkdir(mode=0o700)))

    def owner(self):
        owner = self.module.CoreSupervisor(self.root, self.core, authorized=True)
        self.addCleanup(owner.close)
        return owner

    def names(self):
        return sorted(p.name for p in self.root.iterdir())

    def assert_partial_refused(self, before):
        with self.assertRaisesRegex(self.module.ManagedCoreError, "MANAGED_PROFILE_DENIED"):
            self.module.CoreSupervisor(self.root, self.core, authorized=True)
        self.assertEqual(self.names(), sorted(set(before) | {"supervisor.lock"}))
        self.assertFalse((self.root / "chain").exists())

    def test_existing_profile_reopens_with_retained_residue_unread_and_undeleted(self):
        self.owner().close()
        residue = self.stage / "0123456789abcdef.tmp"
        residue.write_bytes(b"residue")
        os.chmod(residue, 0o600)
        with patch.object(self.module, "read_exact", wraps=store.read_exact) as read_spy:
            reopened = self.owner()
        self.assertEqual(reopened.state, "stopped")
        self.assertEqual(residue.read_bytes(), b"residue")
        read_names = [call.args[1] for call in read_spy.call_args_list]
        self.assertNotIn("0123456789abcdef.tmp", read_names)
        self.assertNotIn(STAGE_DIRECTORY, read_names)

    def test_fresh_root_with_only_an_empty_validated_stage_initializes(self):
        self.stage.mkdir(mode=0o700)
        owner = self.owner()
        self.assertTrue((self.root / "supervisor.profile").exists())
        self.assertEqual(owner.journal.state, "CLEAN")

    def test_stage_only_namespace_with_any_child_is_partial_and_refused(self):
        for child in ("0123456789abcdef.tmp", "unknown-name", "subdir", "symlink"):
            with self.subTest(child=child):
                self.stage.mkdir(mode=0o700)
                path = self.stage / child
                if child == "subdir":
                    path.mkdir()
                elif child == "symlink":
                    os.symlink("/nonexistent", path)
                else:
                    path.write_bytes(b"keep")
                self.assert_partial_refused([STAGE_DIRECTORY])
                self.assertTrue(os.path.lexists(path))  # never deleted
                path.rmdir() if child == "subdir" else path.unlink()
                self.stage.rmdir()

    def test_partial_roots_still_refuse_with_or_without_an_empty_stage(self):
        # token-only and chain-only partial roots
        (self.root / "supervisor.token").write_bytes(b"t" * 32)
        os.chmod(self.root / "supervisor.token", 0o600)
        self.assert_partial_refused(["supervisor.token"])
        self.stage.mkdir(mode=0o700)
        self.assert_partial_refused(["supervisor.token", STAGE_DIRECTORY])
        (self.root / "supervisor.token").unlink()
        self.stage.rmdir()

        (self.root / "chain").mkdir(mode=0o700)
        with self.assertRaisesRegex(self.module.ManagedCoreError, "MANAGED_PROFILE_DENIED"):
            self.module.CoreSupervisor(self.root, self.core, authorized=True)
        self.assertFalse(self.stage.exists())
        self.stage.mkdir(mode=0o700)
        with self.assertRaisesRegex(self.module.ManagedCoreError, "MANAGED_PROFILE_DENIED"):
            self.module.CoreSupervisor(self.root, self.core, authorized=True)
        (self.root / "chain").rmdir()
        self.stage.rmdir()

        # profile-only partial root (valid profile bytes, missing token/chain/journal)
        owner = self.owner()
        profile_bytes = read_exact(self.root, "supervisor.profile")
        owner.close()
        for entry in list(self.root.iterdir()):
            if entry.is_dir():
                for child in sorted(entry.rglob("*"), reverse=True):
                    child.rmdir() if child.is_dir() else child.unlink()
                entry.rmdir()
            elif entry.name != "supervisor.profile":
                entry.unlink()
        with self.assertRaises((self.module.ManagedCoreError, OSError, ValueError)):
            self.module.CoreSupervisor(self.root, self.core, authorized=True)
        self.assertFalse(self.stage.exists())
        self.stage.mkdir(mode=0o700)
        with self.assertRaises((self.module.ManagedCoreError, OSError, ValueError)):
            self.module.CoreSupervisor(self.root, self.core, authorized=True)
        self.assertFalse((self.root / "chain").exists())
        self.assertEqual(read_exact(self.root, "supervisor.profile"), profile_bytes)

    def test_refused_init_never_creates_a_stage_directory(self):
        (self.root / "unknown").write_bytes(b"keep")
        self.assert_partial_refused(["unknown"])
        self.assertFalse(self.stage.exists())

    def test_untrusted_stage_directory_refuses_fresh_and_reopen(self):
        target = self.root.parent / "elsewhere"
        target.mkdir(mode=0o700)
        self.stage.symlink_to(target)
        with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_STAGE_UNTRUSTED"):
            self.module.CoreSupervisor(self.root, self.core, authorized=True)
        self.assertFalse((self.root / "chain").exists())
        self.stage.unlink()
        self.owner().close()
        os.chmod(self.stage, 0o755)
        with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_STAGE_UNTRUSTED"):
            self.module.CoreSupervisor(self.root, self.core, authorized=True)
        self.assertEqual(stat.S_IMODE(os.stat(self.stage).st_mode), 0o755)
        os.chmod(self.stage, 0o700)
        _add_acl(self.stage)
        with self.assertRaisesRegex(SupervisorStorageError, "SUPERVISOR_STORAGE_STAGE_UNTRUSTED"):
            self.module.CoreSupervisor(self.root, self.core, authorized=True)

    def test_tolerance_is_darwin_only(self):
        self.stage.mkdir(mode=0o700)
        with patch.object(self.module.sys, "platform", "linux"), \
                patch.object(self.module, "exclusive_lease", lambda root: ExitStack()), \
                patch.object(self.module, "stage_namespace", Mock(side_effect=AssertionError)):
            with self.assertRaisesRegex(self.module.ManagedCoreError, "MANAGED_PROFILE_DENIED"):
                self.module.CoreSupervisor(self.root, self.core, authorized=True)
        self.assertFalse((self.root / "chain").exists())


if __name__ == "__main__":
    unittest.main()
