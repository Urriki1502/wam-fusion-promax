"""PM-086 step 2: Q05 read-only gate B denies mutations before any side effect."""
import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend
from wam_regtest.cli import main
from wam_regtest.wallet_executor import ManagedWalletBackend, WalletExecutorError

_PASSWORD = b"public-password"


def _digest(root):
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rows.append(path.relative_to(root).as_posix() + ":" + hashlib.sha256(path.read_bytes()).hexdigest())
    return tuple(rows)


class LegacyQ05ReadOnlyGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "canary").write_bytes(b"unchanged")
        self.addCleanup(self.tmp.cleanup)

    def backend(self):
        backend = ManagedWalletBackend(self.root, self.root, self.root)
        backend.session = Mock()
        return backend

    def test_denied_actions_raise_before_any_side_effect(self):
        calls = (
            ("open", (_PASSWORD,), {"create": True}),
            ("prepare", ("code", 1), {}),
            ("prepare_auto", ("code", 1), {}),
            ("sign", ("token",), {}),
            ("broadcast", ("token",), {}),
            ("mine", (), {}),
            ("cancel", ("token",), {}),
            ("recover", (_PASSWORD,), {}),
            ("complete_recovery", (_PASSWORD, "broadcast"), {}),
        )
        with patch("wam_regtest.ui_settings.native_store_enabled", return_value=False), \
                patch("wam_regtest.core_supervisor.CoreSupervisor.start") as started, \
                patch("wam_regtest.wallet_session.WalletSession.open_owned") as opened, \
                patch("wam_regtest.wallet_recovery.recover_checkpoint") as recovered, \
                patch("wam_regtest.wallet_recovery.complete_recovery") as completed:
            before = _digest(self.root)
            for action, args, kwargs in calls:
                with self.subTest(action=action):
                    backend = self.backend()
                    with self.assertRaises(WalletExecutorError) as caught:
                        backend.execute(action, args, kwargs)
                    self.assertEqual(caught.exception.args, ("LEGACY_Q05_RETIRED",))
                    with self.assertRaises(WalletExecutorError) as again:
                        backend.execute(action, args, kwargs)
                    self.assertEqual(again.exception.args, ("LEGACY_Q05_RETIRED",))
                    backend.session.prepare.assert_not_called()
                    backend.session.prepare_auto.assert_not_called()
                    backend.session.sign.assert_not_called()
                    backend.session.broadcast.assert_not_called()
                    backend.session.mine.assert_not_called()
                    backend.session.cancel.assert_not_called()
            started.assert_not_called()
            opened.assert_not_called()
            recovered.assert_not_called()
            completed.assert_not_called()
            self.assertEqual(_digest(self.root), before)

    def test_explicit_prepare_refusal_stays_ahead_of_retirement(self):
        backend = ManagedWalletBackend.__new__(ManagedWalletBackend)
        with patch("wam_regtest.ui_settings.native_store_enabled", return_value=True):
            with self.assertRaisesRegex(WalletExecutorError, "^FEE_EXPLICIT_PREPARE_DENIED$"):
                backend.execute("prepare", ("code", 1_000, 155), {})

    def test_existing_open_reaches_the_owned_session(self):
        backend = ManagedWalletBackend(self.root, self.root, self.root)
        owner = Mock()
        session = Mock()
        session.snapshot.return_value = {"height": 0}
        with patch.object(backend, "_core", return_value=owner) as core, \
                patch("wam_regtest.wallet_session.WalletSession.open_owned", return_value=session) as opened:
            self.assertEqual(
                backend.execute("open", (_PASSWORD,), {"create": False}), {"height": 0})
        core.assert_called_once_with()
        opened.assert_called_once()
        self.assertIs(opened.call_args.kwargs["create"], False)
        self.assertIs(backend.session, session)

    def test_allowed_lifecycle_is_not_retired(self):
        backend = self.backend()
        backend.session.locked = False
        backend.session.snapshot.return_value = {"height": 1}
        backend.session.network_diagnostics.return_value = {"network": "regtest"}
        backend.session.disclose_record.return_value = {"disclosed": True}
        backend.session.backup.return_value = {"path": "backup"}
        owner = Mock()
        owner.process = None
        owner.profile = {"profile_id": "a" * 16}
        owner.root = self.root
        owner.control_operation.return_value = {"state": "stopped"}
        backend.owner = owner
        allowed = (
            ("unlock", (_PASSWORD, False), {}),
            ("lock", (), {}),
            ("snapshot", (), {}),
            ("network", (), {}),
            ("disclose", (), {}),
            ("backup", (), {}),
            ("quit", (), {}),
            ("core_restart", (), {}),
            ("control", ("status",), {}),
            ("quit_notices", (), {}),
            ("acknowledge_quit_notices", (), {}),
            ("core_status", (), {}),
        )
        with patch.object(backend, "_core", return_value=owner), \
                patch("wam_regtest.wallet_session.WalletSession.open_owned", return_value=backend.session), \
                patch.object(backend, "quit_notices", return_value=()), \
                patch.object(backend, "acknowledge_quit_notices", return_value={"recorded": True}):
            for action, args, kwargs in allowed:
                with self.subTest(action=action):
                    try:
                        backend.execute(action, args, kwargs)
                    except WalletExecutorError as error:
                        self.assertNotEqual(error.args, ("LEGACY_Q05_RETIRED",))

    def test_original_owner_stays_controllable_after_create_is_refused(self):
        backend = ManagedWalletBackend(self.root, self.root, self.root)
        owner = Mock()
        owner.process.poll.return_value = None
        owner._faulted = False
        owner.directory = self.root
        owner.control_operation.return_value = {"state": "running"}
        backend.owner = owner
        backend.session = Mock()
        backend.session.snapshot.return_value = {"height": 0}
        with patch("wam_regtest.rpc_scope.identity", return_value=None):
            self.assertEqual(backend.execute("control", ("status",), {}), {"state": "running"})
            result = backend.execute("quit", (), {})
        owner.shutdown.assert_called_once_with()
        owner.release.assert_called_once_with()
        owner.close.assert_called_once_with()
        self.assertIn("runtime_preserved", result)
        owner.start.reset_mock()
        with patch("wam_regtest.core_supervisor.CoreSupervisor.start") as started, \
                patch("wam_regtest.wallet_session.WalletSession.open_owned") as opened:
            with self.assertRaises(WalletExecutorError) as caught:
                backend.execute("open", (_PASSWORD,), {"create": True})
            self.assertEqual(caught.exception.args, ("LEGACY_Q05_RETIRED",))
            started.assert_not_called()
            owner.start.assert_not_called()
            opened.assert_not_called()
            with patch.object(backend, "_core", return_value=owner):
                opened.return_value = backend.session
                self.assertEqual(
                    backend.execute("open", (_PASSWORD,), {"create": False}), {"height": 0})
            self.assertIs(opened.call_args.kwargs["create"], False)

    def test_q06_backend_is_outside_the_q05_gate(self):
        backend = Bip39ReadOnlyBackend.__new__(Bip39ReadOnlyBackend)
        backend._session_kind = "Q06"
        with self.assertRaises(Exception) as caught:
            backend.execute("prepare_auto", (), {})
        self.assertNotEqual(caught.exception.args[:1], ("LEGACY_Q05_RETIRED",))


class LegacyQ05CreateCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def argv(self, *extra):
        return [
            "wam-regtest", "managed-gui",
            "--core-dir", str(self.root),
            "--root", str(self.root),
            "--wsp-source-root", str(self.root),
            "--confirm-regtest-managed-core",
            *extra,
        ]

    def test_create_wallet_is_refused_before_launch(self):
        stderr = io.StringIO()
        with patch.object(sys, "argv", self.argv("--create-wallet")), \
                patch.object(sys, "stderr", stderr), \
                patch("wam_regtest.managed_gui.launch_managed", side_effect=AssertionError("launched")):
            self.assertEqual(main(), 2)
        self.assertIn("LEGACY_Q05_RETIRED", stderr.getvalue())

    def test_existing_profile_open_still_launches(self):
        with patch.object(sys, "argv", self.argv()), \
                patch("wam_regtest.managed_gui.launch_managed", return_value=0) as launch:
            self.assertEqual(main(), 0)
        self.assertIs(launch.call_args.kwargs["create"], False)

    def test_help_does_not_offer_create(self):
        stdout = io.StringIO()
        with patch.object(sys, "argv", ["wam-regtest", "managed-gui", "--help"]), \
                patch.object(sys, "stdout", stdout):
            with self.assertRaises(SystemExit) as caught:
                main()
        self.assertEqual(caught.exception.code, 0)
        help_text = stdout.getvalue()
        self.assertNotIn("--create-wallet", help_text)
        self.assertNotIn("create a new", help_text)
