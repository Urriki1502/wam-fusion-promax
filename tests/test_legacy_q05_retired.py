"""PM-086 step 2: Q05 read-only gate B denies mutations before any side effect."""
import errno
import hashlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend, Q06ReadOnlyError
from wam_regtest.cli import main
from wam_regtest.wallet_executor import ManagedWalletBackend, WalletExecutorError

_PASSWORD = b"public-password"
_DUMMY_PHRASE = "abandon " * 11 + "about"


def _digest(root):
    rows = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            rows.append(("link", rel, os.readlink(path)))
        elif path.is_file():
            rows.append(("file", rel, hashlib.sha256(path.read_bytes()).hexdigest()))
        elif path.is_dir():
            rows.append(("dir", rel, ""))
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

    def test_retirement_stays_ahead_of_explicit_prepare_with_native_store(self):
        with patch("wam_regtest.ui_settings.native_store_enabled", return_value=True), \
                patch("wam_regtest.core_supervisor.CoreSupervisor.start") as started, \
                patch("wam_regtest.wallet_session.WalletSession.open_owned") as opened:
            bare = ManagedWalletBackend.__new__(ManagedWalletBackend)
            with self.assertRaisesRegex(WalletExecutorError, "^LEGACY_Q05_RETIRED$"):
                bare.execute("prepare", ("code", 1_000, 155), {})
            before = _digest(self.root)
            for action, args in (("prepare", ("code", 1_000, 155)), ("prepare_auto", ("code", 1_000))):
                with self.subTest(action=action):
                    backend = self.backend()
                    with self.assertRaisesRegex(WalletExecutorError, "^LEGACY_Q05_RETIRED$"):
                        backend.execute(action, args, {})
                    backend.session.prepare.assert_not_called()
                    backend.session.prepare_auto.assert_not_called()
            started.assert_not_called()
            opened.assert_not_called()
            self.assertEqual(_digest(self.root), before)
            q06 = Bip39ReadOnlyBackend.__new__(Bip39ReadOnlyBackend)
            q06._session_kind = "Q06"
            with self.assertRaisesRegex(WalletExecutorError, "^FEE_EXPLICIT_PREPARE_DENIED$"):
                q06.execute("prepare", ("code", 1_000, 155), {})

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


class LegacyQ05FolderPreflight(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_layout_check_is_read_only_and_detects_all_markers_without_following_links(self):
        from wam_regtest.managed_onboarding import (
            LegacyQ05InspectionError, inspect_legacy_q05_layout, legacy_q05_layout,
        )
        # Actual supervisor Q05 markers: chain/wallet-vault, chain/wallet-runtime.sqlite(+sidecars),
        # chain/wallet-recovery-*, supervisor.wallet, supervisor.recovery.*
        vault = self.root / "with-vault"
        (vault / "chain" / "wallet-vault").mkdir(parents=True)
        (vault / "canary").write_bytes(b"keep")
        before = _digest(vault)
        self.assertTrue(legacy_q05_layout(vault))
        self.assertEqual(inspect_legacy_q05_layout(vault), "legacy")
        self.assertEqual(_digest(vault), before)

        marker_setups = (
            ("supervisor-wallet", lambda d: (d / "supervisor.wallet").write_bytes(b"envelope")),
            ("supervisor-recovery", lambda d: (d / "supervisor.recovery.000001").write_bytes(b"rec")),
            ("chain-runtime", lambda d: ((d / "chain").mkdir(), (d / "chain" / "wallet-runtime.sqlite").write_bytes(b"db"))),
            ("chain-runtime-wal", lambda d: ((d / "chain").mkdir(), (d / "chain" / "wallet-runtime.sqlite-wal").write_bytes(b"wal"))),
            ("chain-runtime-journal", lambda d: ((d / "chain").mkdir(), (d / "chain" / "wallet-runtime.sqlite-journal").write_bytes(b"j"))),
            ("chain-runtime-shm", lambda d: ((d / "chain").mkdir(), (d / "chain" / "wallet-runtime.sqlite-shm").write_bytes(b"s"))),
            ("chain-runtime-lock", lambda d: ((d / "chain").mkdir(), (d / "chain" / "wallet-runtime.sqlite.scan.lock").write_bytes(b"l"))),
            ("chain-recovery", lambda d: (d / "chain" / ("wallet-recovery-" + "a" * 16)).mkdir(parents=True)),
        )
        for name, make_marker in marker_setups:
            with self.subTest(marker=name):
                folder = self.root / name
                folder.mkdir()
                make_marker(folder)
                snap = _digest(folder)
                self.assertTrue(legacy_q05_layout(folder))
                self.assertEqual(_digest(folder), snap)

        # Symlinked and dangling-symlink markers must be conservatively detected without following.
        linked = self.root / "linked"
        (linked / "chain").mkdir(parents=True)
        (linked / "chain" / "wallet-vault").symlink_to(vault / "chain" / "wallet-vault", target_is_directory=True)
        (linked / "supervisor.wallet").symlink_to(self.root / "supervisor-wallet" / "supervisor.wallet")
        linked_snap = _digest(linked)
        self.assertTrue(legacy_q05_layout(linked))
        self.assertEqual(_digest(linked), linked_snap)

        dangling_chain = self.root / "dangling-chain"
        (dangling_chain / "chain").mkdir(parents=True)
        (dangling_chain / "chain" / "wallet-vault").symlink_to(self.root / "does-not-exist-vault")
        dangling_snap = _digest(dangling_chain)
        self.assertTrue(legacy_q05_layout(dangling_chain))
        self.assertEqual(_digest(dangling_chain), dangling_snap)

        dangling_wallet = self.root / "dangling-wallet"
        dangling_wallet.mkdir()
        (dangling_wallet / "supervisor.wallet").symlink_to(self.root / "does-not-exist-wallet")
        self.assertTrue(legacy_q05_layout(dangling_wallet))

        # Shared Q06/supervisor files must not trigger legacy detection.
        q06 = self.root / "q06-shared"
        (q06 / "chain" / ("bip39-12-" + "a" * 32)).mkdir(parents=True)
        (q06 / "supervisor.profile").write_text("DISPOSABLE", encoding="utf-8")
        (q06 / "supervisor.token").write_bytes(b"tok")
        (q06 / "supervisor.event.000001").write_bytes(b"ev")
        (q06 / "chain" / "wam.conf").write_text("regtest=1\n", encoding="utf-8")
        (q06 / "chain" / ("wallet-runtime-recovery-" + "b" * 16 + ".sqlite")).write_bytes(b"q06")
        self.assertFalse(legacy_q05_layout(q06))
        self.assertEqual(inspect_legacy_q05_layout(q06), "absent")

        self.assertFalse(legacy_q05_layout(self.root / "missing"))
        plain = self.root / "plain"
        plain.mkdir()
        self.assertFalse(legacy_q05_layout(plain))

        # Inspection errors must fail closed with a typed error distinct from legacy.
        unreadable = self.root / "unreadable"
        (unreadable / "chain").mkdir(parents=True)
        os.chmod(unreadable / "chain", 0o000)
        self.addCleanup(lambda: os.chmod(unreadable / "chain", 0o700) if (unreadable / "chain").exists() else None)
        if os.geteuid() != 0:
            with self.assertRaisesRegex(LegacyQ05InspectionError, "^LEGACY_Q05_PREFLIGHT_UNVERIFIED$"):
                legacy_q05_layout(unreadable)
        symlink_chain = self.root / "symlink-chain"
        symlink_chain.mkdir()
        (symlink_chain / "chain").symlink_to(vault / "chain", target_is_directory=True)
        with self.assertRaisesRegex(LegacyQ05InspectionError, "^LEGACY_Q05_PREFLIGHT_UNVERIFIED$"):
            legacy_q05_layout(symlink_chain)
        with patch.object(Path, "lstat", side_effect=OSError(errno.EIO, "io failure")):
            with self.assertRaisesRegex(LegacyQ05InspectionError, "^LEGACY_Q05_PREFLIGHT_UNVERIFIED$"):
                legacy_q05_layout(plain)

    def test_open_and_restore_refuse_a_q05_folder_before_core(self):
        from PySide6.QtCore import QTimer
        from wam_regtest import managed_onboarding as onboarding
        from wam_regtest.presentation.strings import CATALOG
        message = CATALOG["en"]["welcome.legacy_q05_preserved"]
        for language, entries in CATALOG.items():
            text = entries["welcome.legacy_q05_preserved"]
            self.assertIn("V1", text, language)
            self.assertTrue(text.strip(), language)
        for choice in ("open", "restore"):
            with self.subTest(choice=choice):
                folder = self.root / choice
                (folder / "chain" / "wallet-vault").mkdir(parents=True)
                (folder / "canary").write_bytes(b"keep")
                before = _digest(folder)
                dialogs = []
                original = onboarding.welcome_dialog

                def welcome():
                    dialog = original()
                    dialogs.append(dialog)
                    QTimer.singleShot(0, dialog.buttons[choice].click if len(dialogs) == 1 else dialog.reject)
                    return dialog

                with patch.object(onboarding, "welcome_dialog", side_effect=welcome), \
                        patch("PySide6.QtWidgets.QFileDialog.getExistingDirectory", return_value=str(folder)), \
                        patch("PySide6.QtWidgets.QMessageBox.warning") as warning, \
                        patch("wam_regtest.bip39_owner_gui.launch_bip39_trial") as launch, \
                        patch("wam_regtest.core_supervisor.CoreSupervisor") as supervisor, \
                        patch("wam_regtest.custody.anchor") as anchor:
                    self.assertEqual(onboarding.launch(self.root, self.root), 0)
                launch.assert_not_called()
                supervisor.assert_not_called()
                anchor.assert_not_called()
                warning.assert_called_once()
                self.assertEqual(warning.call_args.args[2], message)
                self.assertEqual(_digest(folder), before)

    def test_open_and_restore_refuse_symlinked_and_dangling_q05_markers_before_core(self):
        from PySide6.QtCore import QTimer
        from wam_regtest import managed_onboarding as onboarding
        from wam_regtest.presentation.strings import CATALOG
        message = CATALOG["en"]["welcome.legacy_q05_preserved"]
        target_dir = self.root / "target-vault"
        target_dir.mkdir()
        target_file = self.root / "target-wallet"
        target_file.write_bytes(b"envelope")
        cases = (
            ("symlink-vault", lambda d: ((d / "chain").mkdir(), (d / "chain" / "wallet-vault").symlink_to(target_dir, target_is_directory=True))),
            ("dangling-vault", lambda d: ((d / "chain").mkdir(), (d / "chain" / "wallet-vault").symlink_to(self.root / "absent-vault"))),
            ("symlink-wallet", lambda d: (d / "supervisor.wallet").symlink_to(target_file)),
            ("dangling-wallet", lambda d: (d / "supervisor.wallet").symlink_to(self.root / "absent-wallet")),
        )
        for choice in ("open", "restore"):
            for case_name, setup_marker in cases:
                with self.subTest(choice=choice, case=case_name):
                    folder = self.root / f"{choice}-{case_name}"
                    folder.mkdir()
                    (folder / "canary").write_bytes(b"keep")
                    setup_marker(folder)
                    before = _digest(folder)
                    dialogs = []
                    original = onboarding.welcome_dialog

                    def welcome():
                        dialog = original()
                        dialogs.append(dialog)
                        QTimer.singleShot(0, dialog.buttons[choice].click if len(dialogs) == 1 else dialog.reject)
                        return dialog

                    with patch.object(onboarding, "welcome_dialog", side_effect=welcome), \
                            patch("PySide6.QtWidgets.QFileDialog.getExistingDirectory", return_value=str(folder)), \
                            patch("PySide6.QtWidgets.QMessageBox.warning") as warning, \
                            patch("wam_regtest.bip39_owner_gui.launch_bip39_trial") as launch, \
                            patch("wam_regtest.core_supervisor.CoreSupervisor") as supervisor, \
                            patch("wam_regtest.custody.anchor") as anchor:
                        self.assertEqual(onboarding.launch(self.root, self.root), 0)
                    launch.assert_not_called()
                    supervisor.assert_not_called()
                    anchor.assert_not_called()
                    warning.assert_called_once()
                    self.assertEqual(warning.call_args.args[2], message)
                    self.assertEqual(_digest(folder), before)

    def test_open_and_restore_fail_closed_on_inspection_error(self):
        from PySide6.QtCore import QTimer
        from wam_regtest import managed_onboarding as onboarding
        from wam_regtest.presentation.strings import CATALOG
        legacy_msg = CATALOG["en"]["welcome.legacy_q05_preserved"]
        rejected_msg = CATALOG["en"]["welcome.folder_rejected"]
        for choice in ("open", "restore"):
            with self.subTest(choice=choice):
                folder = self.root / f"err-{choice}"
                (folder / "chain").mkdir(parents=True)
                (folder / "canary").write_bytes(b"keep")
                before = _digest(folder)
                dialogs = []
                original = onboarding.welcome_dialog

                def welcome():
                    dialog = original()
                    dialogs.append(dialog)
                    QTimer.singleShot(0, dialog.buttons[choice].click if len(dialogs) == 1 else dialog.reject)
                    return dialog

                with patch.object(onboarding, "welcome_dialog", side_effect=welcome), \
                        patch("PySide6.QtWidgets.QFileDialog.getExistingDirectory", return_value=str(folder)), \
                        patch("PySide6.QtWidgets.QMessageBox.warning") as warning, \
                        patch("wam_regtest.bip39_owner_gui.launch_bip39_trial") as launch, \
                        patch("wam_regtest.core_supervisor.CoreSupervisor") as supervisor, \
                        patch("wam_regtest.custody.anchor") as anchor, \
                        patch.object(onboarding, "legacy_q05_layout", side_effect=onboarding.LegacyQ05InspectionError("LEGACY_Q05_PREFLIGHT_UNVERIFIED")):
                    self.assertEqual(onboarding.launch(self.root, self.root), 0)
                launch.assert_not_called()
                supervisor.assert_not_called()
                anchor.assert_not_called()
                warning.assert_called_once()
                self.assertEqual(warning.call_args.args[2], rejected_msg)
                self.assertNotEqual(warning.call_args.args[2], legacy_msg)
                self.assertEqual(_digest(folder), before)

    def test_a_bip39_folder_still_reaches_the_owner(self):
        from PySide6.QtCore import QTimer
        from wam_regtest import managed_onboarding as onboarding
        folder = self.root / ("wam-fusion-core-" + "ab" * 8)
        folder.mkdir()
        (folder / "supervisor.profile").write_text("DISPOSABLE", encoding="utf-8")
        dialogs = []
        original = onboarding.welcome_dialog

        def welcome():
            dialog = original()
            dialogs.append(dialog)
            QTimer.singleShot(0, dialog.buttons["open"].click)
            return dialog

        with patch.object(onboarding, "welcome_dialog", side_effect=welcome), \
                patch("PySide6.QtWidgets.QFileDialog.getExistingDirectory", return_value=str(folder)), \
                patch("wam_regtest.bip39_owner_gui.launch_bip39_trial", return_value=0) as launch, \
                patch("wam_regtest.core_supervisor.CoreSupervisor") as supervisor:
            self.assertEqual(onboarding.launch(self.root, self.root), 0)
        launch.assert_called_once()
        self.assertEqual(launch.call_args.args[0], folder)
        supervisor.assert_not_called()


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


class LegacyQ05BackendOpenBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _run_guarded(self, folder, action, args):
        anchor_factory = Mock()
        backend = Bip39ReadOnlyBackend(folder, self.root, self.root, _anchor_factory=anchor_factory)
        backend.attach_executor(Mock())
        with patch("wam_regtest.core_supervisor.CoreSupervisor") as supervisor_cls, \
                patch("wam_regtest.core_supervisor.CoreSupervisor.start") as core_start, \
                patch("wam_regtest.custody.anchor") as custody_anchor, \
                patch("wam_regtest.bip39_seed_vault.create_owned_seed_container") as seed_create, \
                patch("wam_regtest.bip39_seed_vault.open_owned_seed_container") as seed_open, \
                patch.object(backend, "_core", wraps=backend._core) as core_call:
            with self.assertRaises(Q06ReadOnlyError) as caught:
                backend.execute(action, args, {})
        supervisor_cls.assert_not_called()
        core_start.assert_not_called()
        core_call.assert_not_called()
        anchor_factory.assert_not_called()
        custody_anchor.assert_not_called()
        seed_create.assert_not_called()
        seed_open.assert_not_called()
        return caught.exception.args

    def test_backend_open_and_unlock_refuse_markers_before_owner_core_anchor(self):
        target_dir = self.root / "real-vault-target"
        target_dir.mkdir()
        target_file = self.root / "real-wallet-target"
        target_file.write_bytes(b"envelope")
        cases = (
            ("chain-wallet-vault", lambda d: (d / "chain" / "wallet-vault").mkdir(parents=True)),
            ("supervisor-wallet", lambda d: (d / "supervisor.wallet").write_bytes(b"envelope")),
            ("supervisor-recovery", lambda d: (d / "supervisor.recovery.000001").write_bytes(b"rec")),
            ("chain-runtime", lambda d: ((d / "chain").mkdir(), (d / "chain" / "wallet-runtime.sqlite").write_bytes(b"db"))),
            ("chain-recovery", lambda d: (d / "chain" / ("wallet-recovery-" + "a" * 16)).mkdir(parents=True)),
            ("symlink-chain-vault", lambda d: ((d / "chain").mkdir(), (d / "chain" / "wallet-vault").symlink_to(target_dir, target_is_directory=True))),
            ("dangling-chain-vault", lambda d: ((d / "chain").mkdir(), (d / "chain" / "wallet-vault").symlink_to(self.root / "missing-vault"))),
            ("symlink-supervisor-wallet", lambda d: (d / "supervisor.wallet").symlink_to(target_file)),
            ("dangling-supervisor-wallet", lambda d: (d / "supervisor.wallet").symlink_to(self.root / "missing-wallet")),
        )
        ops = (
            ("open", (_PASSWORD, "create", "")),
            ("open", (_PASSWORD, "restore", _DUMMY_PHRASE)),
            ("open", (_PASSWORD, "reopen", "")),
            ("unlock", (_PASSWORD, False)),
        )
        for case_name, setup_marker in cases:
            for action, args in ops:
                tag = args[1] if action == "open" else action
                with self.subTest(case=case_name, op=tag):
                    folder = self.root / f"wam-fusion-core-{case_name}-{tag}"
                    folder.mkdir()
                    (folder / "canary").write_bytes(b"keep")
                    setup_marker(folder)
                    before = _digest(folder)
                    code = self._run_guarded(folder, action, args)
                    self.assertEqual(code, ("Q06_GUI_Q05_PROFILE_CONFLICT",))
                    self.assertEqual(_digest(folder), before)

    def test_backend_open_fails_closed_on_inspection_error_before_owner_core_anchor(self):
        folder = self.root / ("wam-fusion-core-" + "c" * 16)
        (folder / "chain").mkdir(parents=True)
        (folder / "canary").write_bytes(b"keep")
        before = _digest(folder)
        if os.geteuid() != 0:
            os.chmod(folder / "chain", 0o000)
            try:
                code = self._run_guarded(folder, "open", (_PASSWORD, "reopen", ""))
                self.assertEqual(code, ("LEGACY_Q05_PREFLIGHT_UNVERIFIED",))
            finally:
                os.chmod(folder / "chain", 0o700)
            self.assertEqual(_digest(folder), before)
        with patch.object(Path, "lstat", side_effect=OSError(errno.EIO, "io failure")):
            code = self._run_guarded(folder, "open", (_PASSWORD, "reopen", ""))
        self.assertEqual(code, ("LEGACY_Q05_PREFLIGHT_UNVERIFIED",))
        self.assertEqual(_digest(folder), before)

    def test_backend_open_refuses_marker_swapped_after_selection_toctou(self):
        from wam_regtest.managed_onboarding import legacy_q05_layout, selected_profile
        # Reopen TOCTOU: selection sees clean Q06 profile, marker swapped in before backend open.
        folder = self.root / ("wam-fusion-core-" + "d" * 16)
        folder.mkdir()
        (folder / "supervisor.profile").write_text("DISPOSABLE", encoding="utf-8")
        (folder / "canary").write_bytes(b"keep")
        self.assertFalse(legacy_q05_layout(folder))
        selected = selected_profile(folder, False)
        self.assertEqual(selected, folder)
        # Attacker swaps in real Q05 marker after selection.
        (selected / "chain" / "wallet-vault").mkdir(parents=True)
        before = _digest(selected)
        code = self._run_guarded(selected, "open", (_PASSWORD, "reopen", ""))
        self.assertEqual(code, ("Q06_GUI_Q05_PROFILE_CONFLICT",))
        self.assertEqual(_digest(selected), before)

        # Create/restore TOCTOU: selection picks fresh profile path, dangling marker placed before open.
        parent = self.root / "parent"
        parent.mkdir()
        self.assertFalse(legacy_q05_layout(parent))
        fresh = selected_profile(parent, True)
        (fresh / "chain").mkdir(parents=True)
        (fresh / "chain" / "wallet-vault").symlink_to(self.root / "missing-target")
        fresh_before = _digest(fresh)
        code = self._run_guarded(fresh, "open", (_PASSWORD, "restore", _DUMMY_PHRASE))
        self.assertEqual(code, ("Q06_GUI_Q05_PROFILE_CONFLICT",))
        self.assertEqual(_digest(fresh), fresh_before)
