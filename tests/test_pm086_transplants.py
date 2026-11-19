"""PM-086 step 1: close-during-broadcast, frozen crash, and D-QUIT transplants."""
import inspect
import os
import runpy
import sys
import threading
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QWidget

from wam_regtest.qualification.broadcast_close_barrier import (
    install_broadcast_barrier, observe_deferred_close)
from wam_regtest.qualification import q05_dquit1_runner as runner
from wam_regtest import q05_crash_scenario as crash
from wam_regtest.q05_packaged import run
from wam_regtest.wallet_executor import ManagedWalletBackend

ROOT = Path(__file__).resolve().parents[1]
_PASSWORD = b"public-disposable-q05-dquit1-only"


class _HoldWindow(QWidget):
    def __init__(self):
        super().__init__()
        self._quit_requested = False

    def closeEvent(self, event):
        event.ignore()
        self._quit_requested = True


class _Process:
    def poll(self):
        return None


class BroadcastCloseBarrierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_barrier_holds_only_broadcast_and_counts_one_success(self):
        calls = []

        class Backend:
            def execute(self, action, args, kwargs):
                calls.append(action)
                if action == "broadcast" and kwargs.get("fail"):
                    raise ValueError("Q06_BROADCAST_CLOSE_BARRIER_TIMEOUT")
                return action

        backend = Backend()
        barrier = install_broadcast_barrier(backend, timeout=2)
        self.assertEqual(backend.execute("snapshot", (), {}), "snapshot")
        self.assertEqual(barrier.submissions, 0)
        results = []

        def broadcast():
            try:
                results.append(backend.execute("broadcast", (), {}))
            except ValueError as error:
                results.append(error.args[0])

        worker = threading.Thread(target=broadcast)
        worker.start()
        self.assertTrue(barrier.entered.wait(1))
        self.assertEqual(barrier.submissions, 0)
        self.assertEqual(calls, ["snapshot"])
        barrier.release.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results, ["broadcast"])
        self.assertEqual(barrier.submissions, 1)
        self.assertEqual(backend.execute("mine", (), {}), "mine")
        self.assertEqual(barrier.submissions, 1)

    def test_barrier_timeout_does_not_count_a_submission(self):
        class Backend:
            def execute(self, action, args, kwargs):
                return action

        backend = Backend()
        barrier = install_broadcast_barrier(backend, timeout=1)
        with self.assertRaisesRegex(ValueError, "^Q06_BROADCAST_CLOSE_BARRIER_TIMEOUT$"):
            backend.execute("broadcast", (), {})
        self.assertEqual(barrier.submissions, 0)

    def test_deferred_close_records_the_four_facts_and_withdraws_quit(self):
        process = _Process()
        window = _HoldWindow()
        window.show()
        self.addCleanup(window.deleteLater)
        executor = Mock()
        executor.busy = True
        executor._backend.owner.process = process
        observed = observe_deferred_close(self.app, window, executor, process)
        self.assertEqual(observed, {
            "close_during_approved_broadcast_deferred": True,
            "qt_timer_alive_during_operation": True,
            "wallet_close_reopen_same_core": True,
        })
        self.assertTrue(window.isVisible())
        self.assertFalse(window._quit_requested)

    def test_deferred_close_refuses_a_hidden_window_or_a_replaced_process(self):
        process = _Process()
        window = _HoldWindow()
        window.show()
        self.addCleanup(window.deleteLater)
        executor = Mock()
        executor.busy = False
        executor._backend.owner.process = process
        with self.assertRaisesRegex(ValueError, "^Q06_GUI_UNSAFE_INFLIGHT_CLOSE$"):
            observe_deferred_close(self.app, window, executor, process)
        executor.busy = True
        executor._backend.owner.process = _Process()
        with self.assertRaisesRegex(ValueError, "^Q06_GUI_CLOSE_CHANGED_CORE$"):
            observe_deferred_close(self.app, window, executor, process)

    def test_probes_and_builders_name_the_same_receipt_fields(self):
        fields = (
            "close_during_approved_broadcast_deferred",
            "qt_timer_alive_during_operation",
            "wallet_close_reopen_same_core",
            "wallet_submissions",
        )
        spend = (ROOT / "src/wam_regtest/q06_spend_probe.py").read_text()
        platform = (ROOT / "src/wam_regtest/q06_platform_probe.py").read_text()
        frozen = (ROOT / "scripts/qualify_q06_frozen.py").read_text()
        bundle = (ROOT / "scripts/build_macos_bundle.sh").read_text()
        for text in (spend, platform, frozen, bundle):
            for field in fields:
                self.assertIn(field, text)
        self.assertIn("install_broadcast_barrier", spend)
        self.assertIn("install_broadcast_barrier", platform)
        self.assertNotIn("os.environ", (ROOT / "src/wam_regtest/qualification/broadcast_close_barrier.py").read_text())
        headless = frozen.split("if not a.headless:", 1)[1]
        for field in fields:
            self.assertIn(field, headless)


class ColdCrashTransplantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.root = self.directory / ("wam-fusion-core-" + "b" * 16)

    def test_crash_refuses_before_source_core_or_files(self):
        args = ["--core-dir", str(self.directory), "--wsp-source", str(self.directory),
                "--root", str(self.root), "--receipt", str(self.directory / "receipt.json")]
        with patch.object(crash, "verify_source") as source, patch.object(crash, "verified_core_paths") as core:
            with self.assertRaisesRegex(ValueError, "Q05_CRASH_DISPOSABLE_SCOPE_DENIED"):
                crash.main(args)
            source.assert_not_called()
            core.assert_not_called()
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_existing_profile_is_not_reused(self):
        self.root.mkdir()
        canary = self.root / "preserve"
        canary.write_bytes(b"public-fixture")
        args = ["--core-dir", str(self.directory), "--wsp-source", str(self.directory),
                "--root", str(self.root), "--receipt", str(self.directory / "receipt.json"),
                "--confirm-disposable-regtest"]
        with patch.object(crash, "verify_source") as source:
            with self.assertRaisesRegex(ValueError, "Q05_CRASH_DISPOSABLE_SCOPE_DENIED"):
                crash.main(args)
            source.assert_not_called()
        self.assertEqual(canary.read_bytes(), b"public-fixture")

    def test_packaged_crash_does_not_fall_through_to_the_gui(self):
        args = ["--root", str(self.root), "--receipt", str(self.directory / "receipt.json"),
                "--confirm-disposable-regtest"]
        with patch.object(sys, "frozen", True, create=True), \
                patch.object(sys, "platform", "darwin"), \
                patch.object(crash, "main", return_value=0) as engine, \
                patch("wam_regtest.q05_gui_scenario.run_scenario") as gui:
            self.assertEqual(run(self.directory, self.directory, [*args, "--scenario", "crash"]), 0)
            engine.assert_called_once_with(args, core=self.directory, source=self.directory, frozen=True)
            gui.assert_not_called()
        text = (ROOT / "src/wam_regtest/q05_crash_scenario.py").read_text()
        self.assertNotIn("ManagedWalletBackend", text)
        self.assertNotIn("os.environ", text)

    def test_require_crash_receipt_is_fail_closed_and_gui_length_stays(self):
        require = runpy.run_path(str(ROOT / "scripts/qualify_q05_frozen.py"))
        binary = self.directory / "bootloader"
        binary.write_bytes(b"public-test-bootloader")
        digest = sha256(binary.read_bytes()).hexdigest()
        good = {
            "status": "PASS", "owner_shutdown_verified": True, "frozen": True,
            "synthetic_rpc": False, "mainnet_allowed": False, "source_sha": "abc",
            "wsp_source_commit": "ac55f13423620252bdbf848c7e8a280c3b84721e",
            "source_provenance": {"frozen_executable_sha256": digest},
            "observations": [
                {"owned_Core_flush_before_cold_crash": True,
                 "history_sha256": "a" * 64, "reservation_sha256": "b" * 64},
                {"crash_scope": "after-owned-Core-flush-without-clean-shutdown",
                 "automatic_wallet_replay": False,
                 "history_sha256": "a" * 64, "reservation_sha256": "b" * 64},
            ],
        }
        require["require_crash_receipt"](good, binary, "abc")
        for changes in (
                {"frozen": False}, {"automatic_wallet_replay": True},
                {"history_sha256": "c" * 64}, {"owner_shutdown_verified": False},
                {"observations": []}):
            broken = {
                **good,
                "observations": [dict(item) for item in good["observations"]],
            }
            if "history_sha256" in changes:
                broken["observations"][1]["history_sha256"] = changes["history_sha256"]
            elif "automatic_wallet_replay" in changes:
                broken["observations"][1]["automatic_wallet_replay"] = changes["automatic_wallet_replay"]
            elif "observations" in changes:
                broken["observations"] = changes["observations"]
            else:
                broken.update(changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "CRASH_RECEIPT_DENIED"):
                require["require_crash_receipt"](broken, binary, "abc")
        frozen_source = (ROOT / "scripts/qualify_q05_frozen.py").read_text()
        receipt = frozen_source.split("def require_crash_receipt", 1)[0]
        self.assertNotIn("owned_Core_flush_before_cold_crash", receipt)
        self.assertNotIn("crash_scope", receipt)
        self.assertNotIn("len(record.get('observations',[]))!=7", receipt)
        self.assertIn("('cold-crash','crash',[])", frozen_source.replace(" ", ""))
        self.assertIn("retired_gui_stage", frozen_source)
        native = (ROOT / "scripts/qualify_q05_native.py").read_text()
        self.assertNotIn("probe_q05_executor_gui.py", native)


class DQuitEngineTransplantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def _backend(self):
        return runner.QualificationQ05Backend(self.root, self.root, self.root)

    def test_engine_create_calls_wallet_session_not_product_open(self):
        backend = self._backend()
        session = Mock()
        session.snapshot.return_value = {"height": 0}
        owner = Mock()
        owner.process = None
        backend._core = Mock(return_value=owner)
        with patch.object(ManagedWalletBackend, "_open", side_effect=AssertionError("product open")), \
                patch("wam_regtest.wallet_session.WalletSession.open_owned", return_value=session) as opened:
            self.assertEqual(
                backend.execute("engine_open_owned", (_PASSWORD,), {"create": True}),
                {"height": 0})
        opened.assert_called_once()
        self.assertIs(opened.call_args.kwargs["create"], True)
        self.assertIs(backend.session, session)
        backend._core.assert_called_once()

    def test_engine_create_false_does_not_start_core(self):
        backend = self._backend()
        backend._core = Mock(side_effect=AssertionError("core"))
        with self.assertRaisesRegex(ValueError, "^Q05_DQUIT1_ENGINE_CREATE_REQUIRED$"):
            backend.execute("engine_open_owned", (_PASSWORD,), {"create": False})
        backend._core.assert_not_called()

    def test_existing_profile_open_stays_on_the_backend(self):
        backend = self._backend()
        with patch.object(ManagedWalletBackend, "_open", return_value="opened") as opened:
            self.assertEqual(backend.execute("open", (_PASSWORD,), {"create": False}), "opened")
        opened.assert_called_once_with(_PASSWORD, create=False)

    def test_engine_recover_calls_wallet_recovery(self):
        backend = self._backend()
        backend.owner = Mock()
        backend.keychain = object()
        backend._core = Mock(side_effect=AssertionError("core"))
        with patch("wam_regtest.wallet_recovery.recover_checkpoint",
                   return_value={"reservation_states": ["signed"]}) as recover:
            self.assertEqual(
                backend.execute("engine_recover", (_PASSWORD,), {}),
                {"reservation_states": ["signed"]})
        recover.assert_called_once()
        self.assertIs(recover.call_args.kwargs["keychain"], backend.keychain)
        backend._core.assert_not_called()

    def test_scenarios_keep_notice_reopen_on_the_backend(self):
        scenario_a = inspect.getsource(runner._run_scenario_a)
        scenario_b = inspect.getsource(runner._run_scenario_b)
        for text, engine in (
                (scenario_a, ("engine_open_owned", "engine_prepare_auto", "engine_sign", "engine_recover")),
                (scenario_b, ("engine_open_owned", "engine_mine"))):
            for name in engine:
                self.assertIn(name, text)
            self.assertNotIn('request("open", _PASSWORD, create=True', text)
            self.assertIn('request("open", _PASSWORD, create=False', text)
            self.assertIn("QUIT_NOTICE_REVIEW_REQUIRED", text)
        self.assertNotIn('request("prepare_auto"', scenario_a)
        self.assertNotIn('request("sign"', scenario_a)
        self.assertNotIn('request("recover"', scenario_a)
        self.assertNotIn('request("mine"', scenario_b)
        self.assertNotIn("os.environ", (ROOT / "src/wam_regtest/qualification/q05_dquit1_runner.py").read_text())


if __name__ == "__main__":
    unittest.main()
