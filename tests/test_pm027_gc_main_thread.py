"""PM-027 / W-GC-THREAD: cyclic GC runs only on the Qt main thread.

Repro (offscreen, before the fix), deterministic across repeated runs:
a self-cycle holding an unparented QLabel and a running QTimer, dropped,
then gc.collect() or a heavy allocation on a plain Python thread. Qt prints
"QObject::killTimer: Timers cannot be stopped from another thread" and
"QObject::~QObject: Timers cannot be stopped from another thread", and the
process dies with SIGSEGV or SIGBUS (exit 139 or 138). The field crashes were
the same warnings plus Shiboken mainThreadDeletionHandler →
callCppDestructor<QLabel> on the main thread. That exact destructor frame was
not reproduced in this session; the timer teardown was.

Headless processes are not touched. shutdown_qt is exercised in a child so
it cannot destroy the suite's shared QApplication.
"""
import gc
import os
import subprocess
import sys
import threading
import unittest
from pathlib import Path

from PySide6.QtCore import QThread


_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"


def _child(script, timeout=30):
    env = os.environ.copy()
    env["QT_QPA_PLATFORM"] = "offscreen"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_SRC), env.get("PYTHONPATH", "")])
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


class MainThreadGcTests(unittest.TestCase):
    def setUp(self):
        from wam_regtest.desktop import qt_application
        self.app = qt_application()

    def test_gui_process_disables_gc_and_runs_a_main_thread_timer(self):
        from wam_regtest.desktop import main_thread_gc_timer
        timer = main_thread_gc_timer()
        self.assertIs(threading.current_thread(), threading.main_thread())
        self.assertFalse(gc.isenabled())
        self.assertIsNotNone(timer)
        self.assertTrue(timer.isActive())
        self.assertFalse(timer.isSingleShot())
        self.assertGreaterEqual(timer.interval(), 1000)
        self.assertLessEqual(timer.interval(), 2000)
        self.assertEqual(timer.thread(), self.app.thread())
        self.assertEqual(QThread.currentThread(), self.app.thread())
        again = main_thread_gc_timer()
        from wam_regtest.desktop import qt_application
        qt_application()
        self.assertIs(main_thread_gc_timer(), again)

    def test_timer_collects_on_the_main_thread_only_when_due(self):
        from wam_regtest.desktop import main_thread_gc_timer
        timer = main_thread_gc_timer()
        seen = []

        def callback(phase, info):
            if phase == "start":
                seen.append(threading.current_thread())

        gc.callbacks.append(callback)
        self.addCleanup(gc.callbacks.remove, callback)
        previous = gc.get_threshold()
        self.addCleanup(gc.set_threshold, *previous)
        gc.collect()
        seen.clear()
        gc.set_threshold(10**9, 10**9, 10**9)
        timer.timeout.emit()
        self.assertEqual(seen, [])
        gc.set_threshold(1, 1, 1)
        cycle = []
        cycle.append(cycle)
        del cycle
        timer.timeout.emit()
        self.assertTrue(seen)
        self.assertTrue(all(thread is threading.main_thread() for thread in seen))

    def test_collect_helper_ignores_other_threads(self):
        from wam_regtest.desktop import _collect_cyclic_garbage
        seen = []

        def callback(phase, info):
            if phase == "start":
                seen.append(threading.current_thread().name)

        gc.callbacks.append(callback)
        self.addCleanup(gc.callbacks.remove, callback)
        finished = []

        def worker():
            _collect_cyclic_garbage(force=True)
            finished.append(True)

        thread = threading.Thread(target=worker, name="WAM-wallet-owner")
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(finished, [True])
        self.assertEqual(seen, [])

    def test_worker_allocations_do_not_trigger_collection(self):
        seen = []
        inside = {"value": False}

        def callback(phase, info):
            if phase == "start" and inside["value"]:
                seen.append(threading.current_thread().name)

        gc.callbacks.append(callback)
        self.addCleanup(gc.callbacks.remove, callback)

        def worker():
            inside["value"] = True
            try:
                junk = []
                for _ in range(8000):
                    cycle = []
                    cycle.append(cycle)
                    junk.append(cycle)
                    if len(junk) > 2000:
                        junk.clear()
            finally:
                inside["value"] = False

        thread = threading.Thread(target=worker, name="WAM-wallet-owner")
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(seen, [])
        self.assertFalse(gc.isenabled())

    def test_headless_process_keeps_automatic_gc(self):
        proc = _child(
            "import gc\n"
            "import wam_regtest.wallet_executor\n"
            "assert gc.isenabled()\n"
            "print('HEADLESS_GC_ON')\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("HEADLESS_GC_ON", proc.stdout)

    def test_shutdown_qt_collects_on_the_main_thread_and_restores_gc(self):
        proc = _child(
            "import gc\n"
            "from PySide6.QtCore import QTimer\n"
            "from PySide6.QtWidgets import QLabel\n"
            "from wam_regtest.desktop import (\n"
            "    main_thread_gc_timer, qt_application, shutdown_qt)\n"
            "app = qt_application()\n"
            "assert gc.isenabled() is False\n"
            "assert main_thread_gc_timer().isActive()\n"
            "label = QLabel('bye')\n"
            "tick = QTimer()\n"
            "tick.start(20)\n"
            "node = [label, tick]\n"
            "node.append(node)\n"
            "del label, tick, node\n"
            "shutdown_qt()\n"
            "assert gc.isenabled() is True\n"
            "assert main_thread_gc_timer() is None\n"
            "print('PM027_SHUTDOWN_RESTORED')\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PM027_SHUTDOWN_RESTORED", proc.stdout)
        self.assertNotIn("another thread", proc.stderr)

    def test_worker_cyclic_qt_garbage_is_collected_on_the_main_thread(self):
        # Same objects that SIGSEGV when a worker thread collects them.
        # Automatic GC is off, so the worker's allocations must not destroy
        # them; the following main-thread collect must, without the warning.
        proc = _child(
            "import gc, sys, threading\n"
            "from PySide6.QtCore import QTimer, qInstallMessageHandler\n"
            "from PySide6.QtWidgets import QLabel\n"
            "from wam_regtest.desktop import qt_application, shutdown_qt\n"
            "warnings = []\n"
            "def handler(mode, context, message):\n"
            "    if 'another thread' in message:\n"
            "        warnings.append(message)\n"
            "qInstallMessageHandler(handler)\n"
            "qt_application()\n"
            "assert gc.isenabled() is False\n"
            "collected = []\n"
            "def callback(phase, info):\n"
            "    if phase == 'start':\n"
            "        collected.append(threading.current_thread().name)\n"
            "gc.callbacks.append(callback)\n"
            "label = QLabel('cycle')\n"
            "tick = QTimer()\n"
            "tick.start(30)\n"
            "node = [label, tick]\n"
            "node.append(node)\n"
            "del label, tick, node\n"
            "def worker():\n"
            "    junk = []\n"
            "    for _ in range(8000):\n"
            "        cycle = []\n"
            "        cycle.append(cycle)\n"
            "        junk.append(cycle)\n"
            "        if len(junk) > 2000:\n"
            "            junk.clear()\n"
            "thread = threading.Thread(target=worker, name='WAM-wallet-owner')\n"
            "thread.start()\n"
            "thread.join(5)\n"
            "assert not thread.is_alive()\n"
            "assert collected == []\n"
            "gc.collect()\n"
            "assert collected == ['MainThread']\n"
            "from PySide6.QtWidgets import QApplication\n"
            "QApplication.instance().processEvents()\n"
            "assert warnings == [], warnings\n"
            "shutdown_qt()\n"
            "assert gc.isenabled() is True\n"
            "if warnings:\n"
            "    print('\\n'.join(warnings), file=sys.stderr)\n"
            "    raise SystemExit(2)\n"
            "print('PM027_CROSS_THREAD_GC_SAFE')\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PM027_CROSS_THREAD_GC_SAFE", proc.stdout)
        self.assertNotIn("another thread", proc.stderr)


if __name__ == "__main__":
    unittest.main()
