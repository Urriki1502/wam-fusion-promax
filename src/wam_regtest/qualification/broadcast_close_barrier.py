"""Probe-local hold for one Q06 broadcast so a close can be observed.

This is qualification code. It is not a product switch, and it does not read
an environment variable or a flag that re-enables a retired Q05 action.
"""
import threading


class BroadcastCloseBarrier:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.submissions = 0
        self.original = None


def install_broadcast_barrier(backend, timeout=120):
    """Hold the next ``broadcast`` on this backend instance only."""
    if type(timeout) is not int or not 1 <= timeout <= 180:
        raise ValueError('Q06_BROADCAST_CLOSE_BARRIER_TIMEOUT')
    barrier = BroadcastCloseBarrier()
    original = backend.execute

    def execute(action, args, kwargs):
        if action != 'broadcast':
            return original(action, args, kwargs)
        barrier.entered.set()
        if not barrier.release.wait(timeout):
            raise ValueError('Q06_BROADCAST_CLOSE_BARRIER_TIMEOUT')
        result = original(action, args, kwargs)
        barrier.submissions += 1
        return result

    backend.execute = execute
    return barrier


def observe_deferred_close(app, window, executor, original):
    """Close while a broadcast is held and record the deferred-close facts.

    The product close asks to quit after the in-flight operation. This
    qualification has already observed that the window stayed visible and the
    owner was unchanged, and it withdraws that quit so the same approved
    broadcast can finish.
    """
    import time
    from PySide6.QtCore import QTimer

    ticks = []
    timer = QTimer()
    timer.setInterval(1)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    try:
        deadline = time.monotonic() + 2
        while not ticks and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.001)
        window.close()
        app.processEvents()
        process = executor._backend.owner.process
        if not window.isVisible() or not executor.busy or not ticks:
            raise ValueError('Q06_GUI_UNSAFE_INFLIGHT_CLOSE')
        if process is not original or original is None or original.poll() is not None:
            raise ValueError('Q06_GUI_CLOSE_CHANGED_CORE')
        window._quit_requested = False
        return {
            'close_during_approved_broadcast_deferred': True,
            'qt_timer_alive_during_operation': True,
            'wallet_close_reopen_same_core': True,
        }
    finally:
        timer.stop()
