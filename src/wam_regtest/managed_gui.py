"""Qt bridge to a persistent wallet owner thread; no live session on Qt workers."""
from PySide6.QtCore import QEvent,QObject,QThread,QTimer,Qt,Signal
from PySide6.QtWidgets import QMenu,QMessageBox,QSystemTrayIcon

from .operational_gui import OperationalWalletWindow,qt_application
from .wallet_executor import ManagedWalletBackend,ManagedWalletProxy,WalletExecutor
from .gui_errors import operation_error,public_code
from .bip39_locale import t
from .bip39_backup_page import get_secret_text
from .quit_lifecycle_gui import QuitLifecycleMixin


class ControlWorker(QThread):
    ready=Signal(str,object)
    denied=Signal(str)
    pending=Signal(str)
    def __init__(self,executor,action,args=(),kwargs=None,parent=None):
        super().__init__(parent)
        self.executor=executor;self.action=action;self.args=args;self.kwargs=kwargs or {}
    def run(self):
        try:
            from concurrent.futures import TimeoutError
            options = dict(self.kwargs)
            timeout = options.pop('timeout', 90)
            future = self.executor.submit(self.action, *self.args, **options)
            notified = False
            while True:
                try:
                    result = future.result(timeout=timeout)
                    break
                except TimeoutError:
                    if future.done():
                        raise  # Backend timeout is a failure, not a new wait.
                    if not notified:
                        self.pending.emit('WALLET_EXECUTOR_OPERATION_STILL_PENDING')
                        notified = True
                    # Keep the ORIGINAL Future. No cancellation, resubmission,
                    # RPC retry, reservation change or extra signing authority.
            self.ready.emit(self.action, result)
        except Exception as error:
            # Diagnostics keep the failing action and a PUBLIC-only raw cause
            # (code-shaped token or exception type name). Never message text.
            self.diagnostic_action = self.action
            from .gui_errors import raw_cause
            self.diagnostic_raw = raw_cause(error)
            self.denied.emit(operation_error(self.action,error))
        finally:self.args=();self.kwargs={}


class QuitFilter(QObject):
    def __init__(self,window):super().__init__(window);self.window=window
    def eventFilter(self,watched,event):
        if event.type()==QEvent.Type.Quit and not self.window.session.executor.closed:
            self.window.request_quit();return True
        return False


class ManagedWalletWindow(QuitLifecycleMixin,OperationalWalletWindow):
    owner_closed=Signal()
    def __init__(self,proxy):
        if type(proxy) is not ManagedWalletProxy:raise ValueError('MANAGED_GUI_PROXY_REQUIRED')
        self._close_requested=self._quit_requested=self._quit_completed=False
        self._after_control=None;self.background_available=False
        self._init_quit_lifecycle()
        super().__init__(proxy)
        self.setWindowTitle(t('managed.window_title'))
        self.warning.setText(t('managed.warning'))
        # Mining stays an explicit test/advanced tool, never normal onboarding.
        self.mine_button.hide()
        self.mine_notice.hide()
        menu=self.menuBar().addMenu(t('managed.menu'))
        menu.addAction(t('managed.verify_restart'),self.request_core_restart)
        menu.addAction(t('managed.stop_quit'),self.request_quit)
        self._executor_poll=QTimer(self);self._executor_poll.setInterval(100)
        self._executor_poll.timeout.connect(self._poll_owner);self._executor_poll.start()

    def _update_controls(self):
        super()._update_controls()
        if self.session.executor.busy or self._close_requested or self._quit_requested:
            for widget in getattr(self,'_actions',()):widget.setEnabled(False)
            for name in ('refresh_button','prepare_button','sign_button','broadcast_button',
                         'cancel_button','backup_button','lock_button','unlock_button','recover_button'):
                widget=getattr(self,name,None)
                if widget is not None:widget.setEnabled(False)

    def request_sync(self):
        if self.session.executor.busy:return
        super().request_sync()

    def _history_page(self,offset):
        if self.session.executor.busy:return
        super()._history_page(offset)

    def _control(self,action,*args,**kwargs):
        if self._worker is not None or self.session.executor.busy:return False
        worker=ControlWorker(self.session.executor,action,args,kwargs,self)
        self._worker=worker
        worker.ready.connect(self._control_ready,Qt.ConnectionType.QueuedConnection)
        worker.denied.connect(self._control_denied,Qt.ConnectionType.QueuedConnection)
        worker.finished.connect(self._worker_finished)
        worker.finished.connect(worker.deleteLater)
        self._update_controls();worker.start();return True

    def open_wallet(self,password,*,create=False):
        return self._control('open',password,create=create)

    def _quit_executor(self):
        return self.session.executor

    def _submit_quit_action(self,action,*args):
        return self._control(action,*args)

    def _on_runtime_preserved_ack(self):
        self._poll_owner()

    def _control_ready(self,action,result):
        if action=='open':
            self._unresolved_quit_notices=()
            self.apply_snapshot(result);self.status.setText(t('managed.ready'))
        elif action=='lock' and self._close_requested:
            self._close_requested=False
            self.review=None;self.signed=False;self._submitted_txid=None
            self._clear_balance()
            if self.background_available:self.hide()
            else:self.showMinimized()  # Keep a reachable window if no tray exists.
        elif action=='quit_notices':
            self._unresolved_quit_notices=tuple(result.get('notices') or ()) if isinstance(result,dict) else ()
            self._present_unresolved_quit_notices()
        elif action=='acknowledge_quit_notices':
            self._unresolved_quit_notices=();self._quit_notice_dialog=None
            self.status.setText(t('quit_lifecycle.unresolved_acked_status'))
        elif action=='retry_quit_notice':
            self._notice_persist_failed=False
            if isinstance(result,dict) and result.get('recorded') is True and result.get('core_alive') is False:
                self._quit_requested=True
            else:
                self.status.setText(t('quit_lifecycle.status_blocked_live'))
        elif action=='quit_ack_unrecorded':
            self._close_transient_quit_dialogs()
            self._notice_persist_failed=False;self._runtime_preserved_acknowledged=True
            self._quit_completed=True
        elif action=='quit':
            self._close_transient_quit_dialogs()
            self._quit_completed=True
            if isinstance(result,dict) and result.get('runtime_preserved') is True and not self._runtime_preserved_acknowledged:
                self.status.setText(t('quit_lifecycle.runtime_preserved_title'))
        elif action=='core_restart':
            self._close_quit_dialog('_dead_owner_dialog')
            self.review=None;self.signed=False;self._submitted_txid=None
            self._clear_balance();self.status.setText(t('managed.core_restarted'))
        elif action=='recovery_status':
            self._after_control=lambda:self._approve_recovery(result['pending_action'])
        elif action in ('recover','complete_recovery'):
            self._clear_balance();self.status.setText(t('managed.recovery_completed'))
        self._update_controls()

    def _control_denied(self,reason):
        code=public_code(reason)
        self._close_requested=self._quit_requested=False;self._after_control=None
        self._operation_denied(code)
        if code=='QUIT_NOTICE_REVIEW_REQUIRED':
            self._after_control=lambda:self._control('quit_notices')
        elif code=='NOTICE_PERSIST_FAILED':
            self._notice_persist_failed=True
            self._present_notice_persist_failed()
        elif code=='MANAGED_DEAD_OWNER_RECOVERY_REQUIRED':
            self._present_dead_owner_recovery()

    def _worker_finished(self):
        super()._worker_finished()
        if self._after_control is not None:
            after=self._after_control;self._after_control=None;QTimer.singleShot(0,after)
        self._poll_owner()

    def _poll_owner(self):
        self._update_controls()
        if self._worker is not None or self.session.executor.busy or self._approval_open:return
        executor=self.session.executor
        if executor.closed:
            self._close_transient_quit_dialogs()
            if executor.state.runtime_preserved is True and not self._runtime_preserved_acknowledged:
                self._present_runtime_preserved_ack();return
            if executor.join(0):
                self._executor_poll.stop()
                self.owner_closed.emit()
                from PySide6.QtWidgets import QApplication
                QApplication.instance().quit()
        elif self._quit_requested:self._control('quit')
        elif self._close_requested:self._control('lock')

    def closeEvent(self,event):
        executor=self.session.executor
        if executor.closed:
            self._close_transient_quit_dialogs()
            if executor.state.runtime_preserved is True and not self._runtime_preserved_acknowledged:
                event.ignore();self._present_runtime_preserved_ack();return
            event.accept();return
        event.ignore()
        if self._notice_persist_failed:
            self._present_notice_persist_failed();return
        self._close_requested=True
        self.status.setText(t('managed.locking'))
        self._poll_owner()

    def reopen(self):
        if self.session.executor.closed:return
        self._close_requested=False;self.showNormal();self.raise_();self.activateWindow()

    def request_quit(self):
        if self._notice_persist_failed:
            self._present_notice_persist_failed();return
        self._quit_requested=True;self._close_requested=False
        self.status.setText(t('managed.finishing_shutdown'))
        self._poll_owner()

    def recover_wallet(self):
        if self._worker is not None or self.session.executor.busy:return
        self._control('recovery_status')

    def request_core_restart(self):
        if self._worker is not None or self.session.executor.busy or self._approval_open:return False
        self._approval_open=True
        try:
            answer=QMessageBox.question(self,t('managed.restart_title'),
                t('managed.restart_body'),
                QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
        finally:self._approval_open=False
        if answer!=QMessageBox.StandardButton.Yes:return False
        return self._control('core_restart')

    def _approve_recovery(self,action):
        self._approval_open=True
        try:
            text=(t('managed.recovery_complete_prompt') if action else
                  t('managed.recovery_fresh_prompt'))
            if QMessageBox.question(self,t('managed.recovery_title'),text,
                    QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes:return
            password=self._passphrase(t('managed.authenticate_checkpoint'))
            if password is None:return
        finally:self._approval_open=False
        if action:self._control('complete_recovery',password,action)
        else:self._control('recover',password)


def launch_managed(root,core,source,*,authorized=False,create=False,keychain=None,
                   _backend_factory=None,_window_hook=None):
    if authorized is not True:raise ValueError('MANAGED_EXPLICIT_CONSENT_REQUIRED')
    app=qt_application();app.setQuitOnLastWindowClosed(False)
    factory=_backend_factory or (lambda:ManagedWalletBackend(root,core,source,keychain=keychain))
    executor=WalletExecutor(factory)
    proxy=ManagedWalletProxy(executor,root,core,source);window=ManagedWalletWindow(proxy)
    window._quit_filter=QuitFilter(window);app.installEventFilter(window._quit_filter)
    tray=None
    if QSystemTrayIcon.isSystemTrayAvailable():
        tray=QSystemTrayIcon(window.windowIcon(),window);menu=QMenu()
        menu.addAction(t('managed.open_wallet'),window.reopen)
        menu.addAction(t('managed.stop_quit'),window.request_quit)
        tray.setContextMenu(menu);tray.show();window.background_available=True
    window.show()
    if _window_hook is not None:_window_hook(window)
    while True:
        password,ok=get_secret_text(window,t('managed.passphrase_title'),
            t('managed.passphrase_prompt'))
        if not ok or 12<=len(password.encode())<=1024:break
        QMessageBox.warning(window,t('managed.passphrase_warning_title'),t('managed.passphrase_warning'))
    if ok:window.open_wallet(password.encode(),create=create)
    else:window.request_quit()
    password=''
    result=app.exec() if (not executor.closed or (
        executor.state.runtime_preserved is True
        and not window._runtime_preserved_acknowledged)) else 0
    # A normal Qt quit must have positive owner shutdown. An unexpected event
    # loop exit retains the non-daemon owner thread; never kill guessed PIDs.
    if not executor.closed:raise ValueError('MANAGED_OWNER_STILL_ACTIVE')
    executor.join();return result
