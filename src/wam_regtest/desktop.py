"""Native Qt macOS REGTEST view, reading *real* Core/WSP state.

The baseline view is read-only; the operational subclass adds gated payments. Core is a separately running, verified
v0.1.13 regtest daemon. All balances/history are cleared on RPC failure.
A Qt worker runs live WSP Scanner.sync off the GUI thread.
"""
from __future__ import annotations

import gc
import sys
import threading
from datetime import datetime
from pathlib import Path
from PySide6.QtCore import QEvent, QThread, QTimer, Signal, Qt
from PySide6.QtGui import QFont, QFontDatabase, QPainter, QColor, QPen, QPixmap, QIcon
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel,
    QListWidget, QListWidgetItem, QMainWindow, QPushButton, QStackedWidget,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .wallet_read import WalletReadSnapshot, read_real_wallet_snapshot, format_wam
from .branding import brand_image
from .fusion_ui import FusionOverview, fusion_palette, fusion_stylesheet, nav_icon_for, vector_icon, label, action
from .fusion_pages import ReceivePage, HistoryPage
from .infrastructure import core_compat
from .bip39_locale import t


_QT_APPLICATION = None
# CPython's cyclic collector runs on whichever thread allocated. In a GUI
# process that thread may be WAM-wallet-owner or a QThread, and a pass can
# destroy PySide wrappers off the Qt thread (W-GC-THREAD). While a
# QApplication exists, automatic collection is disabled and this timer is the
# only collector. Headless processes never call qt_application(), so they keep
# the normal collector. 1.5s is inside the 1–2s bound; generation thresholds
# still decide whether a tick does any work.
_MAIN_THREAD_GC_INTERVAL_MS = 1500
_GC_TIMER = None
_GC_PRIOR_ENABLED = None
_GC_COLLECTING = False


def _due_gc_generation():
    counts = gc.get_count()
    thresholds = gc.get_threshold()
    due = None
    for generation, (count, threshold) in enumerate(zip(counts, thresholds)):
        if threshold > 0 and count >= threshold:
            due = generation
    return due


def _collect_cyclic_garbage(*, force=False):
    """Collect cyclic garbage on the Qt main thread. No-op on any other thread."""
    global _GC_COLLECTING
    if threading.current_thread() is not threading.main_thread() or _GC_COLLECTING:
        return
    generation = None
    if not force:
        generation = _due_gc_generation()
        if generation is None:
            return
    _GC_COLLECTING = True
    try:
        if force:
            gc.collect()
        else:
            gc.collect(generation)
    finally:
        _GC_COLLECTING = False


def _on_main_thread_gc_timer():
    _collect_cyclic_garbage(force=False)


def _ensure_main_thread_gc(app):
    global _GC_TIMER, _GC_PRIOR_ENABLED
    if _GC_TIMER is not None:
        return
    # The timer has to be created on the GUI thread or its slot would run
    # elsewhere. Refuse to disarm the collector until that is true.
    if threading.current_thread() is not threading.main_thread():
        return
    # Remember the caller's state so shutdown can put a headless continuation
    # back, and so a process that had already disabled GC stays disabled.
    if _GC_PRIOR_ENABLED is None:
        _GC_PRIOR_ENABLED = gc.isenabled()
    gc.disable()
    timer = QTimer(app)
    timer.setObjectName("wam-main-thread-gc")
    timer.setInterval(_MAIN_THREAD_GC_INTERVAL_MS)
    timer.timeout.connect(_on_main_thread_gc_timer)
    timer.start()
    _GC_TIMER = timer


def main_thread_gc_timer():
    """The main-thread cyclic collector, or None before the GUI exists."""
    return _GC_TIMER


def qt_application():
    # Qt allows one QApplication lifetime per process. Keep it alive across
    # baseline and operational probes; destroying/recreating it can crash.
    # Production entries, the qualification app and source GUI runs all obtain
    # the QApplication here, so this is the one process-level GC gate.
    global _QT_APPLICATION
    if _QT_APPLICATION is None:
        _QT_APPLICATION = QApplication.instance() or QApplication([])
        families=set(QFontDatabase.families())
        preferred={'win32':('Segoe UI','Arial'),'darwin':('Helvetica Neue','Avenir Next','Arial')}.get(sys.platform,('Noto Sans','DejaVu Sans','Liberation Sans'))
        family=next((f for f in preferred if f in families),None)
        if family:_QT_APPLICATION.setFont(QFont(family,11))
        _QT_APPLICATION.setWindowIcon(QIcon(str(brand_image())))
        _QT_APPLICATION.setApplicationDisplayName("WAM Privacy Wallet REGTEST")
    _ensure_main_thread_gc(_QT_APPLICATION)
    return _QT_APPLICATION


def shutdown_qt():
    global _QT_APPLICATION, _GC_TIMER, _GC_PRIOR_ENABLED
    app = _QT_APPLICATION
    if app is None:
        return
    app.closeAllWindows()
    app.processEvents()
    # Collect while QApplication is still alive and this is the GUI thread,
    # so Shiboken runs QObject destructors here. Then restore automatic GC
    # only after those objects are gone.
    if threading.current_thread() is threading.main_thread():
        timer = _GC_TIMER
        _GC_TIMER = None
        if timer is not None:
            timer.stop()
        _collect_cyclic_garbage(force=True)
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        app.processEvents()
    app.shutdown()
    _QT_APPLICATION = None
    _GC_TIMER = None
    if threading.current_thread() is threading.main_thread():
        prior = _GC_PRIOR_ENABLED
        _GC_PRIOR_ENABLED = None
        if prior:
            gc.enable()


def _wallet_icons(tone: str) -> tuple[QIcon, ...]:
    icons = []
    for which in range(3):
        pix = QPixmap(40, 40)
        pix.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pix)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor(tone), 2.4))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        if which == 0:  # download arrow
            painter.drawLine(20, 7, 20, 27)
            painter.drawLine(11, 19, 20, 28)
            painter.drawLine(29, 19, 20, 28)
            painter.drawLine(8, 33, 32, 33)
        elif which == 1:  # wallet
            painter.drawRoundedRect(6, 10, 28, 21, 4, 4)
            painter.drawRoundedRect(24, 17, 14, 9, 3, 3)
            painter.drawPoint(30, 21)
        else:  # clock/history
            painter.drawEllipse(7, 7, 26, 26)
            painter.drawLine(20, 12, 20, 21)
            painter.drawLine(20, 21, 27, 25)
        painter.end()
        icons.append(QIcon(pix))
    return tuple(icons)


def resolve_theme(mode: str, local_time: datetime) -> str:
    if (type(mode) is not str or mode not in ("auto", "light", "dark")
            or type(local_time) is not datetime
            or local_time.tzinfo is None or local_time.utcoffset() is None):
        raise ValueError("REGTEST_GUI_THEME_DENIED")
    if mode == "auto":
        return "light" if 6 <= local_time.hour < 18 else "dark"
    return mode


class _ReadWorker(QThread):
    ready = Signal(object)
    denied = Signal(str)

    def __init__(self, core_dir: Path, datadir: Path, source: Path, session=None,
                 history_offset=0):
        super().__init__()
        self._core_dir, self._datadir, self._source = core_dir, datadir, source
        self.session = session
        self._history_offset = history_offset

    def run(self):
        try:
            result = (self.session.snapshot(history_offset=self._history_offset)
                      if self.session is not None else
                      read_real_wallet_snapshot(self._core_dir, self._datadir, self._source,
                                                history_offset=self._history_offset))
            self.ready.emit(result)
        except Exception as error:
            # Never forward external RPC messages, paths or private data.
            from .gui_errors import operation_error
            self.denied.emit(operation_error('sync',error))


class RegtestWalletWindow(QMainWindow):
    """Real read-only balance; no signer/send controls exist."""
    snapshot_updated = Signal(object)
    snapshot_failed = Signal(str)

    def __init__(self, core_dir: Path, datadir: Path, source: Path, *, session=None):
        super().__init__()
        self.session = session
        self._core_dir, self._datadir, self._source = core_dir, datadir, source
        self._worker = None
        self._snapshot = None
        self._history_offset = 0
        self.setWindowTitle(t("desktop.window_title"))
        self.setWindowIcon(QIcon(str(brand_image())))
        self.setMinimumSize(820,600)
        self.resize(1280,800)
        base=QWidget();base.setObjectName('WalletRoot');self.setCentralWidget(base)
        shell=QHBoxLayout(base);shell.setContentsMargins(0,0,0,0);shell.setSpacing(0)
        sidebar=QFrame();sidebar.setObjectName('FusionSidebar');sidebar.setFixedWidth(214)
        side=QVBoxLayout(sidebar);side.setContentsMargins(18,26,18,20);side.setSpacing(20)
        brand=QHBoxLayout();mark=QLabel();dpr=max(1.0,float(self.devicePixelRatioF()));logo=QPixmap(str(brand_image()));logo=logo.scaled(int(44*dpr),int(44*dpr),Qt.AspectRatioMode.KeepAspectRatio,Qt.TransformationMode.SmoothTransformation);logo.setDevicePixelRatio(dpr);mark.setPixmap(logo);mark.setFixedSize(44,44);brand.addWidget(mark)
        title=QVBoxLayout();        title.addWidget(label(t('desktop.brand_wam'),'BrandTitle'));title.addWidget(label(t('desktop.brand_version'),'FusionKicker'));brand.addLayout(title);brand.addStretch();side.addLayout(brand)
        side.addWidget(label(t('desktop.workspace_kicker'),'FusionKicker'))
        self.navigation=QListWidget();self.navigation.setIconSize(__import__('PySide6.QtCore',fromlist=['QSize']).QSize(22,22))
        self.navigation.addItems((t('fusion.overview'),t('fusion.receive'),t('fusion.history')));side.addWidget(self.navigation,1)
        side.addWidget(label(t('desktop.regtest_badge'),'FusionBadge'))
        self.warning=label(t('desktop.demo_warning'),'Warning');side.addWidget(self.warning)
        side.addWidget(label(t('desktop.core_standards').format(display_name=core_compat.DISPLAY_NAME),'FusionMuted'));shell.addWidget(sidebar)
        workspace=QWidget();workspace.setObjectName('FusionTransparent');col=QVBoxLayout(workspace);col.setContentsMargins(28,0,22,12);col.setSpacing(18)
        topbar=QFrame();topbar.setObjectName('FusionTopbar');top=QHBoxLayout(topbar);top.setContentsMargins(0,18,0,18)
        self.workspace_title=label(t('desktop.privacy_wallet'),'FusionCardTitle');top.addWidget(self.workspace_title);top.addStretch()
        self.verification_badge=label(t('fusion.not_verified'),'FusionBadge');top.addWidget(self.verification_badge)
        self.appearance=QComboBox()
        for text,value in ((t('desktop.appearance_auto'),'auto'),(t('desktop.appearance_light'),'light'),(t('desktop.appearance_dark'),'dark')):self.appearance.addItem(text,value)
        top.addWidget(self.appearance);self.refresh_button=action(t('desktop.sync_live'),'sync');top.addWidget(self.refresh_button);col.addWidget(topbar)
        self.stack=QStackedWidget();col.addWidget(self.stack,1)
        self.dashboard=FusionOverview();self.balance_text=self.dashboard.balance_value;self.utxo_text=self.dashboard.utxo_details;self.stack.addWidget(self.dashboard)
        self.receive_page=ReceivePage();self.receive_code=self.receive_page.receive_code;self.stack.addWidget(self.receive_page)
        self.history_page=HistoryPage();self.history_table=self.history_page.table;self.history_page.page_requested.connect(self._history_page);self.stack.addWidget(self.history_page)
        self.status=label(t('desktop.not_synced'),'StatusText');col.addWidget(self.status);shell.addWidget(workspace,1)
        self.navigation.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.navigation.currentRowChanged.connect(lambda i:self.workspace_title.setText((t('fusion.overview'),t('fusion.receive'),t('fusion.history'),t('fusion.send'),t('fusion.security'),t('fusion.settings'))[i] if 0<=i<6 else t('desktop.privacy_wallet')))
        self.navigation.setCurrentRow(0);self.refresh_button.clicked.connect(self.request_sync);self.appearance.currentIndexChanged.connect(self.apply_theme)
        self.dashboard.go_receive.clicked.connect(lambda:self.navigation.setCurrentRow(1));self.dashboard.open_history.clicked.connect(lambda:self.navigation.setCurrentRow(2));self.dashboard.manual_sync.clicked.connect(self.request_sync)
        self.dashboard.transaction_selected.connect(self._open_transaction)

        self._theme_timer = QTimer(self)
        self._theme_timer.setInterval(60_000)
        self._theme_timer.timeout.connect(self.apply_theme)
        self._theme_timer.start()
        self._sync_timer = QTimer(self)
        self._sync_timer.setInterval(30_000)
        self._sync_timer.timeout.connect(self.request_sync)
        self._sync_timer.start()
        QApplication.styleHints().colorSchemeChanged.connect(self.apply_theme)
        self._appearance_connected = True
        self.apply_theme()

    def apply_theme(self, *_):
        local = datetime.now().astimezone()
        active = resolve_theme(self.appearance.currentData(), local)
        if self.appearance.currentData() == "auto":
            scheme = QApplication.styleHints().colorScheme()
            if scheme == Qt.ColorScheme.Dark:
                active = "dark"
            elif scheme == Qt.ColorScheme.Light:
                active = "light"
        c = fusion_palette(active)
        self.setStyleSheet(fusion_stylesheet(active))
        self._active_theme=active
        self.dashboard.set_theme(active)
        self.history_page.set_theme(active)
        for button in self.findChildren(QPushButton):
            name=button.property("fusion_icon")
            if name:button.setIcon(vector_icon(name,c["onaccent"] if button.objectName() in ("FusionPrimary","PrimaryButton") else c["accent"],self.devicePixelRatioF()))
        for icon_label in self.findChildren(QLabel):
            name=icon_label.property("fusion_icon_label")
            if name:icon_label.setPixmap(vector_icon(name,c["accent"],self.devicePixelRatioF()).pixmap(24,24))
        for index in range(self.navigation.count()):
            item = self.navigation.item(index)
            item.setIcon(nav_icon_for(item.text(), c["accent"], self.devicePixelRatioF()))

    def request_sync(self):
        if self._worker is not None:
            return
        self.refresh_button.setEnabled(False)
        self.status.setText(t("desktop.verifying_core"))
        worker = _ReadWorker(self._core_dir, self._datadir, self._source, self.session,
                             history_offset=self._history_offset)
        self._worker = worker
        worker.ready.connect(self.apply_snapshot)
        worker.denied.connect(self._sync_failed)
        worker.finished.connect(self._worker_finished)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _worker_finished(self):
        self._worker = None
        self.refresh_button.setEnabled(True)

    def _clear_balance(self):
        self._snapshot = None
        self.receive_page.render_snapshot(None)
        self.history_page.render_snapshot(None)
        self.balance_text.setText('—');self.utxo_text.setText(t('desktop.unverified_scan'))
        self.verification_badge.setText(t('fusion.not_verified'))
        self.dashboard.render_snapshot(None, locked=bool(
            self.session is not None and (self.session.locked or self.session.faulted)
        ))

    def _sync_failed(self, reason: str):
        from .gui_errors import error_text,public_code
        reason=public_code(reason,fallback='WALLET_SYNC_UNVERIFIED')
        self._clear_balance()
        self.status.setText(error_text(reason,fallback='WALLET_SYNC_UNVERIFIED'))
        self.snapshot_failed.emit(reason)

    def apply_snapshot(self, snap: WalletReadSnapshot):
        if (type(snap) is not WalletReadSnapshot or snap.chain != "regtest"
                or not snap.demo_account_only or snap.synthetic_rpc
                or snap.signer_allowed is not (self.session is not None)
                or snap.broadcast_allowed is not (self.session is not None)
                or snap.mainnet_allowed):
            self._sync_failed("REGTEST_UNTRUSTED_SNAPSHOT_DENIED")
            return
        self._snapshot = snap
        try:
            self.receive_page.render_snapshot(snap)
            self.history_page.render_snapshot(snap)
        except (TypeError,ValueError):
            self._sync_failed('FUSION_UNTRUSTED_RECEIVE_DENIED');return
        self.verification_badge.setText(t('desktop.core_verified').format(height=str(snap.height)))
        self.status.setText(
            (t('desktop.verified_disposable') if self.session is not None else t('desktop.verified_readonly')).format(
                height=snap.height, tip=snap.tip[:14]))
        try:
            from .domain.payment_state import read_only_reservation_lock_summary
            self.dashboard.render_snapshot(
                snap, operational=self.session is not None,
                reservation_lock_summary=(
                    None if self.session is not None else read_only_reservation_lock_summary()))
        except (TypeError, ValueError):
            self._sync_failed("FUSION_UNTRUSTED_HISTORY_DENIED")
            return
        self.snapshot_updated.emit(snap)

    def _open_transaction(self,txid):
        self.navigation.setCurrentRow(2)
        self.history_page.select_txid(txid)

    def _history_page(self,offset):
        if type(offset) is not int or offset<0 or self._worker is not None:
            return
        self._history_offset=offset
        self.request_sync()

    def closeEvent(self, event):
        if self._worker is not None:
            # Do not destroy a running QThread while Core RPC is in progress.
            event.ignore()
            self.status.setText(t("desktop.waiting_shutdown"))
            return
        self._theme_timer.stop()
        self._sync_timer.stop()
        if self._appearance_connected:
            QApplication.styleHints().colorSchemeChanged.disconnect(self.apply_theme)
            self._appearance_connected = False
        super().closeEvent(event)


def launch_readonly_wallet(core_dir: Path, datadir: Path, source: Path) -> int:
    app = qt_application()
    window = RegtestWalletWindow(core_dir, datadir, source)
    window.show()
    QTimer.singleShot(0, window.request_sync)
    # Do not destroy window or worker before app event loop returns.
    return app.exec()
