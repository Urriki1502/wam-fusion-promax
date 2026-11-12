"""UI gallery: render every main Fusion screen and dialog for visual review.

Presentation fixture only (owner premium-UI directive, stage V0).
  * No backend, Core, Keychain, profile, network or wallet operation is
    started. The executor is an inert fixture, so no action can run.
  * Data is public fixture data: the published BIP39 test vector
    ("abandon" x11 + "about"), a derived REGTEST test payment code, and
    made-up history rows and amounts. No secret material exists here.
  * Every scene is rendered for every supported language, both themes and
    several window sizes. A PNG is written per scene, plus a JSON report of
    automatic layout findings: clipped or overflowing text, clipped buttons,
    horizontal scrolling.

The findings are review input, not acceptance. A human or peer still looks
at the images, and nothing here marks any G6 or owner acceptance.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

SIZES = ((900, 630), (1100, 720), (1440, 900))
THEMES = ((1, 'light'), (2, 'dark'))
TEST_VECTOR = ('abandon',) * 11 + ('about',)
TXIDS = tuple(hashlib.sha256(b'wam-ui-gallery-%d' % n).hexdigest() for n in range(4))


def _fixture_snapshot():
    from wam_sp.core import pub
    from wam_sp.keystore import ScanAccount
    from ..wallet_read import HistoryRow, WalletReadSnapshot
    code = ScanAccount(0, 1, pub(2), birthday=1).payment_code()
    history = (
        HistoryRow(TXIDS[0], 112, 1, 0, 25_010_000),
        HistoryRow(TXIDS[1], 108, 5, 50_000_000, 0),
        HistoryRow(TXIDS[2], 104, 9, 125_000_000, 0),
    )
    snap = WalletReadSnapshot(
        chain='regtest', height=112, tip=hashlib.sha256(b'tip').hexdigest(),
        receive_code=code, confirmed_atoms=149_990_000, confirmed_utxos=2,
        history=history, core_sha256=hashlib.sha256(b'core').hexdigest(),
        signer_allowed=True, broadcast_allowed=True, history_complete=True,
        history_count=len(history), receive_count=1, reservation_count=0,
        reservation_state_counts=())
    result = dict(fusion_snapshot=snap, receive_code=code,
                  confirmed_atoms=snap.confirmed_atoms, available_atoms=snap.confirmed_atoms,
                  signer_allowed=True, broadcast_allowed=True,
                  reservation_count=0, reservation_state_counts=())
    return snap, result


def _review():
    return SimpleNamespace(code=_fixture_snapshot()[0].receive_code, atoms=25_000_000,
                           fee=10_000, change_atoms=124_990_000, input_count=1)


def _renders_rich_text(widget):
    from PySide6.QtCore import Qt
    from PySide6.QtGui import Qt as GuiQt
    fmt = widget.textFormat()
    if fmt == Qt.TextFormat.RichText:
        return True
    return fmt == Qt.TextFormat.AutoText and GuiQt.mightBeRichText(widget.text())


def _label_text_size(widget, width):
    """(width, height) the label's text needs; width=None means no wrapping."""
    from PySide6.QtCore import QRect, Qt
    from PySide6.QtGui import QTextDocument
    text = widget.text()
    if _renders_rich_text(widget):
        doc = QTextDocument()
        doc.setDocumentMargin(0)
        doc.setDefaultFont(widget.font())
        doc.setHtml(text)
        if width is not None:
            doc.setTextWidth(max(1, width))
            return int(doc.idealWidth() + 0.999), int(doc.size().height() + 0.999)
        return int(doc.idealWidth() + 0.999), int(doc.size().height() + 0.999)
    flags = int(Qt.TextFlag.TextWordWrap) if width is not None else 0
    bounds = widget.fontMetrics().boundingRect(
        QRect(0, 0, max(1, width if width is not None else 100000), 100000), flags, text)
    return bounds.width(), bounds.height()


def _button_needs(button):
    """(needed, available) content width of a push button, check box or radio
    button, from the style's own content rectangle; None for other buttons.
    A preferred sizeHint wider than the button is not clipping by itself."""
    from PySide6.QtWidgets import (QCheckBox, QPushButton, QRadioButton, QStyle,
                                   QStyleOptionButton)
    if isinstance(button, QPushButton):
        element = QStyle.SubElement.SE_PushButtonContents
    elif isinstance(button, QCheckBox):
        element = QStyle.SubElement.SE_CheckBoxContents
    elif isinstance(button, QRadioButton):
        element = QStyle.SubElement.SE_RadioButtonContents
    else:
        return None
    option = QStyleOptionButton()
    button.initStyleOption(option)
    content = button.style().subElementRect(element, option, button)
    need = button.fontMetrics().horizontalAdvance(button.text().replace('&&', '\0').replace('&', '').replace('\0', '&'))
    if not button.icon().isNull():
        need += button.iconSize().width() + 4
    return need, content.width()


def _inspect(root, scene, findings):
    """Automatic layout findings for every visible text widget under root.

    Review input only. Findings: H_SCROLL (any scroll area, table or text
    view that scrolls horizontally), TEXT_CLIPPED_V / TEXT_CLIPPED_H (label
    text taller or wider than its box), TEXT_OVERFLOW_H (wrapped text with an
    unbreakable run wider than its box), BUTTON_CLIPPED (button text and icon
    wider than the style's content rectangle).
    """
    from PySide6.QtWidgets import QAbstractButton, QAbstractScrollArea, QHeaderView, QLabel
    for area in root.findChildren(QAbstractScrollArea):
        # Header views are scroll areas that mirror their table; the table
        # itself is reported, so headers are skipped to avoid duplicates.
        if isinstance(area, QHeaderView) or not area.isVisible():
            continue
        if area.horizontalScrollBar().maximum() > 0:
            findings.append(dict(scene=scene, kind='H_SCROLL',
                                 widget=area.objectName() or type(area).__name__,
                                 overflow=area.horizontalScrollBar().maximum()))
    for widget in root.findChildren(QLabel):
        text = widget.text()
        if not widget.isVisible() or not text or widget.pixmap() is not None and not widget.pixmap().isNull():
            continue
        rect = widget.contentsRect()
        name = widget.objectName()
        if widget.wordWrap():
            need_w, need_h = _label_text_size(widget, rect.width())
            if need_h > rect.height() + 1:
                findings.append(dict(scene=scene, kind='TEXT_CLIPPED_V', widget=name,
                                     text=text[:80], need=need_h, have=rect.height()))
            if need_w > rect.width() + 1:
                findings.append(dict(scene=scene, kind='TEXT_OVERFLOW_H', widget=name,
                                     text=text[:80], need=need_w, have=rect.width()))
        else:
            need_w, need_h = _label_text_size(widget, None)
            if need_w > rect.width() + 1:
                findings.append(dict(scene=scene, kind='TEXT_CLIPPED_H', widget=name,
                                     text=text[:80], need=need_w, have=rect.width()))
            if need_h > rect.height() + 1:
                findings.append(dict(scene=scene, kind='TEXT_CLIPPED_V', widget=name,
                                     text=text[:80], need=need_h, have=rect.height()))
    for button in root.findChildren(QAbstractButton):
        if not button.isVisible() or not button.text():
            continue
        measured = _button_needs(button)
        if measured is not None and measured[0] > measured[1] + 1:
            findings.append(dict(scene=scene, kind='BUTTON_CLIPPED', widget=button.objectName(),
                                 text=button.text()[:60], need=measured[0], have=measured[1]))


def render_gallery(output, languages=None, sizes=SIZES, themes=THEMES):
    from PySide6.QtCore import QCoreApplication, QEvent
    from ..desktop import qt_application
    from ..presentation.strings import SUPPORTED_LANGUAGES
    from ..ui_settings import native_store_enabled, ui_settings
    from ..wallet_executor import ExecutorState

    if native_store_enabled():
        # Only shipped production entries enable the owner's real store; the
        # gallery must never write the owner's UI preferences.
        raise RuntimeError('UI_GALLERY_NATIVE_STORE_DENIED')
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=False)
    settings_dir = tempfile.mkdtemp(prefix='wam-ui-gallery-')
    settings_path = os.path.join(settings_dir, 'ui-settings.ini')
    previous = os.environ.get('WAM_UI_SETTINGS_PATH')
    os.environ['WAM_UI_SETTINGS_PATH'] = settings_path  # isolated; never the real store
    app = qt_application()
    findings, scenes = [], []

    def settle():
        for _ in range(10):
            app.processEvents()
            time.sleep(0.01)

    def shoot(widget, name):
        path = destination / (name + '.png')
        assert widget.grab().save(str(path)), name
        scenes.append(name)

    try:
        for language in (languages or SUPPORTED_LANGUAGES):
            store = ui_settings()  # isolated INI: WAM_UI_SETTINGS_PATH set above
            store.setValue('ui_language', language)
            store.sync()
            for width, height in sizes:
                for theme_index, theme in themes:
                    _render_window(language, width, height, theme_index, theme,
                                   shoot, settle, findings, ExecutorState)
    finally:
        if previous is None:
            os.environ.pop('WAM_UI_SETTINGS_PATH', None)
        else:
            os.environ['WAM_UI_SETTINGS_PATH'] = previous
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    report = dict(status='UI_GALLERY_RENDERED', qt_platform=app.platformName(),
                  frozen=bool(getattr(sys, 'frozen', False)),
                  backend_or_core_started=False, wallet_or_transaction_acceptance=False,
                  g6_or_owner_acceptance=False, scene_count=len(scenes),
                  finding_count=len(findings), scenes=scenes, findings=findings)
    (destination / 'gallery.json').write_text(json.dumps(report, indent=1, ensure_ascii=False) + '\n')
    return report


def _render_window(language, width, height, theme_index, theme, shoot, settle, findings,
                   ExecutorState):
    from PySide6.QtCore import QCoreApplication, QEvent, Qt
    from ..bip39_backup_page import BackupLeaveConfirm
    from ..bip39_fusion_gui import Bip39FusionWindow
    from ..bip39_locale import t
    from ..fusion_pages import PaymentApproval, WalletConsent
    from ..gui_errors import error_text

    executor = SimpleNamespace(state=ExecutorState(locked=False, faulted=False, core_alive=True),
                               busy=False, closed=False)
    window = Bip39FusionWindow(executor)
    window._poll.stop()  # inert: no executor polling, quit handling or commands
    window.reduce_motion.setChecked(True)
    tag = f'{language}-{width}x{height}-{theme}'

    def scene(name, root=None):
        settle()
        full = f'{name}--{tag}'
        _inspect(root or window, full, findings)
        shoot(root or window, full)

    try:
        window.resize(width, height)
        window.show()
        window.appearance_buttons[theme_index].click()
        settle()
        # Locked / not yet opened: the state every session starts in.
        window.navigation.setCurrentRow(0)
        scene('01-overview-locked')
        _snap, result = _fixture_snapshot()
        window._ready = True
        window._spend_enabled = True
        window._render_verified(result)
        window._set_actions()
        window.status.setText(t('owner.seed_opened'))
        for row, name in ((0, '02-overview'), (1, '03-receive'), (2, '04-history'),
                          (3, '05-send'), (4, '06-security'), (5, '07-network'),
                          (6, '08-settings')):
            window.navigation.setCurrentRow(row)
            scene(name)
        window.advanced_toggle.setChecked(True)
        scene('09-settings-advanced')
        window.advanced_toggle.setChecked(False)
        window.navigation.setCurrentRow(2)
        window.history_page.table.selectRow(0)
        scene('10-history-detail')
        window.navigation.setCurrentRow(0)
        window.status.setText(t('owner.refused_prefix') + error_text('WALLET_UNLOCK_REFUSED'))
        scene('11-status-refusal')
        window.status.setText('')
        # Backup flow: public test vector only.
        window.navigation.clearSelection()
        window.stack.setCurrentWidget(window.backup_page)
        window.backup_page.set_phrase(TEST_VECTOR)
        scene('12-backup-words')
        window.backup_page.set_challenge(dict(challenge_id='ab' * 32, positions=(2, 7, 11)))
        window.backup_page._stack.setCurrentWidget(window.backup_page._verify_page)
        scene('13-backup-verify')
        window.backup_page._stack.setCurrentWidget(window.backup_page._success_page)
        scene('14-backup-success')
        # Dialogs, shown non-modally so they can be captured; never accepted.
        dialogs = (
            ('15-dialog-consent', lambda: WalletConsent(t('wallet.backup_title'),
                                                        t('wallet.backup_explanation'), window,
                                                        accept_text=t('wallet.verify_words'))),
            ('16-dialog-unlock', lambda: WalletConsent(t('owner.password_title'),
                                                       t('owner.password_prompt'), window,
                                                       password=True)),
            ('17-dialog-sign', lambda: PaymentApproval(_review(), 'sign', window)),
            ('18-dialog-broadcast', lambda: PaymentApproval(_review(), 'broadcast', window)),
            ('19-dialog-leave-backup', lambda: BackupLeaveConfirm(window)),
        )
        for name, make in dialogs:
            dialog = make()
            dialog.setWindowModality(Qt.WindowModality.NonModal)
            dialog.show()
            scene(name, dialog)
            dialog.reject()
            dialog.deleteLater()
    finally:
        window._closed = True
        window.hide()
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def run(output='ui-gallery'):
    from ..desktop import shutdown_qt
    try:
        report = render_gallery(output)
        print('UI_GALLERY_RENDERED scenes=%d findings=%d platform=%s frozen=%s' % (
            report['scene_count'], report['finding_count'], report['qt_platform'],
            report['frozen']), flush=True)
        return 0
    finally:
        shutdown_qt()


if __name__ == '__main__':
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else 'ui-gallery'))
