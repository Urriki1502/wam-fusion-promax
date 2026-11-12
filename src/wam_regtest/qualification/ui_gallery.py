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


def _inspect(root, scene, findings):
    """Automatic layout findings for every visible text widget under root."""
    from PySide6.QtCore import QRect, Qt
    from PySide6.QtWidgets import QAbstractButton, QLabel, QScrollArea
    for area in root.findChildren(QScrollArea):
        if area.isVisible() and area.horizontalScrollBar().maximum() > 0:
            findings.append(dict(scene=scene, kind='H_SCROLL', widget=area.objectName() or 'QScrollArea',
                                 overflow=area.horizontalScrollBar().maximum()))
    for widget in root.findChildren(QLabel):
        text = widget.text()
        if not widget.isVisible() or not text or widget.pixmap() is not None and not widget.pixmap().isNull():
            continue
        rect = widget.contentsRect()
        metrics = widget.fontMetrics()
        if widget.wordWrap():
            bounds = metrics.boundingRect(QRect(0, 0, max(1, rect.width()), 100000),
                                          int(Qt.TextFlag.TextWordWrap), text)
            if bounds.height() > rect.height() + 1:
                findings.append(dict(scene=scene, kind='TEXT_CLIPPED_V', widget=widget.objectName(),
                                     text=text[:80], need=bounds.height(), have=rect.height()))
            if bounds.width() > rect.width() + 1:
                findings.append(dict(scene=scene, kind='TEXT_OVERFLOW_H', widget=widget.objectName(),
                                     text=text[:80], need=bounds.width(), have=rect.width()))
        else:
            need = max((metrics.horizontalAdvance(line) for line in text.split('\n')), default=0)
            if need > rect.width() + 1:
                findings.append(dict(scene=scene, kind='TEXT_CLIPPED_H', widget=widget.objectName(),
                                     text=text[:80], need=need, have=rect.width()))
    for button in root.findChildren(QAbstractButton):
        if not button.isVisible() or not button.text():
            continue
        if button.sizeHint().width() > button.width() + 1:
            findings.append(dict(scene=scene, kind='BUTTON_CLIPPED', widget=button.objectName(),
                                 text=button.text()[:60], need=button.sizeHint().width(),
                                 have=button.width()))


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
