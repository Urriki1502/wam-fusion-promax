"""PM-103 inert Vietnamese presentation captures, not native/Core acceptance.

Run with the project's interpreter, PYTHONPATH=src:tests and
QT_QPA_PLATFORM=offscreen. Every value/phrase is a public gallery fixture.
No owner executor, wallet/profile, RPC or Core is created.
"""
import argparse
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace


def capture_screens(output):
    if os.environ.get('QT_QPA_PLATFORM') != 'offscreen':
        raise RuntimeError('PM103_CAPTURE_REQUIRES_OFFSCREEN')
    from PySide6.QtCore import Qt
    from wam_regtest.desktop import qt_application
    from wam_regtest.ui_settings import ui_settings
    from wam_regtest.wallet_executor import ExecutorState
    from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
    from wam_regtest.fusion_pages import PaymentApproval
    from wam_regtest.managed_onboarding import welcome_dialog
    from wam_regtest.qualification.ui_gallery import _fixture_snapshot, _inspect, _review, TEST_VECTOR

    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    previous = os.environ.get('WAM_UI_SETTINGS_PATH')
    with tempfile.TemporaryDirectory(prefix='pm103-capture-') as directory:
        os.environ['WAM_UI_SETTINGS_PATH'] = str(Path(directory) / 'ui.ini')
        app = qt_application()
        ui_settings().setValue('ui_language', 'vi')
        window = Bip39FusionWindow(SimpleNamespace(
            state=ExecutorState(locked=False, faulted=False, core_alive=True),
            busy=False, closed=False))
        window._poll.stop()
        window.reduce_motion.setChecked(True)
        _, result = _fixture_snapshot()
        window._ready = window._spend_enabled = True
        window._render_verified(result)
        window._set_actions()
        window.status.setText('')
        window.resize(1100, 720)
        window.show()
        findings, names = [], []

        def shoot(widget, name, theme):
            for _ in range(12):
                app.processEvents()
            tag = f'{name}--vi-1100x720-{theme}'
            _inspect(widget, tag, findings)
            assert widget.size().width() == 1100 and widget.size().height() == 720, tag
            assert widget.grab().save(str(output / (tag + '.png'))), tag
            names.append(tag)

        try:
            for index, theme in ((2, 'dark'), (1, 'light')):
                window.appearance_buttons[index].click()
                for row, name in enumerate(('overview', 'receive', 'history', 'send', 'security', 'network', 'settings')):
                    window.navigation.setCurrentRow(row)
                    if row == 6:
                        window.settings_categories[3].click()
                    shoot(window, name, theme)
                for category, name in ((0, 'settings-general'), (4, 'settings-advanced')):
                    window.settings_categories[category].click()
                    window.advanced_toggle.setChecked(category == 4)
                    shoot(window, name, theme)
                window.advanced_toggle.setChecked(False)
                welcome = welcome_dialog()
                welcome.resize(1100, 720)
                welcome.show()
                shoot(welcome, 'welcome', theme)
                welcome.reject()
                welcome.deleteLater()
                window.stack.setCurrentWidget(window.backup_page)
                window.backup_page.set_phrase(TEST_VECTOR)
                shoot(window, 'backup-public-vector', theme)
                window.backup_page.set_challenge(dict(challenge_id='ab' * 32, positions=(2, 7, 11)))
                window.backup_page._stack.setCurrentWidget(window.backup_page._verify_page)
                shoot(window, 'backup-verify', theme)
                window.backup_page.show_success()
                shoot(window, 'backup-success', theme)
                window.backup_page.clear_phrase()
                for mode in ('sign', 'broadcast'):
                    dialog = PaymentApproval(_review(), mode, window)
                    dialog.resize(1100, 720)
                    dialog.setWindowModality(Qt.WindowModality.NonModal)
                    dialog.show()
                    for _ in range(6):
                        app.processEvents()
                    dialog.resize(1100, 720)
                    shoot(dialog, 'consent-' + mode, theme)
                    dialog.reject()
                    dialog.deleteLater()
                window.navigation.setCurrentRow(0)
        finally:
            window.hide()
            window.deleteLater()
            if previous is None:
                os.environ.pop('WAM_UI_SETTINGS_PATH', None)
            else:
                os.environ['WAM_UI_SETTINGS_PATH'] = previous
        report = dict(status='PM103_OFFSCREEN_PRESENTATION_CAPTURES', platform=app.platformName(),
                      width=1100, height=720, language='vi', screenshots=names,
                      finding_count=len(findings), findings=findings,
                      public_test_vector_only=True, backend_or_core_started=False,
                      native_or_fee3_qualification=False, accepted=False,
                      source_sha=_source_sha())
        (output / 'capture-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
        return report


def _source_sha():
    """The exact source commit these captures were rendered from (HEAD)."""
    import subprocess
    try:
        sha = subprocess.run(
            ['git', 'rev-parse', 'HEAD'], capture_output=True, check=True,
            text=True, timeout=15).stdout.strip()
    except Exception:
        raise RuntimeError('PM103_CAPTURE_REQUIRES_GIT_SHA')
    if not sha:
        raise RuntimeError('PM103_CAPTURE_REQUIRES_GIT_SHA')
    return sha


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    report = capture_screens(parser.parse_args().output)
    print(f"PM103_OFFSCREEN_CAPTURES images={len(report['screenshots'])} findings={report['finding_count']}")
