"""UI interaction probe: keyboard focus, mouse navigation and action states.

This closes the gap that the static V0 gallery cannot cover (owner premium-UI
directive, items 3 and 4: real mouse and keyboard interaction, enabled and
disabled states). It uses the same inert presentation fixture as ui_gallery:
no backend, Core, Keychain, profile or network, and public fixture data only.
The executor is an ExecutorState namespace, so no wallet command can run.

Per language it records:
  * focus traversal: Tab pressed repeatedly from the window. For every
    step it records the focused widget (type, object name, accessible name
    or text, whether it is visible inside the window) and a screenshot.
    Findings:
      FOCUS_INVISIBLE   focus lands on a widget that is not visible;
      FOCUS_OUTSIDE     the widget lies outside the window's rectangle;
      FOCUS_UNLABELLED  no accessible name and no text;
      FOCUS_STUCK       Tab does not move focus.
  * mouse navigation: a real mouse click on every sidebar item. Finding
    NAV_CLICK_MISMATCH when the page or title does not follow the click.
  * action states: the enabled state of every visible button on every page,
    for the locked fixture and the verified-unlocked fixture. This is a review
    table, not an oracle.

The output is review input only. It grants no UI, G6 or owner acceptance.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

MAX_TAB_STEPS = 60
PAGES = range(7)  # overview, receive, history, send, security, network, settings


def _describe(widget):
    if widget is None:
        return None
    text = ''
    if hasattr(widget, 'text') and callable(widget.text):
        try:
            value = widget.text()
            text = value if isinstance(value, str) else ''
        except TypeError:
            text = ''
    return dict(type=type(widget).__name__, name=widget.objectName(),
                accessible=widget.accessibleName(), text=text[:60])


def _buttons(window):
    from PySide6.QtWidgets import QAbstractButton
    rows = []
    for button in window.findChildren(QAbstractButton):
        if button.isVisible() and (button.text() or button.accessibleName()):
            rows.append(dict(text=(button.text() or button.accessibleName())[:60],
                             enabled=button.isEnabled()))
    return rows


def render_interaction(output, languages=('en',), size=(1100, 720), theme_index=1):
    from PySide6.QtCore import QCoreApplication, QEvent, QPoint, Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication
    from ..bip39_fusion_gui import Bip39FusionWindow
    from ..desktop import qt_application
    from ..ui_settings import native_store_enabled, ui_settings
    from ..wallet_executor import ExecutorState
    from .ui_gallery import _fixture_snapshot

    if native_store_enabled():
        raise RuntimeError('UI_INTERACTION_NATIVE_STORE_DENIED')
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=False)
    previous = os.environ.get('WAM_UI_SETTINGS_PATH')
    os.environ['WAM_UI_SETTINGS_PATH'] = os.path.join(
        tempfile.mkdtemp(prefix='wam-ui-interaction-'), 'ui-settings.ini')
    app = qt_application()
    findings, report_languages = [], {}

    def settle():
        for _ in range(10):
            app.processEvents()
            time.sleep(0.01)

    try:
        for language in languages:
            store = ui_settings()
            store.setValue('ui_language', language)
            store.sync()
            executor = SimpleNamespace(state=ExecutorState(locked=True, faulted=False, core_alive=True),
                                       busy=False, closed=False)
            window = Bip39FusionWindow(executor)
            window._poll.stop()  # inert: no polling, quit handling or commands
            window.reduce_motion.setChecked(True)
            record = dict(states={}, navigation=[], focus=[])
            try:
                window.resize(*size)
                window.show()
                window.appearance_buttons[theme_index].click()
                window.raise_()
                window.activateWindow()
                settle()
                # Action states: locked first, then the verified-unlocked fixture.
                for state_name in ('locked', 'unlocked'):
                    if state_name == 'unlocked':
                        _snap, result = _fixture_snapshot()
                        executor.state = ExecutorState(locked=False, faulted=False, core_alive=True)
                        window._ready = True
                        window._spend_enabled = True
                        window._render_verified(result)
                        window._set_actions()
                    pages = {}
                    for row in PAGES:
                        window.navigation.setCurrentRow(row)
                        settle()
                        pages[window.navigation.item(row).text()] = _buttons(window)
                    record['states'][state_name] = pages
                # Mouse navigation with real clicks on the sidebar items.
                navigation = window.navigation
                for row in PAGES:
                    rect = navigation.visualItemRect(navigation.item(row))
                    QTest.mouseClick(navigation.viewport(), Qt.MouseButton.LeftButton,
                                     Qt.KeyboardModifier.NoModifier, rect.center())
                    settle()
                    ok = (navigation.currentRow() == row
                          and window.page_title.text() == navigation.item(row).text())
                    record['navigation'].append(dict(row=row, item=navigation.item(row).text(), ok=ok))
                    if not ok:
                        findings.append(dict(language=language, kind='NAV_CLICK_MISMATCH', row=row))
                # Keyboard focus traversal from the overview.
                navigation.setCurrentRow(0)
                settle()
                navigation.setFocus(Qt.FocusReason.TabFocusReason)
                settle()
                window_rect = window.rect()
                first = None
                for step in range(MAX_TAB_STEPS):
                    focused = QApplication.focusWidget()
                    info = _describe(focused) or {}
                    if focused is not None:
                        top_left = focused.mapTo(window, QPoint(0, 0))
                        info['visible'] = focused.isVisible()
                        info['inside'] = window_rect.contains(top_left)
                        if not focused.isVisible():
                            findings.append(dict(language=language, kind='FOCUS_INVISIBLE', step=step, **_describe(focused)))
                        elif not info['inside']:
                            findings.append(dict(language=language, kind='FOCUS_OUTSIDE', step=step, **_describe(focused)))
                        if not (focused.accessibleName() or info.get('text')):
                            findings.append(dict(language=language, kind='FOCUS_UNLABELLED', step=step, **_describe(focused)))
                    record['focus'].append(info)
                    if first is None:
                        first = focused
                    if language == languages[0]:
                        assert window.grab().save(str(destination / f'focus-{language}-{step:02d}.png'))
                    QTest.keyClick(focused or window, Qt.Key.Key_Tab)
                    settle()
                    now = QApplication.focusWidget()
                    if now is focused and focused is not None:
                        findings.append(dict(language=language, kind='FOCUS_STUCK', step=step, **_describe(focused)))
                        break
                    if now is first:
                        record['cycle_length'] = step + 1
                        break  # completed one full Tab cycle
            finally:
                window._closed = True
                window.hide()
                window.deleteLater()
                QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
            report_languages[language] = record
    finally:
        if previous is None:
            os.environ.pop('WAM_UI_SETTINGS_PATH', None)
        else:
            os.environ['WAM_UI_SETTINGS_PATH'] = previous
    report = dict(status='UI_INTERACTION_RECORDED', qt_platform=app.platformName(),
                  frozen=bool(getattr(sys, 'frozen', False)), size=list(size),
                  backend_or_core_started=False, wallet_or_transaction_acceptance=False,
                  g6_or_owner_acceptance=False, finding_count=len(findings),
                  findings=findings, languages=report_languages)
    (destination / 'interaction.json').write_text(json.dumps(report, indent=1, ensure_ascii=False) + '\n')
    return report


def run(output='ui-interaction'):
    from ..desktop import shutdown_qt
    from ..presentation.strings import SUPPORTED_LANGUAGES
    try:
        report = render_interaction(output, languages=SUPPORTED_LANGUAGES)
        print('UI_INTERACTION_RECORDED findings=%d platform=%s frozen=%s' % (
            report['finding_count'], report['qt_platform'], report['frozen']), flush=True)
        return 0
    finally:
        shutdown_qt()


if __name__ == '__main__':
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else 'ui-interaction'))
