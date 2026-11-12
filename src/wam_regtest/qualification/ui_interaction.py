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
      FOCUS_TRAP        Tab only moves inside one widget and returns to a
                        cell already visited (focus cannot leave it);
      FOCUS_LOST        no widget has focus;
      FOCUS_STEP_LIMIT  no cycle within the step limit.
    Every run records why traversal ended (CYCLE_COMPLETE, FOCUS_TRAP,
    FOCUS_LOST or STEP_LIMIT). FOCUS_INVISIBLE checks widget visibility,
    not the focus indicator; FOCUS_UNLABELLED is a heuristic (visible text
    is not always an accessible label).
  * mouse navigation: a real mouse click on every sidebar item. Finding
    NAV_CLICK_MISMATCH when the selection, the DISPLAYED stack page or the
    title does not follow the click (PAGE_NOT_DISPLAYED for programmatic
    selection while recording action states).
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
PAGES = tuple(range(7))  # overview, receive, history, send, security, network, settings


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
    """Every visible button, named or not (unnamed ones are a finding of their own)."""
    from PySide6.QtWidgets import QAbstractButton
    rows = []
    for button in window.findChildren(QAbstractButton):
        if button.isVisible():
            rows.append(dict(text=(button.text() or button.accessibleName())[:60],
                             type=type(button).__name__, name=button.objectName(),
                             enabled=button.isEnabled()))
    return rows


def _focus_state(widget):
    """Focus identity: the widget plus, for item views, the current cell."""
    if widget is None:
        return None
    index = None
    current = getattr(widget, 'currentIndex', None)
    if callable(current):
        try:
            model_index = current()
            if hasattr(model_index, 'row'):
                index = (model_index.row(), model_index.column())
        except TypeError:
            index = None
    return (id(widget), index)


def _show_page(window, row, settle):
    """Select a sidebar row and return whether the DISPLAYED page followed."""
    window.navigation.setCurrentRow(row)
    settle()
    return (window.stack.currentIndex() == row
            and window.stack.currentWidget() is window.stack.widget(row)
            and window.stack.currentWidget().isVisible()
            and window.page_title.text() == window.navigation.item(row).text())


def render_interaction(output, languages=('en',), size=(1100, 720), theme_index=1):
    from PySide6.QtCore import QCoreApplication, QEvent, QPoint, QRect, Qt, qVersion
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
                # Action states. "initial_not_opened" is the fresh window before any
                # open (unlock not yet offered), not a session locked after use.
                for state_name in ('initial_not_opened', 'verified_unlocked'):
                    if state_name == 'verified_unlocked':
                        _snap, result = _fixture_snapshot()
                        executor.state = ExecutorState(locked=False, faulted=False, core_alive=True)
                        window._ready = True
                        window._spend_enabled = True
                        window._render_verified(result)
                        window._set_actions()
                    pages = {}
                    for row in PAGES:
                        shown = _show_page(window, row, settle)
                        if not shown:
                            findings.append(dict(language=language, kind='PAGE_NOT_DISPLAYED',
                                                 row=row, state=state_name))
                        pages[window.navigation.item(row).text()] = dict(
                            displayed=shown, buttons=_buttons(window.stack.currentWidget()))
                    record['states'][state_name] = pages
                # Mouse navigation: real clicks; the displayed page must follow.
                navigation = window.navigation
                for row in (*PAGES[1:], PAGES[0]):
                    rect = navigation.visualItemRect(navigation.item(row))
                    QTest.mouseClick(navigation.viewport(), Qt.MouseButton.LeftButton,
                                     Qt.KeyboardModifier.NoModifier, rect.center())
                    settle()
                    ok = (navigation.currentRow() == row and window.stack.currentIndex() == row
                          and window.stack.currentWidget().isVisible()
                          and window.page_title.text() == navigation.item(row).text())
                    record['navigation'].append(dict(row=row, item=navigation.item(row).text(),
                                                     stack_index=window.stack.currentIndex(), ok=ok))
                    if not ok:
                        findings.append(dict(language=language, kind='NAV_CLICK_MISMATCH', row=row))
                # Keyboard focus traversal from the overview navigation list.
                _show_page(window, 0, settle)
                navigation.setFocus(Qt.FocusReason.TabFocusReason)
                settle()
                window_rect = window.rect()
                seen = {}      # focus state -> step first seen
                widgets = []   # widget id per step
                reason = 'STEP_LIMIT'
                for step in range(MAX_TAB_STEPS):
                    focused = QApplication.focusWidget()
                    if focused is None:
                        findings.append(dict(language=language, kind='FOCUS_LOST', step=step))
                        reason = 'FOCUS_LOST'
                        break
                    state = _focus_state(focused)
                    if state in seen:
                        since = widgets[seen[state]:]
                        if all(w == id(focused) for w in since):
                            # Tab only moved inside this one widget and came back
                            # to a cell already visited: focus cannot leave it.
                            findings.append(dict(language=language, kind='FOCUS_TRAP', step=step,
                                                 cells_visited=len(since), **_describe(focused)))
                            reason = 'FOCUS_TRAP'
                        else:
                            record['cycle_length'] = step - seen[state]
                            reason = 'CYCLE_COMPLETE'
                        break
                    seen[state] = step
                    widgets.append(id(focused))
                    info = _describe(focused)
                    top_left = focused.mapTo(window, QPoint(0, 0))
                    info['visible'] = focused.isVisible()
                    info['inside'] = window_rect.contains(QRect(top_left, focused.size()))
                    info['cell'] = state[1]
                    if not focused.isVisible():
                        findings.append(dict(language=language, kind='FOCUS_INVISIBLE', step=step, **_describe(focused)))
                    elif not info['inside']:
                        findings.append(dict(language=language, kind='FOCUS_OUTSIDE', step=step, **_describe(focused)))
                    if not (focused.accessibleName() or info.get('text')):
                        findings.append(dict(language=language, kind='FOCUS_UNLABELLED', step=step, **_describe(focused)))
                    record['focus'].append(info)
                    if language == languages[0]:
                        assert window.grab().save(str(destination / f'focus-{language}-{step:02d}.png'))
                    QTest.keyClick(focused, Qt.Key.Key_Tab)
                    settle()
                else:
                    findings.append(dict(language=language, kind='FOCUS_STEP_LIMIT', step=MAX_TAB_STEPS))
                record['termination'] = reason
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
    hints = app.styleHints()
    platform = dict(qt_version=qVersion(), style=app.style().name(),
                    # Native traversal follows this (macOS: the system "Keyboard
                    # navigation" setting decides whether buttons take Tab focus).
                    tab_focus_behavior=str(hints.tabFocusBehavior()))
    report = dict(status='UI_INTERACTION_RECORDED', qt_platform=app.platformName(), platform=platform,
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
