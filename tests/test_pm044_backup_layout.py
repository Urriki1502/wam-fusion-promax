"""D5-C geometry and interaction checks; disposable presentation fixtures only."""
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import QApplication, QLabel, QDialogButtonBox, QWidgetItem
from PySide6.QtTest import QTest
from shiboken6 import isValid
from wam_regtest.bip39_backup_page import Bip39BackupPage
from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
from wam_regtest.bip39_locale import t
from wam_regtest.presentation.strings import CATALOG
from wam_regtest.wallet_executor import ExecutorState
from wam_regtest.ui_settings import ui_settings


class BackupLayout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def settle(self):
        for _ in range(6):
            self.app.processEvents()

    def test_reflow_preserves_live_layout_items(self):
        # A Python-derived item makes Qt's otherwise silent C++ deletion
        # observable even when malloc immediately reuses the item's address.
        class TrackedItem(QWidgetItem):
            pass

        page = Bip39BackupPage()
        self.addCleanup(page.deleteLater)
        page.set_phrase(['testword'] * 12)
        items = []
        while page._grid.count():
            old = page._grid.takeAt(0)
            items.append(TrackedItem(old.widget()))
        for index, item in enumerate(items):
            page._grid.addItem(item, index // 3, index % 3)
        page._columns = None
        page._reflow_words()
        self.assertTrue(all(isValid(item) for item in items),
                        'reflow must not delete live widget-item wrappers')
        self.assertEqual([page._grid.itemAt(i) for i in range(12)], items)

    def test_motion_enabled_intro_backup_and_teardown_in_subprocess(self):
        # A native SIGSEGV must fail this test without killing the test runner.
        # The child explicitly removes both environment motion overrides and
        # uses fresh UI preferences, including in the reduced-motion suite run.
        code = textwrap.dedent('''
            import os
            import tempfile
            from PySide6.QtCore import QCoreApplication, QEvent
            from PySide6.QtTest import QTest
            from shiboken6 import isValid
            from test_q06_bip39_backup_ack import (
                _make_window, _open_result, _DISPLAY_PHRASE_WORDS)
            from wam_regtest.fusion_motion import motion_reduced, STAGGER_MS, STANDARD_MS

            with tempfile.TemporaryDirectory(prefix='pm044-motion-') as folder:
                os.environ['WAM_UI_SETTINGS_PATH'] = os.path.join(folder, 'ui.ini')
                for early_teardown in (False, True, False, True):
                    app, window = _make_window()
                    window._poll.stop()
                    assert not motion_reduced(window)
                    assert not window.reduce_motion.isChecked()
                    assert window._overview_intro
                    groups = (window.overview.hero, window.overview.status_board,
                              window.overview.activity_panel)
                    window.show()
                    app.processEvents()  # run the first staggered fade
                    assert groups[0].graphicsEffect() is not None
                    window._on_ready('open', _open_result(
                        'required', _DISPLAY_PHRASE_WORDS, window.executor.seed_folder))
                    page = window.backup_page
                    page._written_check.setChecked(True)
                    page._back_up_now.click()
                    app.processEvents()
                    assert page._stack.currentWidget() is page._verify_page
                    page._verify_back.click()
                    for width in (900, 1440, 900):
                        window.resize(width, 720)
                        app.processEvents()
                    if not early_teardown:
                        QTest.qWait(2 * STAGGER_MS + STANDARD_MS + 80)
                        assert all(w.graphicsEffect() is None for w in groups)
                    page.clear_phrase()
                    window.hide()
                    window.deleteLater()
                    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
                    assert not isValid(window)
                    assert all(not isValid(w) for w in groups)
                    QTest.qWait(2 * STAGGER_MS + STANDARD_MS + 80)
        ''')
        env = dict(os.environ)
        env.pop('QT_REDUCE_MOTION', None)
        env.pop('GITHUB_ACTIONS', None)
        # unittest discovery adds this directory only in the parent process.
        # Bootstrap the same sibling fixtures in the fresh interpreter without
        # relying on the caller's PYTHONPATH or a checkout-root package import.
        code = ('import sys; sys.path.insert(0, '
                + repr(str(Path(__file__).resolve().parent)) + ')\n' + code)
        result = subprocess.run([sys.executable, '-X', 'faulthandler', '-c', code],
                                env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_preparing_and_checking_block_reentrant_submissions(self):
        page = Bip39BackupPage()
        self.addCleanup(page.deleteLater)
        page.show()
        self.settle()
        self.assertTrue(page._phrase_preparing.isVisible())
        self.assertFalse(page._back_up_now.isEnabled())
        page.set_phrase(['testword'] * 12)
        page._written_check.setChecked(True)
        requests = []
        page.challenge_requested.connect(lambda: requests.append('challenge'))
        page._on_back_up_now()
        page._on_back_up_now()
        self.assertEqual(requests, ['challenge'])
        self.assertEqual(page._verify_button.text(), t('backup.preparing'))
        self.assertFalse(page._verify_button.isEnabled())
        page.set_challenge({'challenge_id': '1' * 64, 'positions': [2, 7, 12]})
        for edit in page._verify_inputs:
            edit.setText('testword')
        received = []
        page.verify_requested.connect(lambda *_: received.append(
            (page._verify_button.text(), page._verify_button.isEnabled(),
             all(not edit.text() for _, _, edit in page._verify_cards))))
        page._on_verify()
        page._on_verify()
        self.assertEqual(received, [(t('backup.checking'), False, True)])
        page.show_verification_error('verify_unavailable')
        self.assertEqual(page._verify_error.text(), t('verify_unavailable'))
        self.assertTrue(page._verify_button.isEnabled())

    def test_grid_reflows_without_changing_reading_order(self):
        page = Bip39BackupPage()
        self.addCleanup(page.deleteLater)
        page.resize(520, 630)
        # Deliberately longer than BIP39 English, exercising font/width pressure.
        page.set_phrase(['uninterruptibility'] * 12)
        page.show()
        self.settle()
        self.assertEqual(page._columns, 2)
        self.assertEqual(page._phrase_scroll.horizontalScrollBar().maximum(), 0)
        page.resize(900, 720)
        self.settle()
        self.assertEqual(page._columns, 3)
        for index in range(12):
            card = page._grid.itemAtPosition(index // 3, index % 3).widget()
            self.assertEqual(card.findChildren(QLabel)[0].text(), str(index + 1))
        self.assertEqual(page._phrase_scroll.horizontalScrollBar().maximum(), 0)

    def test_scenes_at_three_window_sizes_in_all_locales(self):
        for language, catalog in CATALOG.items():
            with tempfile.TemporaryDirectory(prefix='pm044-locale-') as folder, patch.dict(
                    os.environ, {'WAM_UI_SETTINGS_PATH': os.path.join(folder, 'ui.ini')}):
                ui_settings().setValue('ui_language', language)
                for width, height in ((900, 630), (1100, 720), (1440, 900)):
                    with self.subTest(language=language, size=(width, height)):
                        executor = SimpleNamespace(state=ExecutorState(), busy=False, closed=False)
                        window = Bip39FusionWindow(executor)
                        window._poll.stop()
                        page = window.backup_page
                        window.resize(width, height)
                        window.stack.setCurrentWidget(page)
                        page.set_phrase(['representative'] * 12)
                        window.show()
                        self.settle()
                        try:
                            self.assertEqual(page._phrase_page.accessibleName(), catalog['backup_title'])
                            self.assertFalse(page._back_up_now.isEnabled())
                            self.assertEqual(page._grid.count(), 12)
                            self.assertEqual(page._phrase_scroll.horizontalScrollBar().maximum(), 0)
                            for index in range(12):
                                card = page._grid.itemAtPosition(index // page._columns, index % page._columns).widget()
                                self.assertEqual(card.findChildren(QLabel)[0].text(), str(index + 1))
                            for i in range(12):
                                card = page._grid.itemAt(i).widget()
                                word = next(x for x in card.findChildren(QLabel) if x.text() == 'representative')
                                self.assertFalse(word.wordWrap())
                                self.assertGreaterEqual(word.contentsRect().width(), word.fontMetrics().horizontalAdvance(word.text()))
                                self.assertEqual(word.focusPolicy(), Qt.FocusPolicy.NoFocus)
                            for button in (page._back_up_now, page._back_up_later):
                                self.assertTrue(page.rect().contains(button.mapTo(page, QPoint(0, 0))))
                                self.assertLessEqual(button.mapTo(page, QPoint(0, button.height())).y(), page.height())
                            page._phrase_scroll.verticalScrollBar().setValue(9999)
                            self.settle()
                            self.assertTrue(page._back_up_later.isVisible())
                            page._written_check.setChecked(True)
                            self.assertTrue(page._back_up_now.isEnabled())
                            page._written_check.setFocus()
                            QTest.keyClick(page._written_check, Qt.Key.Key_Tab)
                            self.assertIs(self.app.focusWidget(), page._back_up_later)
                            QTest.keyClick(page._back_up_later, Qt.Key.Key_Tab)
                            self.assertIs(self.app.focusWidget(), page._back_up_now)
                            self.assertEqual(page._phrase_buttons.buttonRole(page._back_up_now), QDialogButtonBox.ButtonRole.AcceptRole)
                            page.set_challenge({'challenge_id': '2' * 64, 'positions': [1, 7, 12]})
                            page._stack.setCurrentWidget(page._verify_page)
                            self.settle()
                            for _, title, edit in page._verify_cards:
                                self.assertEqual(edit.accessibleName(), title.text())
                                self.assertIs(title.buddy(), edit)
                                edit.setFocus()
                                self.settle()
                                self.assertTrue(page._verify_scroll.viewport().rect().contains(edit.mapTo(page._verify_scroll.viewport(), QPoint(0, 0))))
                            self.assertTrue(page._verify_button.isVisible())
                            self.assertEqual(page._verify_scroll.horizontalScrollBar().maximum(), 0)
                            self.assertLessEqual(page._verify_button.mapTo(page, QPoint(0, page._verify_button.height())).y(), page.height())
                            controls = page._verify_inputs + [page._verify_back, page._verify_button]
                            controls[0].setFocus()
                            for first, second in zip(controls, controls[1:]):
                                QTest.keyClick(first, Qt.Key.Key_Tab)
                                self.assertIs(self.app.focusWidget(), second)
                            for first, second in zip(controls[::-1], controls[-2::-1]):
                                QTest.keyClick(first, Qt.Key.Key_Backtab)
                                self.assertIs(self.app.focusWidget(), second)
                            self.assertFalse(any(x.isVisible() and x.text() in (catalog['backup_flow_kicker'], catalog['backup_step_progress'].format(step=2, total=2)) for x in page.findChildren(QLabel)))
                        finally:
                            window.hide()
                            window.deleteLater()
                            self.settle()
