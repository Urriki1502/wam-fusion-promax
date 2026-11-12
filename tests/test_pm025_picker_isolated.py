"""PM-025: the language picker shows the language actually in effect.

Isolated processes with no stored ui_language render English (PM-020). The
picker must select English there. The native store with no stored value still
selects System. A stored token is selected as stored, and an invalid token
still falls back to System.
"""
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from PySide6.QtCore import QSettings

from wam_regtest.presentation.strings import text


_NAV_KEYS = (
    'fusion.overview', 'fusion.receive', 'fusion.history', 'fusion.send',
    'fusion.security', 'fusion.network', 'fusion.settings')


class PickerIsolatedTests(unittest.TestCase):
    def setUp(self):
        from wam_regtest.desktop import qt_application
        qt_application()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / 'ui.ini')

    def _system(self, name):
        from wam_regtest import bip39_locale
        return patch.object(
            bip39_locale.QLocale, 'system',
            return_value=SimpleNamespace(name=lambda n=name: n))

    def _open(self, *, native, system, seed=None):
        from wam_regtest import bip39_locale, ui_settings
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.wallet_executor import ExecutorState
        settings = QSettings(self.path, QSettings.Format.IniFormat)
        if seed is not None:
            settings.setValue('ui_language', seed)
            settings.sync()
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(ui_settings, '_native', native))
        stack.enter_context(self._system(system))
        if native:
            # The native flag must be true, but this test must not open the
            # owner's production store. Both readers share this empty file.
            stack.enter_context(patch.object(
                bip39_locale, 'ui_settings', return_value=settings))
            stack.enter_context(patch(
                'wam_regtest.bip39_fusion_gui.ui_settings', return_value=settings))
        else:
            stack.enter_context(patch.dict(
                os.environ, {'WAM_UI_SETTINGS_PATH': self.path}))
        window = Bip39FusionWindow(SimpleNamespace(
            state=ExecutorState(), busy=False, closed=False))
        window._poll.stop()
        self.addCleanup(window.deleteLater)
        return window, settings

    def _navigation(self, window):
        return [window.navigation.item(index).text()
                for index in range(window.navigation.count())]

    def test_isolated_missing_picker_shows_english_and_ui_is_english(self):
        window, _settings = self._open(native=False, system='ja_JP')
        self.assertEqual(window.language.currentData(), 'en')
        self.assertEqual(window.language.currentText(), 'English')
        shown = self._navigation(window)
        self.assertEqual(shown, [text(key, 'en') for key in _NAV_KEYS])
        self.assertNotEqual(shown[0], text('fusion.overview', 'ja'))

    def test_native_missing_picker_shows_system(self):
        window, _settings = self._open(native=True, system='en_US')
        self.assertEqual(window.language.currentData(), 'system')
        self.assertEqual(window.language.currentText(), 'System default')

    def test_stored_korean_picker_shows_korean(self):
        window, settings = self._open(native=False, system='en_US', seed='ko')
        self.assertEqual(window.language.currentData(), 'ko')
        self.assertEqual(window.language.currentText(), '한국어')
        self.assertEqual(settings.value('ui_language'), 'ko')

    def test_stored_garbage_falls_back_to_system(self):
        window, settings = self._open(native=False, system='ja_JP', seed='garbage')
        self.assertEqual(window.language.currentData(), 'system')
        self.assertEqual(window.language.currentIndex(), window.language.findData('system'))
        self.assertEqual(settings.value('ui_language'), 'garbage')

    def test_choosing_an_entry_stores_that_token(self):
        window, _settings = self._open(native=False, system='en_US', seed='en')
        window.language.setCurrentIndex(window.language.findData('vi'))
        stored = QSettings(self.path, QSettings.Format.IniFormat)
        stored.sync()
        self.assertEqual(stored.value('ui_language'), 'vi')
