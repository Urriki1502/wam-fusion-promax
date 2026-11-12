"""PM-020: a missing UI language is English outside the native production store."""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from PySide6.QtCore import QSettings


class QualLocalePinTests(unittest.TestCase):
    def setUp(self):
        from wam_regtest.desktop import qt_application
        qt_application()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / 'ui.ini')

    def _settings(self):
        return QSettings(self.path, QSettings.Format.IniFormat)

    def _system(self, name):
        from wam_regtest import bip39_locale
        return patch.object(
            bip39_locale.QLocale, 'system',
            return_value=SimpleNamespace(name=lambda n=name: n))

    def test_native_missing_key_follows_system_locale(self):
        from wam_regtest import bip39_locale, ui_settings
        settings = self._settings()
        with patch.object(ui_settings, '_native', True), \
                patch.object(bip39_locale, 'ui_settings', return_value=settings), \
                self._system('ja_JP'):
            self.assertEqual(bip39_locale._lang(), 'ja')

    def test_isolated_missing_key_is_english_for_translated_host_locales(self):
        from wam_regtest import bip39_locale, ui_settings
        settings = self._settings()
        for name in ('ja_JP', 'vi_VN', 'zh_CN'):
            with self.subTest(system=name), \
                    patch.object(ui_settings, '_native', False), \
                    patch.object(bip39_locale, 'ui_settings', return_value=settings), \
                    self._system(name):
                self.assertEqual(bip39_locale._lang(), 'en')

    def test_isolated_stored_system_follows_patched_locale(self):
        from wam_regtest import bip39_locale, ui_settings
        settings = self._settings()
        settings.setValue('ui_language', 'system')
        with patch.object(ui_settings, '_native', False), \
                patch.object(bip39_locale, 'ui_settings', return_value=settings), \
                self._system('ja_JP'):
            self.assertEqual(bip39_locale._lang(), 'ja')

    def test_isolated_stored_vi_stays_vietnamese(self):
        from wam_regtest import bip39_locale, ui_settings
        settings = self._settings()
        settings.setValue('ui_language', 'vi')
        with patch.object(ui_settings, '_native', False), \
                patch.object(bip39_locale, 'ui_settings', return_value=settings), \
                self._system('ja_JP'):
            self.assertEqual(bip39_locale._lang(), 'vi')

    def test_isolated_window_navigation_is_english_under_ja_jp(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.presentation.strings import text
        from wam_regtest.wallet_executor import ExecutorState
        keys = (
            'fusion.overview', 'fusion.receive', 'fusion.history', 'fusion.send',
            'fusion.security', 'fusion.network', 'fusion.settings')
        with patch.dict(os.environ, {'WAM_UI_SETTINGS_PATH': self.path}), \
                self._system('ja_JP'):
            window = Bip39FusionWindow(SimpleNamespace(
                state=ExecutorState(), busy=False, closed=False))
            window._poll.stop()
            self.addCleanup(window.deleteLater)
            shown = [window.navigation.item(index).text()
                     for index in range(window.navigation.count())]
        self.assertEqual(shown, [text(key, 'en') for key in keys])
        self.assertNotEqual(shown[0], text('fusion.overview', 'ja'))
