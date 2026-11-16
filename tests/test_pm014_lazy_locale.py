"""Regression coverage for owner-thread imports and late presentation locale."""
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class LazyLocaleTests(unittest.TestCase):
    def test_gui_errors_import_does_not_load_qt_in_fresh_process(self):
        result = subprocess.run(
            [sys.executable, '-c',
             'import sys; import wam_regtest.gui_errors; '
             'assert not any(n == "PySide6" or n.startswith("PySide6.") '
             'for n in sys.modules), sorted(n for n in sys.modules if n.startswith("PySide6"))'],
            env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')},
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_widgets_resolve_navigation_after_import(self):
        from wam_regtest import bip39_locale, fusion_ui
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.desktop import qt_application
        from wam_regtest.presentation.strings import text
        from wam_regtest.wallet_executor import ExecutorState

        qt_application()
        # These Fusion keys have no vi entries yet. Use existing vi copy as a
        # test-only resolver response, without extending the production catalog.
        def resolved_text(key):
            if bip39_locale._lang() == 'vi' and key.startswith('fusion.'):
                return text('backup_title', 'vi') + ':' + key
            return text(key, 'en')

        with patch.object(fusion_ui, 'ui_text', side_effect=resolved_text):
            for language in ('en', 'vi'):
                with self.subTest(language=language), patch.object(bip39_locale, '_lang', return_value=language):
                    window = Bip39FusionWindow(SimpleNamespace(
                        state=ExecutorState(), busy=False, closed=False))
                    self.addCleanup(window.deleteLater)
                    window._poll.stop()
                    expected = ['Overview', 'Receive', 'History', 'Send', 'Security', 'Network', 'Settings']
                    if language == 'vi':
                        expected = ['Sao lưu ví của bạn:fusion.' + name.lower() for name in expected]
                    self.assertEqual([window.navigation.item(i).text()
                                      for i in range(window.navigation.count())], expected)
                    window._navigate(2)
                    self.assertEqual(window.page_title.text(), expected[2])

    def test_default_kicker_resolves_language_after_import(self):
        from PySide6.QtWidgets import QLabel
        from wam_regtest import bip39_locale, fusion_ui
        from wam_regtest.desktop import qt_application
        from wam_regtest.presentation.strings import text

        qt_application()
        with patch.object(fusion_ui, 'ui_text',
                          side_effect=lambda key: text('backup_title', bip39_locale._lang())):
            for language, expected in (('en', 'Back up your wallet'), ('vi', 'Sao lưu ví của bạn')):
                with self.subTest(language=language), patch.object(bip39_locale, '_lang', return_value=language):
                    scroll, _ = fusion_ui.page('Title', 'Subtitle')
                    self.addCleanup(scroll.deleteLater)
                    self.assertEqual(scroll.findChild(QLabel, 'FusionKicker').text(), expected)
            for explicit in ('Custom kicker', ''):
                scroll, _ = fusion_ui.page('Title', 'Subtitle', kicker=explicit)
                self.addCleanup(scroll.deleteLater)
                self.assertEqual(scroll.findChild(QLabel, 'FusionKicker').text(), explicit)
