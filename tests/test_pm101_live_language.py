"""PM-101: one window retranslates every visible string, and nav icons stay per page.

Offscreen. Isolated UI settings. No Core, profile, or spend authority.
"""
import ast
import os
import re
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import Qt
from PySide6.QtGui import QImage
from PySide6.QtWidgets import QWidget

from wam_regtest.presentation.strings import CATALOG, text

ROOT = Path(__file__).resolve().parents[1]
SCREEN_SOURCES = (
    'src/wam_regtest/bip39_fusion_gui.py',
    'src/wam_regtest/fusion_ui.py',
    'src/wam_regtest/fusion_pages.py',
    'src/wam_regtest/managed_onboarding.py',
)
LITERAL_CALLS = {
    'setText', 'setPlaceholderText', 'QPushButton', 'QLabel', 'QCheckBox',
    'label', 'action',
}
PAGE_IDS = (
    'overview', 'receive', 'history', 'send', 'security', 'network', 'settings')
SWITCH = ('vi', 'ja', 'ko', 'zh-Hans', 'id')
RETIRED_NEXT_WINDOW = {
    'en': 'Applies to windows opened after this change.',
    'vi': 'Áp dụng cho các cửa sổ được mở sau thay đổi này.',
    'ja': 'この変更は、このあと開くウィンドウに適用されます。',
    'ko': '이 변경은 이후에 열리는 창에 적용됩니다.',
    'id': 'Berlaku untuk jendela yang dibuka setelah perubahan ini.',
    'zh-Hans': '此更改应用于之后打开的窗口。',
}


def _letters(value):
    return re.sub(r'[^A-Za-z]', '', value)


def _english_literal(value):
    letters = _letters(value)
    if not letters or letters == 'WAM':
        return False
    return True


def _call_name(node):
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _visible_literals(node):
    """String constants shown as text, not catalog keys passed to t()."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node
        return
    if isinstance(node, ast.Call):
        if _call_name(node) in ('t', 'ui_text', 'text'):
            return
        return
    if isinstance(node, (ast.IfExp, ast.BinOp, ast.BoolOp, ast.JoinedStr, ast.Tuple, ast.List)):
        for child in ast.iter_child_nodes(node):
            yield from _visible_literals(child)


def hardcoded_english_literals(path):
    tree = ast.parse(path.read_text())
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        if _call_name(node) not in LITERAL_CALLS:
            continue
        for constant in _visible_literals(node.args[0]):
            if _english_literal(constant.value):
                found.append((node.lineno, constant.value))
    return found


def _norm(value):
    return re.sub(r'\s+', ' ', value.replace('\u200b', '')).strip()


def _png(icon, size, dpr):
    pixmap = icon.pixmap(size)
    image = pixmap.toImage().convertToFormat(QImage.Format.Format_ARGB32)
    return image.constBits().tobytes() if image.constBits() is not None else b''


class LiveLanguageTests(unittest.TestCase):
    def setUp(self):
        from wam_regtest.desktop import qt_application
        qt_application()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / 'ui.ini')
        self._previous = os.environ.get('WAM_UI_SETTINGS_PATH')
        os.environ['WAM_UI_SETTINGS_PATH'] = self.path
        self.addCleanup(self._restore_settings_path)

    def _restore_settings_path(self):
        if self._previous is None:
            os.environ.pop('WAM_UI_SETTINGS_PATH', None)
        else:
            os.environ['WAM_UI_SETTINGS_PATH'] = self._previous

    def _window(self):
        from types import SimpleNamespace
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.wallet_executor import ExecutorState
        window = Bip39FusionWindow(SimpleNamespace(
            state=ExecutorState(), busy=False, closed=False))
        window._poll.stop()
        window.show()
        self.addCleanup(window.deleteLater)
        return window

    def _shell_widgets(self, window):
        legacy = {id(window._legacy_layout_holder)}
        legacy.update(id(child) for child in window._legacy_layout_holder.findChildren(QWidget))
        widgets = [window]
        widgets.extend(window.findChildren(QWidget))
        return [widget for widget in widgets if id(widget) not in legacy]

    def _readers(self, window):
        readers = []
        for widget in self._shell_widgets(window):
            if callable(getattr(widget, 'text', None)):
                readers.append(widget.text)
            if callable(getattr(widget, 'placeholderText', None)):
                readers.append(widget.placeholderText)
            readers.extend((widget.toolTip, widget.accessibleName, widget.accessibleDescription))
            if widget is window:
                readers.append(widget.windowTitle)
        navigation = window.navigation
        for index in range(navigation.count()):
            item = navigation.item(index)
            readers.append(item.text)
        language = window.language
        readers.append(lambda combo=language: combo.itemText(0))
        history = window.history_page
        for index in range(history.filter.count()):
            readers.append(lambda combo=history.filter, row=index: combo.itemText(row))
        for table in (history.table, window.overview.activity_table):
            for column in range(table.columnCount()):
                readers.append(lambda grid=table, col=column: (
                    grid.horizontalHeaderItem(col).text()
                    if grid.horizontalHeaderItem(col) is not None else ''))
        for label in window.payment_steps.labels:
            readers.append(label.text)
        return readers

    def _catalog_reads(self, window, language):
        """Readers whose whole text is exactly one catalog entry in `language`."""
        found = []
        for reader in self._readers(window):
            try:
                raw = reader()
            except Exception:
                continue
            if not isinstance(raw, str) or not raw.strip():
                continue
            normalized = _norm(raw)
            keys = [key for key, entry in CATALOG[language].items() if _norm(entry) == normalized]
            if len(keys) == 1:
                found.append((reader, keys[0]))
            else:
                numbered = re.fullmatch(r'(\d+\s+)(.+)', normalized)
                if numbered is None:
                    continue
                prefix, body = numbered.groups()
                body_keys = [key for key, entry in CATALOG[language].items() if _norm(entry) == body]
                if len(body_keys) == 1:
                    found.append((reader, body_keys[0], prefix))
        return found

    def _assert_language(self, window, language, previous, readers):
        from wam_regtest.fusion_ui import fusion_palette, vector_icon
        for index, page_id in enumerate(PAGE_IDS):
            item = window.navigation.item(index)
            self.assertEqual(item.data(Qt.ItemDataRole.UserRole), page_id)
            self.assertEqual(item.text(), text('fusion.' + page_id, language))
        colors = fusion_palette(window._styled_mode)
        dpr = max(1, window.devicePixelRatioF())
        size = window.navigation.iconSize()
        selected = window.navigation.currentRow()
        for index, page_id in enumerate(PAGE_IDS):
            tone = colors['onaccent'] if index == selected else colors['muted']
            actual = window.navigation.item(index).icon()
            expected = vector_icon(page_id, tone, dpr)
            self.assertEqual(
                _png(actual, size, dpr), _png(expected, size, dpr), page_id)
        current = []
        for reader in self._readers(window):
            try:
                raw = reader()
            except Exception:
                continue
            if isinstance(raw, str) and raw.strip():
                current.append(_norm(raw))
        for record in readers:
            reader, key = record[0], record[1]
            shown = _norm(reader())
            expected = _norm(text(key, language))
            if len(record) == 3:
                expected = _norm(record[2] + text(key, language))
            self.assertEqual(shown, expected, (language, key, shown))
        previous_only = [
            _norm(value) for value in set(CATALOG[previous].values())
            if _norm(value) not in {_norm(item) for item in CATALOG[language].values()}
            and len(_norm(value)) >= 12]
        for needle in previous_only:
            for shown in current:
                self.assertNotIn(needle, shown, (language, needle, shown))
        self.assertEqual(
            _norm(window.language.itemText(0)),
            _norm(text('settings.language_system', language)))
        self.assertNotIn(RETIRED_NEXT_WINDOW[language], current)
        self.assertIn(_norm(text('settings.language_next_window', language)), current)

    def test_runtime_switch_retranslates_every_surface_and_keeps_page_icons(self):
        window = self._window()
        self.assertEqual(
            [window.navigation.item(index).text() for index in range(window.navigation.count())],
            [text('fusion.' + page_id, 'en') for page_id in PAGE_IDS])
        previous = 'en'
        readers = self._catalog_reads(window, previous)
        self.assertGreater(len(readers), 20)
        for language in SWITCH:
            window.language.setCurrentIndex(window.language.findData(language))
            self.assertEqual(window.language.currentData(), language)
            self._assert_language(window, language, previous, readers)
            readers = self._catalog_reads(window, language)
            previous = language

    def test_welcome_retranslates_without_a_new_dialog(self):
        from PySide6.QtCore import QSettings
        from wam_regtest.managed_onboarding import welcome_dialog
        dialog = welcome_dialog()
        self.addCleanup(dialog.deleteLater)
        self.assertTrue(callable(getattr(dialog, 'retranslate', None)))
        settings = QSettings(self.path, QSettings.Format.IniFormat)
        settings.setValue('ui_language', 'ja')
        settings.sync()
        dialog.retranslate()
        shown = []
        for label in dialog.findChildren(QWidget):
            if callable(getattr(label, 'text', None)):
                try:
                    value = label.text()
                except Exception:
                    continue
                if isinstance(value, str) and value.strip():
                    shown.append(_norm(value))
        self.assertIn(_norm(text('welcome.welcome_to_your_wallet', 'ja')), shown)
        self.assertNotIn(_norm(text('welcome.welcome_to_your_wallet', 'en')), shown)

    def test_rec1_observations_survive_language_switch_without_a_new_snapshot(self):
        from test_fusion_v21_layout import verified_snapshot
        from test_pm090_rec_gui_truthful import STATES
        window = self._window()
        history = window.history_page
        snap = verified_snapshot()
        txid = snap.history[0].txid
        for state in STATES:
            history.render_snapshot(snap)
            history.set_rec1_states({txid: state})
            history.select_txid(txid)
            for language in ('en', 'vi', 'ja'):
                with self.subTest(state=state, language=language):
                    window.language.setCurrentIndex(window.language.findData(language))
                    self.assertEqual(history._rec1_by_txid, {txid: state})
                    self.assertEqual(history._selected_txid(), txid)
                    self.assertIn(text('rec1.' + state, language), history.detail_values.text())
        history.render_snapshot(snap)
        self.assertEqual(history._rec1_by_txid, {})

    def test_new_busy_presentation_survives_language_switch(self):
        from test_fusion_v21_layout import verified_snapshot
        window = self._window()
        snap = verified_snapshot()
        from wam_regtest.wallet_executor import ExecutorState
        window.executor.state = ExecutorState(locked=False, core_alive=True)
        window._last_verified = snap
        window._ready = True
        window.overview.render_snapshot(snap, locked=False, operational=True,
                                        core_alive=True, busy=False)
        window.executor.busy = True
        window._set_actions()
        for language in ('en', 'vi', 'ja'):
            with self.subTest(language=language):
                window.language.setCurrentIndex(window.language.findData(language))
                self.assertEqual(window.overview.currentness.text(),
                                 text('operational.last_verified', language).format(height=110))
                self.assertFalse(window.overview.currentness.isHidden())
                self.assertTrue(window.executor.busy)

    def test_read_only_permission_fact_survives_language_switch(self):
        """A read-only profile must not turn 'Operational' on a language switch."""
        from test_fusion_v21_layout import verified_snapshot
        from wam_regtest.wallet_executor import ExecutorState
        window = self._window()
        snap = verified_snapshot()
        window.executor.state = ExecutorState(locked=False, core_alive=True)
        window._last_verified = snap
        window._ready = True
        window.overview.render_snapshot(snap, locked=False, operational=False,
                                        core_alive=True, busy=False)
        window._set_actions()
        for language in ('en', 'vi', 'ja'):
            with self.subTest(language=language):
                window.language.setCurrentIndex(window.language.findData(language))
                self.assertEqual(window.overview.wallet_profile.text(),
                                 text('fusion.read_only_regtest_wallet', language))

    def test_populated_payment_result_rec_and_operation_text_retranslate(self):
        from wam_regtest.bip39_locale import t
        from wam_regtest.fusion_pages import fusion_review_text, describe_broadcast_result
        from wam_regtest.gui_errors import error_text
        from wam_regtest.wallet_session import PaymentReview
        from test_pm090_rec_gui_truthful import _signed
        window = self._window()
        txid = 'ab' * 32
        review = PaymentReview('wamrtsp1public', 50000, 1000, 49000, 1, 'a' * 64)
        window.review_summary.setText(fusion_review_text(review))
        window.send_result.setText(describe_broadcast_result(txid))
        for populate, expected in (
                (lambda: window.status.setText(t('owner.broadcast_submitted').format(txid=txid)),
                 lambda lang: text('owner.broadcast_submitted', lang).format(txid=txid)),
                (lambda: window.status.setText(t('operational.last_verified').format(height=110)),
                 lambda lang: text('operational.last_verified', lang).format(height=110)),
                (lambda: window.status.setText(error_text('WALLET_UNLOCK_REFUSED')),
                 lambda lang: text('errors.WALLET_UNLOCK_REFUSED', lang)),
                (lambda: window._on_ready('intent_status', {'intents': [_signed()]}), None)):
            populate()
            for language in ('en', 'vi', 'ja'):
                with self.subTest(language=language, status=expected):
                    window.language.setCurrentIndex(window.language.findData(language))
                    with self.subTest(surface='review'):
                        self.assertIn(text('wallet.review_details', language).split('{code}')[0],
                                      window.review_summary.text())
                    with self.subTest(surface='result'):
                        self.assertIn(text('pages.submitted_pending', language), window.send_result.text())
                        self.assertIn(txid, window.send_result.text())
                    with self.subTest(surface='status'):
                        if expected:
                            self.assertEqual(_norm(window.status.text()), _norm(expected(language)))
                        else:
                            self.assertIn(_norm(text('rec1.NOT_OBSERVED_LOCALLY', language)),
                                          _norm(window.status.text()))

    def test_active_backup_challenge_labels_and_accessibility_retranslate(self):
        window = self._window()
        backup = window.backup_page
        backup.set_challenge({'challenge_id': 'a' * 64, 'positions': [1, 4, 9]})
        for edit, value in zip(backup._verify_inputs, ('alpha', 'beta', 'gamma')):
            edit.setText(value)
        for language in ('en',) + SWITCH:
            window.language.setCurrentIndex(window.language.findData(language))
            for (_, title, edit), position, value in zip(
                    backup._verify_cards, (1, 4, 9), ('alpha', 'beta', 'gamma')):
                with self.subTest(language=language, position=position):
                    expected = text('recovery_word_position', language).format(position=position)
                    self.assertEqual(title.text(), expected)
                    self.assertEqual(edit.accessibleName(), expected)
                    self.assertEqual(edit.text(), value)
            self.assertEqual(backup._challenge_id, 'a' * 64)

    def test_screen_sources_have_no_hardcoded_english_literals(self):
        for language, retired in RETIRED_NEXT_WINDOW.items():
            self.assertNotEqual(CATALOG[language]['settings.language_next_window'], retired)
            self.assertNotIn('opened after', CATALOG[language]['settings.language_next_window'].lower())
        offenders = []
        for relative in SCREEN_SOURCES:
            for line, value in hardcoded_english_literals(ROOT / relative):
                offenders.append('%s:%d: %r' % (relative, line, value))
        self.assertEqual(offenders, [])

    def test_language_subtitle_is_immediate_in_every_locale(self):
        for language, retired in RETIRED_NEXT_WINDOW.items():
            value = CATALOG[language]['settings.language_next_window']
            self.assertNotEqual(value, retired, language)
            self.assertNotIn('opened after', value.lower(), language)
            self.assertGreaterEqual(len(value.strip()), 4, language)


if __name__ == '__main__':
    unittest.main()
