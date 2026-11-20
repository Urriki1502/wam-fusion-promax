"""PM-029 D1: shell tokens, type scale, focus rings, direction colours.

Presentation contracts only. No wallet, Core, or signing behaviour.
"""
import re
import unittest
from pathlib import Path

from wam_regtest.fusion_ui import (
    FOCUS, QR, SHELL, SPACING, TYPE, direction_tone,
    fusion_palette, fusion_stylesheet, present_brand_title, page, StateSwitch,
)
from wam_regtest.presentation.strings import CATALOG

ROOT = Path(__file__).resolve().parents[1]
SHELL_MODULES = (
    'src/wam_regtest/fusion_ui.py',
    'src/wam_regtest/bip39_fusion_gui.py',
    'src/wam_regtest/fusion_pages.py',
    'src/wam_regtest/fusion_motion.py',
    'src/wam_regtest/bip39_backup_page.py',
)
_KF = '[keyboardFocus="true"]'
FOCUS_SELECTORS = (
    'QListWidget' + _KF,
    'QPushButton' + _KF,
    'QPushButton#FusionPrimary' + _KF,
    'QCheckBox' + _KF + '::indicator',
    'QCheckBox' + _KF + '::indicator:checked',
    'QComboBox' + _KF,
    'QLineEdit' + _KF,
    'QPlainTextEdit' + _KF,
    'QPlainTextEdit#ReceiveCode' + _KF,
    'QTextEdit' + _KF,
    'QTableWidget' + _KF,
    'QTableWidget#FusionActivityTable' + _KF,
    'QToolButton#FusionSegment' + _KF,
    'QFrame#FusionSegmented' + _KF,
    'QTableWidget' + _KF + '::item:focus',
)


def _luminance(hexcolor):
    rgb = [int(hexcolor[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
              for v in rgb]
    return sum(w * v for w, v in zip((0.2126, 0.7152, 0.0722), linear))


def _contrast(a, b):
    x, y = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (x + 0.05) / (y + 0.05)


class ShellTokenContracts(unittest.TestCase):
    def test_light_and_dark_expose_the_same_token_keys(self):
        dark = fusion_palette('dark')
        light = fusion_palette('light')
        self.assertEqual(set(dark), set(light))
        self.assertGreater(len(dark), 0)

    def test_duplicated_colours_are_one_stored_hex(self):
        table = (ROOT / 'src/wam_regtest/fusion_ui.py').read_text()
        start = table.index('# TOKEN_TABLE_START')
        end = table.index('# TOKEN_TABLE_END')
        body = table[start:end]
        for hexcolor in ('#E0C36A', '#7A5A12', '#3DDC97', '#0F7A52',
                         '#FF8B8F', '#B8424C'):
            self.assertEqual(body.count(hexcolor), 1, hexcolor)
        for mode in ('dark', 'light'):
            colors = fusion_palette(mode)
            self.assertEqual(colors['focus'], colors['accent'])
            self.assertEqual(colors['success'], colors['green'])
            self.assertEqual(colors['error'], colors['red'])
            self.assertEqual(colors['received'], colors['green'])
            self.assertEqual(colors['sent'], colors['blue'])
            self.assertNotEqual(colors['sent'], colors['error'])
            self.assertNotIn('shadow', colors)
            self.assertIn('pending', colors)

    def test_direction_and_status_colours_keep_one_meaning(self):
        for mode in ('dark', 'light'):
            colors = fusion_palette(mode)
            self.assertEqual(direction_tone(colors, 1), colors['received'])
            self.assertEqual(direction_tone(colors, -1), colors['sent'])
            self.assertEqual(direction_tone(colors, 0), colors['muted'])
            self.assertNotEqual(direction_tone(colors, -1), colors['error'])
        motion = (ROOT / 'src/wam_regtest/fusion_motion.py').read_text()
        self.assertIn("c['pending']", motion)
        self.assertIn("c['success']", motion)
        self.assertIn("c['error']", motion)
        self.assertNotIn("'pending': c['accent']", motion)

    def test_shell_modules_keep_hex_inside_the_token_table(self):
        for relative in SHELL_MODULES:
            text = (ROOT / relative).read_text()
            if relative.endswith('fusion_ui.py'):
                start = text.index('# TOKEN_TABLE_START')
                end = text.index('# TOKEN_TABLE_END')
                text = text[:start] + text[end + len('# TOKEN_TABLE_END'):]
            found = re.findall(r'#[0-9A-Fa-f]{3,8}\b', text)
            self.assertEqual(found, [], relative)

    def test_type_scale_is_used_and_kickers_are_at_least_12(self):
        self.assertGreaterEqual(TYPE['caption'], 12)
        self.assertLess(TYPE['caption'], TYPE['secondary'])
        self.assertLess(TYPE['secondary'], TYPE['body'])
        self.assertLess(TYPE['body'], TYPE['section'])
        self.assertLess(TYPE['section'], TYPE['number'])
        self.assertLess(TYPE['number'], TYPE['heading'])
        self.assertLess(TYPE['heading'], TYPE['display'])
        self.assertEqual(SPACING['xs'], 4)
        self.assertIn(SHELL['page_top'], SPACING.values())
        self.assertIn(SHELL['panel_gap'], SPACING.values())
        self.assertIn(SHELL['topbar_gap'], SPACING.values())
        sheet = fusion_stylesheet('dark')
        self.assertNotIn('font-size:11px', sheet)
        for role in ('heading', 'section', 'body', 'secondary', 'caption', 'brand'):
            self.assertIn('font-size:%dpx' % TYPE[role], sheet)
        gui = (ROOT / 'src/wam_regtest/bip39_fusion_gui.py').read_text()
        self.assertIn("SHELL['sidebar_width']", gui)
        self.assertNotIn('setFixedWidth(232)', gui)
        self.assertNotIn('palette(mid)', gui)

    def test_focus_style_covers_each_focusable_control(self):
        for mode in ('dark', 'light'):
            colors = fusion_palette(mode)
            sheet = fusion_stylesheet(mode)
            for selector in FOCUS_SELECTORS:
                self.assertIn(selector, sheet, selector)
            for line in sheet.splitlines():
                if ':focus' in line:
                    self.assertIn('[keyboardFocus="true"]', line, line)
            # The ring is the accent colour. It has to clear 3:1 against the
            # surfaces those controls sit on (WCAG non-text contrast).
            for surface in ('bg', 'surface', 'panel', 'tint', 'sidebar'):
                ratio = _contrast(colors['focus'], colors[surface])
                self.assertGreaterEqual(ratio, 3.0, (mode, surface, round(ratio, 2)))
            # A checked primary control is filled with accent, so its focus
            # border uses on-accent, which already clears the accent fill.
            self.assertGreaterEqual(
                _contrast(colors['onaccent'], colors['accent']), 3.0, mode)
        switch = (ROOT / 'src/wam_regtest/fusion_ui.py').read_text()
        self.assertIn("QPen(QColor(colors['focus']), FOCUS)", switch)
        self.assertIn("property('keyboardFocus')", switch)
        self.assertNotIn('setTabFocusBehavior', switch)
        self.assertNotIn('TabFocusAllControls', switch)
        self.assertGreaterEqual(FOCUS, 2)

    def test_qr_colours_come_from_the_token_table(self):
        self.assertEqual(QR['paper'], '#FFFFFF')
        self.assertEqual(QR['ink'], '#101010')
        self.assertNotEqual(QR['paper'], QR['ink'])


class SidebarBrandFit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def test_system_keyboard_navigation_is_left_alone(self):
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QCheckBox
        shell = (ROOT / 'src/wam_regtest/fusion_ui.py').read_text()
        gui = (ROOT / 'src/wam_regtest/bip39_fusion_gui.py').read_text()
        self.assertNotIn('setTabFocusBehavior', shell + gui)
        self.assertNotIn('enable_shell_tab_focus', shell + gui)
        self.assertNotIn("FocusPolicy.NoFocus", shell)
        box = QCheckBox('Reduce interface motion')
        switch = StateSwitch('Locked')
        self.addCleanup(box.deleteLater)
        self.addCleanup(switch.deleteLater)
        self.assertEqual(switch.focusPolicy(), box.focusPolicy())

    def test_page_scroll_still_moves_on_page_down(self):
        from PySide6.QtCore import Qt
        from PySide6.QtTest import QTest
        from PySide6.QtWidgets import QWidget
        scroll, layout = page('Title', 'subtitle')
        self.addCleanup(scroll.deleteLater)
        filler = QWidget()
        filler.setMinimumHeight(1800)
        filler.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        layout.addWidget(filler)
        scroll.resize(420, 280)
        scroll.show()
        self.assertNotEqual(scroll.focusPolicy(), Qt.FocusPolicy.NoFocus)
        scroll.setFocus(Qt.FocusReason.TabFocusReason)
        self.app.processEvents()
        self.assertIs(self.app.focusWidget(), scroll)
        before = scroll.verticalScrollBar().value()
        QTest.keyClick(scroll, Qt.Key.Key_PageDown)
        self.app.processEvents()
        self.assertGreater(scroll.verticalScrollBar().value(), before)

    def test_focus_ring_follows_keyboard_and_not_the_mouse(self):
        from PySide6.QtCore import QEvent, Qt
        from PySide6.QtGui import QFocusEvent
        from PySide6.QtWidgets import QPushButton
        from wam_regtest.fusion_ui import _KeyboardFocusMark
        button = QPushButton('Refresh')
        self.addCleanup(button.deleteLater)
        marker = _KeyboardFocusMark(button)
        self.addCleanup(marker.deleteLater)

        def deliver(kind, reason):
            self.assertFalse(marker.eventFilter(button, QFocusEvent(kind, reason)))

        deliver(QEvent.Type.FocusIn, Qt.FocusReason.MouseFocusReason)
        self.assertFalse(bool(button.property('keyboardFocus')))
        deliver(QEvent.Type.FocusIn, Qt.FocusReason.OtherFocusReason)
        self.assertFalse(bool(button.property('keyboardFocus')))
        deliver(QEvent.Type.FocusIn, Qt.FocusReason.ActiveWindowFocusReason)
        self.assertFalse(bool(button.property('keyboardFocus')))
        deliver(QEvent.Type.FocusIn, Qt.FocusReason.TabFocusReason)
        self.assertTrue(bool(button.property('keyboardFocus')))
        deliver(QEvent.Type.FocusIn, Qt.FocusReason.BacktabFocusReason)
        self.assertTrue(bool(button.property('keyboardFocus')))
        deliver(QEvent.Type.FocusOut, Qt.FocusReason.MouseFocusReason)
        self.assertFalse(bool(button.property('keyboardFocus')))

    def test_brand_breaks_on_words_in_every_language(self):
        from PySide6.QtWidgets import QLabel
        width = SHELL['sidebar_width'] - 2 * SHELL['sidebar_pad_x']
        for language, catalog in CATALOG.items():
            text = catalog['wallet.brand']
            label = QLabel()
            label.setObjectName('BrandTitle')
            self.addCleanup(label.deleteLater)
            present_brand_title(label, text, width, '#9B742E')
            shown = label.text()
            self.assertEqual(shown.replace('\n', ' '), text, language)
            for line in shown.split('\n'):
                self.assertGreater(len(line.strip()), 1, (language, shown))
            if language == 'en':
                # English fits one line, so the visible words stay the catalog string.
                self.assertNotIn('\n', shown)
            if language == 'ja':
                # The sidebar now fits the Japanese brand on one line, so the
                # catalog string shows unbroken (no orphaned single CJK char,
                # which the per-line check above already forbids everywhere).
                self.assertNotIn('\n', shown)
