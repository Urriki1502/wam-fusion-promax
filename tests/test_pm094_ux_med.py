"""PM-094: no raw codes on screen, named controls, one theme control.

Presentation only. REGTEST and Core P2P stay technical terms in the Welcome
checkbox; the remaining Vietnamese words are translated. PM-090 sentences are
reused for the three classifications that already have that exact claim.
"""
import json
import os
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractButton, QAbstractItemView, QAbstractSpinBox, QApplication,
    QComboBox, QFrame, QHeaderView, QLabel, QLineEdit, QScrollBar, QTextEdit,
    QWidget,
)

from wam_regtest.bip39_locale import t
from wam_regtest.gui_errors import error_text, public_code
from wam_regtest.presentation.strings import CATALOG, SUPPORTED_LANGUAGES
from wam_regtest.wallet_executor import ExecutorState

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / 'tests/pm094_english_literals.json').read_text())
ENGLISH = FIXTURE['english']
REUSED = FIXTURE['reused_from']
PRIOR_CATALOG_KEYS = 808  # PM-103: 15 decorative keys retired; General added.
RAW_CODE = re.compile(
    r'\b(?:Q06_[A-Z0-9_]+|OPERATOR_REVIEW_[A-Z0-9_]+|REC2_[A-Z0-9_]+|'
    r'SIGNED_NOT_SUBMITTED_RESUMABLE|UNCERTAIN_NOT_OBSERVED_RESUMABLE|'
    r'CONFIRMED_IN_VERIFIED_HISTORY|IN_MEMPOOL_AWAITING_CONFIRMATION|'
    r'WALLET_[A-Z0-9_]+)\b')
CLASSIFICATIONS = (
    'OPERATOR_REVIEW_MIXED_STATE',
    'OPERATOR_REVIEW_EVIDENCE_INVALID',
    'OPERATOR_REVIEW_SIGNED_EVIDENCE_MISSING',
    'OPERATOR_REVIEW_EVIDENCE_INPUT_MISMATCH',
    'OPERATOR_REVIEW_CORRUPTED_EVIDENCE_QUARANTINED',
    'OPERATOR_REVIEW_INPUT_SPENT_OR_CONFLICTED',
    'OPERATOR_REVIEW_OBSERVATION_CONTRADICTION',
    'SIGNED_NOT_SUBMITTED_RESUMABLE',
    'UNCERTAIN_NOT_OBSERVED_RESUMABLE',
    'CONFIRMED_IN_VERIFIED_HISTORY',
    'IN_MEMPOOL_AWAITING_CONFIRMATION',
    'NOT_A_PUBLIC_CLASSIFICATION',
)
SCREENS = (
    (0, 'overview'),
    (1, 'receive'),
    (2, 'history'),
    (3, 'send'),
    (6, 'settings'),
)
_INTERACTIVE = (QAbstractButton, QLineEdit, QComboBox, QAbstractItemView, QTextEdit, QAbstractSpinBox)


def _surfaces(root):
    chunks = []
    widgets = [root, *root.findChildren(QWidget)]
    for widget in widgets:
        for name in ('toolTip', 'accessibleName', 'accessibleDescription', 'windowTitle', 'placeholderText'):
            accessor = getattr(widget, name, None)
            if not callable(accessor):
                continue
            try:
                value = accessor()
            except TypeError:
                continue
            if isinstance(value, str) and value:
                chunks.append(value)
        accessor = getattr(widget, 'text', None)
        if callable(accessor):
            try:
                value = accessor()
            except TypeError:
                value = ''
            if isinstance(value, str) and value:
                chunks.append(value)
        if hasattr(widget, 'toPlainText'):
            value = widget.toPlainText()
            if value:
                chunks.append(value)
    return chunks


def _interactive(root):
    found = []
    for widget in root.findChildren(QWidget):
        if not isinstance(widget, _INTERACTIVE) or isinstance(widget, QHeaderView):
            continue
        parent = widget.parentWidget()
        skip = False
        while parent is not None:
            if isinstance(parent, QScrollBar):
                skip = True
                break
            parent = parent.parentWidget()
        if not skip:
            found.append(widget)
    return found


def _assert_no_raw(testcase, root):
    for value in _surfaces(root):
        testcase.assertIsNone(RAW_CODE.search(value), value)


class CatalogMapping(unittest.TestCase):
    def test_new_keys_exist_in_every_locale_and_reuse_pm090_claims(self):
        self.assertEqual(len(CATALOG['en']), PRIOR_CATALOG_KEYS + len(ENGLISH))
        for language, entries in CATALOG.items():
            self.assertEqual(len(entries), PRIOR_CATALOG_KEYS + len(ENGLISH), language)
            for key, english in ENGLISH.items():
                self.assertEqual(CATALOG['en'][key], english, key)
                self.assertIn(key, entries)
                self.assertTrue(entries[key].strip(), (language, key))
                if language != 'en' and key not in REUSED:
                    self.assertNotEqual(entries[key], english, (language, key))
            for key, source in REUSED.items():
                self.assertEqual(entries[key], entries[source], (language, key))
        # REGTEST and Core P2P stay technical terms. "Shared" does not.
        vi = CATALOG['vi']['welcome.shared_regtest_manual_core_p2p']
        self.assertEqual(vi, FIXTURE['vi_shared_regtest_manual_core_p2p'])
        self.assertIn('REGTEST', vi)
        self.assertIn('Core P2P', vi)
        self.assertNotIn('Shared', vi)
        self.assertNotIn('manual', vi.lower())

    def test_public_code_and_error_text_hide_unknown_tokens_in_every_locale(self):
        from wam_regtest import bip39_locale
        for language in SUPPORTED_LANGUAGES:
            with self.subTest(language=language), patch.object(
                    bip39_locale, '_lang', return_value=language):
                for key, english in ENGLISH.items():
                    if not key.startswith('errors.'):
                        continue
                    code = key.removeprefix('errors.')
                    self.assertEqual(public_code(code), code)
                    shown = error_text(code)
                    self.assertEqual(shown, CATALOG[language][key])
                    self.assertIsNone(RAW_CODE.search(shown), shown)
                self.assertEqual(public_code('Q06_FUSION_VERIFIED_SNAPSHOT_DENIED',
                                              fallback='WALLET_SYNC_UNVERIFIED'),
                                 'WALLET_SYNC_UNVERIFIED')
                self.assertEqual(
                    error_text(public_code('Q06_FUSION_PRESENTATION_DENIED')),
                    CATALOG[language]['errors.WALLET_OPERATION_DENIED_STATE_RETAINED'])
                self.assertEqual(public_code('NOT_A_PUBLIC_CODE'),
                                 'WALLET_OPERATION_DENIED_STATE_RETAINED')
                fallback = error_text('NOT_A_PUBLIC_CODE')
                self.assertEqual(fallback, CATALOG[language]['errors.WALLET_OPERATION_DENIED_STATE_RETAINED'])
                self.assertNotIn('NOT_A_PUBLIC_CODE', fallback)


class IntentStatus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def setUp(self):
        from wam_regtest.bip39_owner_gui import Bip39TrialWindow
        owner = SimpleNamespace(
            state=ExecutorState(locked=False, faulted=False, core_alive=True),
            busy=False, closed=False)
        self.window = Bip39TrialWindow(owner)
        self.window._poll.stop()

    def tearDown(self):
        self.window._poll.stop()
        self.window.deleteLater()
        self.app.processEvents()

    def test_classification_counts_are_localized_messages(self):
        for code in CLASSIFICATIONS:
            with self.subTest(code=code):
                self.window._on_ready('intent_status', {'intents': [{
                    'classification': code,
                    'rec1_state': None,
                    'state': 'unknown',
                }]})
                shown = self.window.status.text()
                self.assertIsNone(RAW_CODE.search(shown), shown)
                self.assertNotIn(code, shown)
                expected = error_text(public_code(code))
                self.assertIn(expected, shown)
                self.assertIn(t('owner.intent_protected'), shown)
                _assert_no_raw(self, self.window)


class FusionScreens(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def setUp(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.fusion_ui import ThemeSlider
        from wam_regtest.wallet_read import WalletReadSnapshot
        self.ThemeSlider = ThemeSlider
        owner = SimpleNamespace(
            state=ExecutorState(locked=True, faulted=False, core_alive=True),
            busy=False, closed=False)
        self.window = Bip39FusionWindow(owner)
        self.window._poll.stop()
        self.window.resize(1260, 810)
        self.window.show()
        self.app.processEvents()
        self.snapshot = WalletReadSnapshot(
            'regtest', 4, 'ab' * 32, 'wamrtsp1example', 1000, 1, (), 'cd' * 32)

    def tearDown(self):
        self.window._poll.stop()
        self.window.deleteLater()
        self.app.processEvents()

    def _page(self, index):
        self.window.navigation.setCurrentRow(index)
        self.window.resize(1260, 810)
        self.app.processEvents()
        return self.window.stack.widget(index)

    def test_denials_use_public_messages_on_every_surface(self):
        self.window._render_verified({'fusion_snapshot': None})
        status = self.window.status.text().replace('\u200b', '')
        self.assertEqual(status, error_text(public_code(
            'Q06_FUSION_VERIFIED_SNAPSHOT_DENIED', fallback='WALLET_SYNC_UNVERIFIED')))
        self.assertNotIn('Q06_FUSION_VERIFIED_SNAPSHOT_DENIED', status)
        _assert_no_raw(self, self.window)

        result = {
            'fusion_snapshot': self.snapshot,
            'receive_code': self.snapshot.receive_code,
            'confirmed_atoms': self.snapshot.confirmed_atoms,
            'signer_allowed': False,
            'broadcast_allowed': False,
        }
        original = self.window.overview.render_snapshot

        def deny(snap, *args, **kwargs):
            if snap is not None:
                raise ValueError('Q06_FUSION_PRESENTATION_DENIED secret path /tmp/wallet')
            return original(snap, *args, **kwargs)

        self.window.overview.render_snapshot = deny
        try:
            self.window._render_verified(result)
        finally:
            self.window.overview.render_snapshot = original
        status = self.window.status.text().replace('\u200b', '')
        self.assertEqual(status, error_text('WALLET_OPERATION_DENIED_STATE_RETAINED'))
        self.assertNotIn('Q06_FUSION_PRESENTATION_DENIED', status)
        self.assertNotIn('secret path', status)
        self.assertNotIn('/tmp/wallet', status)
        _assert_no_raw(self, self.window)

    def test_settings_is_the_only_theme_control(self):
        sliders = self.window.findChildren(self.ThemeSlider)
        self.assertEqual(sliders, [self.window.settings_theme])
        self.assertFalse(hasattr(self.window, 'header_theme'))
        self.assertIs(self.window.appearance_group, self.window.settings_theme.group)
        self.assertIs(self.window.appearance_buttons, self.window.settings_theme.buttons)
        self.assertEqual(self.window.findChildren(QFrame, 'FusionDivider'), [])
        self.assertNotIn(t('wallet.theme'), [label.text() for label in self.window.findChildren(QLabel)])
        settings = self._page(6)
        self.assertTrue(settings.isAncestorOf(self.window.settings_theme))
        self.window.settings_theme.buttons[1].click()
        self.app.processEvents()
        from wam_regtest.ui_settings import ui_settings
        self.assertEqual(int(ui_settings().value('fusion_appearance')), 1)
        self.assertEqual(self.window.settings_theme.currentIndex(), 1)
        self.assertEqual(self.window.appearance_group.checkedId(), 1)
        for page_index, _name in SCREENS:
            if page_index == 6:
                continue
            page = self._page(page_index)
            self.assertEqual(page.findChildren(self.ThemeSlider), [])

    def test_every_interactive_widget_has_a_localized_accessible_name(self):
        from wam_regtest.managed_onboarding import welcome_dialog
        described = {
            self.window.recipient_input: 'wallet.recipient_accessible_description',
            self.window.amount_input: 'wallet.amount_accessible_description',
            self.window.send: 'wallet.review_payment_description',
            self.window.activate: 'wallet.enable_sending_description',
            self.window.broadcast: 'wallet.approve_broadcast_description',
            self.window.cancel: 'wallet.cancel_draft_description',
            self.window.receive_page.copy_button: 'pages.copy_full_address_description',
            self.window.reduce_motion: 'wallet.reduce_motion_description',
        }
        self.assertEqual(self.window.recipient_input.accessibleName(), t('wallet.recipient_accessible'))
        self.assertEqual(self.window.amount_input.accessibleName(), t('wallet.amount_accessible'))
        self.assertNotEqual(self.window.recipient_input.accessibleName(),
                            self.window.recipient_input.placeholderText())
        self.assertEqual(self.window.history_page.filter.accessibleName(), t('pages.history_type_filter'))
        self.assertEqual(self.window.reduce_motion.accessibleName(), t('wallet.reduce_motion'))
        for widget, key in described.items():
            self.assertEqual(widget.accessibleDescription(), t(key), key)
        missing = []
        for index, name in SCREENS:
            page = self._page(index)
            widgets = _interactive(page)
            self.assertTrue(widgets, name)
            for widget in widgets:
                label = widget.accessibleName()
                if not label.strip():
                    missing.append((name, type(widget).__name__, widget.objectName()))
                    continue
                self.assertIsNone(RAW_CODE.search(label), label)
                if (widget.isVisible() and widget.isEnabled()
                        and widget.focusPolicy() != Qt.FocusPolicy.NoFocus):
                    widget.setFocus()
                    self.app.processEvents()
                    self.assertIs(QApplication.focusWidget(), widget)
            _assert_no_raw(self, page)
        self.assertEqual(missing, [])
        welcome = welcome_dialog()
        self.addCleanup(welcome.deleteLater)
        checkbox = welcome.shared_mode
        self.assertEqual(checkbox.accessibleName(), t('welcome.shared_regtest_manual_core_p2p'))
        self.assertTrue(checkbox.accessibleName().strip())
        for widget in _interactive(welcome):
            self.assertTrue(widget.accessibleName().strip(), type(widget).__name__)
        _assert_no_raw(self, welcome)
