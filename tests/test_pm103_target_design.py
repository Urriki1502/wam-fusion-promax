"""PM-103 presentation contracts; inert executor, no wallet or Core."""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtWidgets import QApplication
from wam_regtest.desktop import qt_application
from wam_regtest.wallet_executor import ExecutorState
from wam_regtest.bip39_fusion_gui import Bip39FusionWindow

class TargetDesign(unittest.TestCase):
    def setUp(self):
        qt_application()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        old = os.environ.get('WAM_UI_SETTINGS_PATH')
        os.environ['WAM_UI_SETTINGS_PATH'] = str(Path(self.tmp.name) / 'ui.ini')
        self.addCleanup(lambda: os.environ.pop('WAM_UI_SETTINGS_PATH', None) if old is None else os.environ.__setitem__('WAM_UI_SETTINGS_PATH', old))
        self.w = Bip39FusionWindow(SimpleNamespace(state=ExecutorState(), busy=False, closed=False))
        self.w._poll.stop()
        self.addCleanup(self.w.deleteLater)

    def refresh(self):
        self.w._set_actions()
        QApplication.processEvents()

    def test_default_dark_and_six_live_language_tiles_keep_system(self):
        self.assertEqual(self.w.settings_theme.currentIndex(), 2)
        self.assertEqual(set(self.w.language_tiles), {'en','vi','zh-Hans','ja','ko','id'})
        executor = self.w.executor
        self.w.language_tiles['vi'].click()
        self.assertEqual(self.w.language.currentData(), 'vi')
        self.assertIs(self.w.executor, executor)
        self.assertTrue(self.w.language_tiles['vi'].isChecked())
        self.assertEqual(self.w.language.itemData(0), 'system')

    def test_visibility_changes_with_workflow_not_busy_or_lock(self):
        w = self.w
        self.refresh()
        self.assertFalse(w.activate.isHidden())
        self.assertTrue(w.broadcast.isHidden())
        self.assertTrue(w.cancel.isHidden())
        self.assertFalse(w.inspect.isHidden())
        self.assertFalse(w.intents.isHidden())
        self.assertTrue(w.resume.isHidden())
        w._spend_enabled = True
        w._approved_commitment = 'exact'
        self.refresh()
        self.assertTrue(w.activate.isHidden())
        self.assertFalse(w.cancel.isHidden())
        w.executor.busy = True
        self.refresh()
        self.assertFalse(w.cancel.isHidden())
        self.assertFalse(w.cancel.isEnabled())
        w.executor.busy = False
        w._signed_ready = True
        self.refresh()
        self.assertTrue(w.cancel.isHidden())
        self.assertTrue(w.broadcast.isHidden(), 'no exact current review')
        w._last_review = SimpleNamespace(commitment='exact')
        self.refresh()
        self.assertFalse(w.broadcast.isHidden())
        self.assertFalse(w.broadcast.isEnabled())
        w._last_review = SimpleNamespace(commitment='stale')
        self.refresh()
        self.assertTrue(w.broadcast.isHidden())

    def test_restart_unsigned_cancel_and_resume_remain_discoverable(self):
        w = self.w
        w._spend_enabled = True
        w._recovered_unsigned_cancel = True
        self.refresh()
        self.assertFalse(w.cancel.isHidden())
        w._recovered_unsigned_cancel = False
        w._resumable_intent = {'token': 'verified'}
        self.refresh()
        self.assertFalse(w.resume.isHidden())
        self.assertFalse(w.inspect.isHidden())
        self.assertFalse(w.intents.isHidden())

    def test_restore_scope_always_present_after_reopen(self):
        self.assertFalse(self.w.restore_scope_notice.isHidden())
        self.w._restored_session = False
        self.refresh()
        self.assertFalse(self.w.restore_scope_notice.isHidden())

    def test_saved_light_is_respected(self):
        from wam_regtest.ui_settings import ui_settings
        ui_settings().setValue('fusion_appearance', 1)
        another = Bip39FusionWindow(SimpleNamespace(state=ExecutorState(), busy=False, closed=False))
        another._poll.stop()
        self.addCleanup(another.deleteLater)
        self.assertEqual(another.settings_theme.currentIndex(), 1)

    def test_removed_keys_absent_from_every_locale_and_runtime_source(self):
        import json
        from wam_regtest.presentation.strings import CATALOG
        root = Path(__file__).resolve().parents[1]
        retired = json.loads((root / 'tests/pm103_retired_keys.json').read_text())
        for key in retired:
            for language, catalog in CATALOG.items():
                self.assertNotIn(key, catalog, (key, language))
            for path in (root / 'src').rglob('*.py'):
                self.assertNotIn(repr(key), path.read_text(), str(path))
                self.assertNotIn('"' + key + '"', path.read_text(), str(path))

    def test_focus_moves_to_recipient_when_a_workflow_action_disappears(self):
        w = self.w
        w.executor.state = ExecutorState(locked=False, core_alive=True)
        w._ready = w._spend_enabled = True
        w._approved_commitment = 'unsigned'
        w.reduce_motion.setChecked(True)
        w.navigation.setCurrentRow(3)
        w.show()
        self.refresh()
        w.cancel.setFocus()
        QApplication.processEvents()
        self.assertTrue(w.cancel.hasFocus())
        w._approved_commitment = None
        self.refresh()
        self.assertTrue(w.recipient_input.hasFocus())

    def test_three_short_steps_and_labeled_settings_categories(self):
        from PySide6.QtCore import Qt
        self.assertEqual(len(self.w.payment_steps.labels), 3)
        self.assertEqual(len(self.w.settings_categories), 5)
        for button in self.w.settings_categories:
            self.assertTrue(button.text())
            self.assertEqual(button.toolButtonStyle(), Qt.ToolButtonStyle.ToolButtonTextBesideIcon)

    def test_control_focus_and_disabled_contrast_in_both_themes(self):
        from wam_regtest.fusion_ui import fusion_palette
        def luminance(h):
            rgb = [int(h[i:i+2], 16)/255 for i in (1,3,5)]
            return sum(k*(v/12.92 if v <= .04045 else ((v+.055)/1.055)**2.4)
                       for k,v in zip((.2126,.7152,.0722), rgb))
        def ratio(a,b):
            x,y = sorted((luminance(a), luminance(b)))
            return (y+.05)/(x+.05)
        for theme in ('dark','light'):
            c = fusion_palette(theme)
            for surface in ('surface','panel','bg'):
                self.assertGreaterEqual(ratio(c['control'], c[surface]), 3, (theme,surface))
                self.assertGreaterEqual(ratio(c['focus'], c[surface]), 3, (theme,surface))
                self.assertGreaterEqual(ratio(c['muted'], c[surface]), 4.5, (theme,surface))
            self.assertGreaterEqual(ratio(c['disabled_fg'], c['disabled_bg']), 4.5)
            for fill in ('cta_start','cta_end'):
                self.assertGreaterEqual(ratio(c['onaccent'], c[fill]), 4.5)

    def test_send_has_only_recipient_amount_and_no_mockup_features(self):
        from PySide6.QtWidgets import QLineEdit, QLabel, QAbstractButton
        w = self.w
        self.assertEqual(set(w.recipient_input.parentWidget().findChildren(QLineEdit)),
                         {w.recipient_input, w.amount_input})
        forbidden = ('Secure & Healthy', 'Up to date', 'Manage Wallet', 'Transfer', 'USD', 'QR scan', 'Address book')
        for widget in w.findChildren(QLabel) + w.findChildren(QAbstractButton):
            self.assertNotIn(widget.text(), forbidden)

    def test_settings_categories_keep_live_translation_before_first_visit(self):
        from wam_regtest.presentation.strings import text
        self.w.language_tiles['vi'].click()
        self.assertEqual(self.w.advanced_toggle.text(), text('wallet.show_developer','vi'))
        self.assertEqual(self.w.settings_categories[0].text(), text('settings.general','vi'))
        self.w.navigation.setCurrentRow(6)
        self.w.settings_categories[1].click()
        self.assertEqual(self.w.navigation.currentRow(), 4)
        self.w.navigation.setCurrentRow(6)
        self.w.settings_categories[2].click()
        self.assertEqual(self.w.navigation.currentRow(), 5)

    def test_settings_tiles_fit_minimum_width_in_every_locale(self):
        from PySide6.QtCore import QPoint
        for language in self.w.language_tiles:
            self.w.language_tiles[language].click()
            self.w.resize(900,630)
            self.w.reduce_motion.setChecked(True)
            self.w.navigation.setCurrentRow(6)
            self.w.settings_categories[3].click()
            self.w.show()
            for _ in range(6):QApplication.processEvents()
            settings_page = self.w.stack.widget(6)
            self.assertEqual(settings_page.horizontalScrollBar().maximum(), 0, language)
            for tile in self.w.language_tiles.values():
                self.assertGreaterEqual(tile.width(), tile.minimumSizeHint().width(), (language,tile.text()))

    def test_complete_payment_approval_fits_minimum_window(self):
        from wam_regtest.fusion_pages import PaymentApproval, approval_amount_text
        from wam_regtest.qualification.ui_gallery import _review
        from PySide6.QtWidgets import QLabel
        review = _review()
        self.w.resize(900,630)
        dialog = PaymentApproval(review, 'sign', self.w)
        self.addCleanup(dialog.deleteLater)
        dialog.show()
        for _ in range(6):QApplication.processEvents()
        self.assertLessEqual(dialog.height(),630)
        self.assertIn(approval_amount_text(review), [label.text() for label in dialog.findChildren(QLabel)])
        self.assertTrue(dialog.cancel.isDefault())
        self.assertFalse(dialog.approve.isDefault())
        dialog.reject()

    def test_history_filters_follow_programmatic_selection_and_clear(self):
        history = self.w.history_page
        history.filter.setCurrentIndex(2)
        self.assertTrue(history._filter_chips[2].isChecked())
        history.render_snapshot(None)
        self.assertTrue(history._filter_chips[0].isChecked())

    def test_reveal_hides_controls_even_under_hidden_page(self):
        from wam_regtest.fusion_pages import reveal
        from PySide6.QtWidgets import QWidget, QPushButton
        parent = QWidget()
        self.addCleanup(parent.deleteLater)
        button = QPushButton(parent)
        button.show()
        self.assertFalse(button.isHidden())
        self.assertFalse(button.isVisible())
        reveal(button, False)
        self.assertTrue(button.isHidden())

    def test_workflow_actions_have_distinct_stroke_icons(self):
        from wam_regtest.fusion_ui import vector_icon
        icons = ('review','broadcast','cancel','fund','confirm','search','signed','resume','quit')
        rendered = []
        for name in icons:
            pixmap = vector_icon(name, '#E9C56B').pixmap(24,24)
            rendered.append(pixmap.toImage().constBits().tobytes())
        self.assertEqual(len(set(rendered)), len(icons))

    def test_security_stacks_before_translated_actions_overflow(self):
        self.w.language_tiles['vi'].click()
        self.w.resize(1100,720)
        self.w.reduce_motion.setChecked(True)
        self.w.navigation.setCurrentRow(4)
        self.w.show()
        for _ in range(8):QApplication.processEvents()
        self.w._apply_fusion_theme()
        for _ in range(8):QApplication.processEvents()
        from wam_regtest.qualification.ui_gallery import _inspect
        findings = []
        _inspect(self.w, "security", findings)
        self.assertFalse([f for f in findings if f["kind"] == "H_SCROLL"], findings)

    def test_unknown_peer_count_is_not_rendered_as_zero(self):
        from wam_regtest.bip39_locale import t
        self.assertEqual(self.w.overview.network_card.detail.text(), t('pages.peers_after_check'))
        self.w.network_page.render(shared=False)
        self.assertEqual(self.w.network_page.peer_value.text(), t('pages.peers_after_check'))
