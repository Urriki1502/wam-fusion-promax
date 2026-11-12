"""PM-032: V0 R-10/R-11/R-12 keyboard fixes (trap, names, focus kept in view)."""
import tempfile
import unittest
from pathlib import Path


class KeyboardFixes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def test_tables_let_tab_leave_and_are_named(self):
        from wam_regtest.bip39_locale import t
        from wam_regtest.fusion_pages import HistoryPage
        from wam_regtest.fusion_ui import FusionOverview
        overview, history = FusionOverview(), HistoryPage()
        self.addCleanup(overview.deleteLater)
        self.addCleanup(history.deleteLater)
        self.assertFalse(overview.activity_table.tabKeyNavigation())
        self.assertFalse(history.table.tabKeyNavigation())
        self.assertEqual(overview.activity_table.accessibleName(), t('fusion.recent_transactions'))
        self.assertEqual(history.table.accessibleName(), t('pages.history'))
        self.assertEqual(overview.accessibleName(), t('fusion.overview'))

    def test_page_scroll_areas_take_their_title_as_name(self):
        from wam_regtest.fusion_ui import page
        scroll, _layout = page('Some title', 'subtitle')
        self.addCleanup(scroll.deleteLater)
        self.assertEqual(scroll.accessibleName(), 'Some title')

    def test_focused_control_is_scrolled_into_view(self):
        from PySide6.QtCore import QPoint
        from PySide6.QtWidgets import QPushButton, QWidget
        from wam_regtest.fusion_ui import page
        scroll, layout = page('Title', 'subtitle')
        self.addCleanup(scroll.deleteLater)
        near = QPushButton('Near the top')
        layout.addWidget(near)
        filler = QWidget()
        filler.setMinimumHeight(1500)
        layout.addWidget(filler)
        button = QPushButton('Far below')
        layout.addWidget(button)
        scroll.resize(400, 300)
        scroll.show()
        scroll.activateWindow()
        near.setFocus()
        scroll.verticalScrollBar().setValue(0)
        self.app.processEvents()
        self.assertEqual(scroll.verticalScrollBar().value(), 0)
        button.setFocus()
        self.app.processEvents()
        top = button.mapTo(scroll.viewport(), QPoint(0, 0)).y()
        self.assertGreater(scroll.verticalScrollBar().value(), 0)
        self.assertTrue(0 <= top <= scroll.viewport().height() - button.height())

    def test_interaction_probe_finds_no_trap_and_completes_the_cycle(self):
        from wam_regtest.qualification.ui_interaction import render_interaction
        with tempfile.TemporaryDirectory() as tmp:
            report = render_interaction(Path(tmp) / 'out')
        kinds = {f['kind'] for f in report['findings']}
        self.assertNotIn('FOCUS_TRAP', kinds)
        self.assertNotIn('FOCUS_UNLABELLED', kinds)
        self.assertNotIn('FOCUS_OUTSIDE', kinds)
        self.assertEqual(report['languages']['en']['termination'], 'CYCLE_COMPLETE')


if __name__ == '__main__':
    unittest.main()
