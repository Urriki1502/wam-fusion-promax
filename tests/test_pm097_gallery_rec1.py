"""PM-097: REC-1 gallery scenes and History detail wrapped-text growth."""
import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QSizePolicy

from wam_regtest import bip39_locale
from wam_regtest.presentation.strings import CATALOG, SUPPORTED_LANGUAGES
from wam_regtest.wallet_executor import ExecutorState

REC1_SCENES = (
    ('10b-history-rec1-uncertain', 'BROADCAST_OUTCOME_UNCERTAIN',
     'OPERATOR_REVIEW_OBSERVATION_CONTRADICTION', 'unknown'),
    ('10c-history-rec1-not-observed', 'NOT_OBSERVED_LOCALLY',
     'UNCERTAIN_NOT_OBSERVED_RESUMABLE', 'uncertain'),
    ('10d-history-rec1-corrupted', 'CORRUPTED_EVIDENCE',
     'OPERATOR_REVIEW_MIXED_STATE', 'mixed'),
)

RAW_TOKEN = re.compile(
    r'\b(?:BROADCAST_OUTCOME_UNCERTAIN|NOT_OBSERVED_LOCALLY|CORRUPTED_EVIDENCE|'
    r'UNCLASSIFIED|CONFIRMED|IN_LOCAL_MEMPOOL|CONFLICTED|REJECTED_BY_POLICY|'
    r'Q06_[A-Z0-9_]+|OPERATOR_REVIEW_[A-Z0-9_]+|REC2_[A-Z0-9_]+|'
    r'SIGNED_NOT_SUBMITTED_RESUMABLE|UNCERTAIN_NOT_OBSERVED_RESUMABLE|'
    r'CONFIRMED_IN_VERIFIED_HISTORY|IN_MEMPOOL_AWAITING_CONFIRMATION|'
    r'WALLET_[A-Z0-9_]+)\b'
)


class HistoryDetailRec1WrapsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def test_detail_values_grows_and_fits_wrapped_rec1_text(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.fusion_pages import HistoryPage
        from wam_regtest.qualification.ui_gallery import (
            TXIDS, _fixture_snapshot, _label_text_size,
        )

        probe = HistoryPage()
        self.addCleanup(probe.deleteLater)
        self.assertTrue(probe.detail_values.wordWrap())
        self.assertEqual(
            probe.detail_values.sizePolicy().verticalPolicy(),
            QSizePolicy.Policy.Minimum,
        )
        self.assertTrue(probe.detail_values.sizePolicy().hasHeightForWidth())

        _snap, result = _fixture_snapshot()
        for language in SUPPORTED_LANGUAGES:
            with patch.object(bip39_locale, '_lang', return_value=language):
                executor = SimpleNamespace(
                    state=ExecutorState(locked=False, faulted=False, core_alive=True),
                    busy=False, closed=False,
                )
                window = Bip39FusionWindow(executor)
                window._poll.stop()
                window.reduce_motion.setChecked(True)
                window.resize(900, 630)
                window.show()
                window.appearance_buttons[2].click()
                window._ready = True
                window._spend_enabled = True
                window._render_verified(result)
                window._set_actions()
                window.navigation.setCurrentRow(2)
                window.history_page.table.selectRow(0)
                self.app.processEvents()
                try:
                    for scene_name, rec1_state, classification, intent_state in REC1_SCENES:
                        with self.subTest(language=language, scene=scene_name):
                            window._on_ready('intent_status', {'intents': [{
                                'token': 'ab' * 16,
                                'txid': TXIDS[0],
                                'classification': classification,
                                'state': intent_state,
                                'rec1_state': rec1_state,
                            }]})
                            for _ in range(5):
                                self.app.processEvents()
                            detail = window.history_page.detail_values
                            rect = detail.contentsRect()
                            self.assertGreater(rect.width(), 0)
                            _need_w, need_h = _label_text_size(detail, rect.width())
                            hfw = detail.heightForWidth(rect.width())
                            self.assertGreater(hfw, 0)
                            self.assertGreaterEqual(
                                rect.height() + 1, need_h,
                                f'{language} {scene_name}: detail_values clipped '
                                f'(have={rect.height()}, need={need_h}, hfw={hfw})',
                            )
                            self.assertGreaterEqual(
                                detail.height(), hfw,
                                f'{language} {scene_name}: height {detail.height()} < hfw {hfw}',
                            )
                            self.assertFalse(window.resume.isEnabled())
                finally:
                    window._closed = True
                    window.hide()
                    window.deleteLater()
                    self.app.processEvents()


class GalleryRec1ScenesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from wam_regtest.desktop import qt_application
        cls.app = qt_application()

    def test_render_gallery_en_and_vi_includes_rec1_scenes(self):
        from wam_regtest.qualification.ui_gallery import render_gallery
        from test_pm024_ui_gallery import SCENES_PER_WINDOW

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'gallery'
            report = render_gallery(
                out, languages=('en', 'vi'), sizes=((900, 630),), themes=((2, 'dark'),),
            )
            self.assertEqual(report['scene_count'], SCENES_PER_WINDOW * 2)
            self.assertEqual(report['finding_count'], 0, report['findings'])
            for language in ('en', 'vi'):
                for scene_name, _state, _cls, _istate in REC1_SCENES:
                    full = f'{scene_name}--{language}-900x630-dark'
                    self.assertIn(full, report['scenes'])
                    self.assertTrue((out / f'{full}.png').stat().st_size > 1000, full)

    def test_rec1_scenes_render_product_copy_without_raw_tokens_or_submit_and_restore_state(self):
        from wam_regtest.fusion_pages import rec1_status_line
        from wam_regtest.qualification.ui_gallery import _render_window
        from wam_regtest.ui_settings import ui_settings
        from wam_regtest.wallet_executor import ExecutorState

        previous = os.environ.get('WAM_UI_SETTINGS_PATH')
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ['WAM_UI_SETTINGS_PATH'] = os.path.join(tmp, 'ui-settings.ini')
                for language in ('en', 'vi'):
                    store = ui_settings()
                    store.setValue('ui_language', language)
                    store.sync()
                    captured = {}
                    findings = []

                    def shoot(widget, full_name):
                        scene_name = full_name.split('--', 1)[0]
                        if hasattr(widget, 'history_page'):
                            captured[scene_name] = {
                                'detail': widget.history_page.detail_values.text(),
                                'status': widget.status.text(),
                                'resume_enabled': widget.resume.isEnabled(),
                                'resumable_intent': widget._resumable_intent,
                                'rec1_map': dict(getattr(widget.history_page, '_rec1_by_txid', {})),
                            }

                    def settle():
                        for _ in range(5):
                            self.app.processEvents()

                    _render_window(
                        language, 900, 630, 2, 'dark',
                        shoot, settle, findings, ExecutorState,
                    )
                    self.assertEqual(findings, [], (language, findings))
                    for scene_name, state, _cls, _istate in REC1_SCENES:
                        with self.subTest(language=language, scene=scene_name):
                            snap = captured[scene_name]
                            expected_key_text = CATALOG[language][f'rec1.{state}']
                            expected_line = rec1_status_line(state, language)
                            status_clean = snap['status'].replace('\u200b', '')

                            self.assertTrue(snap['detail'].endswith('\n' + expected_line))
                            self.assertTrue(status_clean.endswith('\n' + expected_line))
                            self.assertIn(expected_key_text, snap['detail'])
                            self.assertIn(expected_key_text, status_clean)
                            if state == 'BROADCAST_OUTCOME_UNCERTAIN':
                                self.assertEqual(
                                    expected_line,
                                    expected_key_text + CATALOG[language]['pages.no_retry_until_confirmed'],
                                )
                            else:
                                self.assertEqual(expected_line, expected_key_text)
                                self.assertEqual(snap['detail'].splitlines()[-1], expected_key_text)
                                self.assertEqual(status_clean.splitlines()[-1], expected_key_text)

                            self.assertIsNone(RAW_TOKEN.search(snap['detail']), snap['detail'])
                            self.assertIsNone(RAW_TOKEN.search(status_clean), status_clean)
                            self.assertFalse(snap['resume_enabled'])
                            self.assertIsNone(snap['resumable_intent'])

                    # State restored afterwards so subsequent scenes are unaffected
                    self.assertEqual(captured['10-history-detail']['rec1_map'], {})
                    self.assertEqual(captured['10-history-detail']['status'], '')
                    self.assertEqual(captured['11-status-refusal']['rec1_map'], {})
                    self.assertFalse(captured['11-status-refusal']['resume_enabled'])
                    self.assertIsNone(captured['11-status-refusal']['resumable_intent'])
        finally:
            if previous is None:
                os.environ.pop('WAM_UI_SETTINGS_PATH', None)
            else:
                os.environ['WAM_UI_SETTINGS_PATH'] = previous


if __name__ == '__main__':
    unittest.main()
