"""PM-090: truthful REC-1 status and a submit control only for signed-never-submitted.

Presentation only. No Core, no profile, and no change to REC-1 classification
or to the PM-088 refusal. Native-speaker review of the new translations is
owner-external.
"""
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from wam_regtest.bip39_locale import t
from wam_regtest.gui_errors import operation_error
from wam_regtest.presentation.strings import CATALOG, SUPPORTED_LANGUAGES
from wam_regtest.wallet_executor import ExecutorState
from wam_regtest.wallet_session import WalletSessionError

TXID = 'ab' * 32
TOKEN = 'cd' * 16
REC2 = 'REC2_UNCERTAIN_RESUBMIT_DEFERRED'

# Authoritative English. Other locales must carry the same claim, not a
# stronger one. BROADCAST_OUTCOME_UNCERTAIN reuses the PM-082 sentence.
ENGLISH = {
    'rec1.CONFIRMED': "Confirmed in this node's verified history.",
    'rec1.IN_LOCAL_MEMPOOL': (
        "Pending in this node's mempool. Not confirmed and not spendable."),
    'rec1.NOT_OBSERVED_LOCALLY': (
        'Not seen by this node. This does not mean the payment failed. '
        'Funds stay reserved and no automatic action is taken.'),
    'rec1.CONFLICTED': (
        'Conflicted with another transaction or an unavailable input. '
        'Reservations stay locked and nothing is released automatically.'),
    'rec1.REJECTED_BY_POLICY': (
        'Rejected by a recorded policy check. The payment record is unchanged '
        'and nothing is re-sent or released automatically.'),
    'rec1.BROADCAST_OUTCOME_UNCERTAIN': (
        'Broadcast outcome is unknown. This version does not re-send.'),
    'rec1.CORRUPTED_EVIDENCE': (
        "This payment's record could not be verified. It is kept unchanged and isolated."),
    'rec1.UNCLASSIFIED': (
        "This payment's broadcast state is not classified. Nothing is re-sent "
        'or released automatically.'),
    'errors.REC2_UNCERTAIN_RESUBMIT_DEFERRED': (
        'Uncertain re-submission is deferred in this version. The payment was '
        'not re-sent. Reserved inputs stay locked and are not released automatically.'),
}
STATES = (
    'CONFIRMED', 'IN_LOCAL_MEMPOOL', 'NOT_OBSERVED_LOCALLY', 'CONFLICTED',
    'REJECTED_BY_POLICY', 'BROADCAST_OUTCOME_UNCERTAIN', 'CORRUPTED_EVIDENCE',
)
PRIOR_CATALOG_KEYS = 814


def _signed(**extra):
    item = {
        'token': TOKEN, 'txid': TXID, 'state': 'signed',
        'classification': 'SIGNED_NOT_SUBMITTED_RESUMABLE',
        'rec1_state': 'NOT_OBSERVED_LOCALLY',
        'recipient': 'wamrtsp1example', 'atoms': 50_000, 'fee': 1000,
    }
    item.update(extra)
    return item


class Rec1Copy(unittest.TestCase):
    def test_new_english_is_authoritative_in_every_locale(self):
        from wam_regtest.fusion_pages import rec1_status_line
        # PM-103 retires redundant copy and adds the General category.
        import json
        from pathlib import Path
        retired = json.loads((Path(__file__).parent / 'pm103_retired_keys.json').read_text())
        expected_count = PRIOR_CATALOG_KEYS + len(ENGLISH) + 22 - len(retired) + 1
        self.assertEqual(len(CATALOG['en']), expected_count)
        for language, entries in CATALOG.items():
            self.assertEqual(len(entries), expected_count, language)
            for key, english in ENGLISH.items():
                self.assertEqual(CATALOG['en'][key], english, key)
                self.assertIn(key, entries)
                self.assertTrue(entries[key].strip(), (language, key))
                if language != 'en':
                    self.assertNotEqual(entries[key], english, (language, key))
                lowered = entries[key].lower()
                self.assertNotIn('rebroadcast available', lowered)
                self.assertNotIn('eligible', lowered)
        for language in SUPPORTED_LANGUAGES:
            for state in STATES:
                line = rec1_status_line(state, language)
                self.assertIn(CATALOG[language]['rec1.' + state], line)
                self.assertNotIn(state, line.split('\n')[0]) if state != 'CONFIRMED' else None
                if state == 'BROADCAST_OUTCOME_UNCERTAIN':
                    self.assertIn(CATALOG[language]['pages.no_retry_until_confirmed'], line)
                    self.assertNotIn('until confirmed', CATALOG['en']['pages.no_retry_until_confirmed'])
            missing = rec1_status_line(None, language)
            self.assertEqual(missing, CATALOG[language]['rec1.UNCLASSIFIED'])
            self.assertNotIn('REBROADCAST', missing)
        for language, entries in CATALOG.items():
            for value in entries.values():
                lowered = value.lower()
                self.assertNotIn('rebroadcast available', lowered)
                self.assertNotIn('eligible', lowered)

    def test_not_observed_locally_does_not_claim_payment_not_gone(self):
        self.assertEqual(
            CATALOG['en']['rec1.NOT_OBSERVED_LOCALLY'],
            'Not seen by this node. This does not mean the payment failed. '
            'Funds stay reserved and no automatic action is taken.')
        for language, entries in CATALOG.items():
            value = entries['rec1.NOT_OBSERVED_LOCALLY']
            self.assertNotIn('not gone', value.lower(), language)
            self.assertNotIn('chưa biến mất', value, language)
            self.assertNotIn('并未消失', value, language)
            self.assertNotIn('tidak hilang', value, language)
            self.assertNotIn('消えたわけではありません', value, language)
            self.assertNotIn('사라진 것은 아닙니다', value, language)


class SubmitOffer(unittest.TestCase):
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
        self.window._spend_enabled = True
        self.window._ready = True
        self.history = SimpleNamespace(states=None, calls=0)

        def set_rec1_states(states):
            self.history.states = dict(states)
            self.history.calls += 1

        self.history.set_rec1_states = set_rec1_states
        self.window.history_page = self.history

    def tearDown(self):
        self.window._poll.stop()
        self.window.deleteLater()
        self.app.processEvents()

    def _review(self, intents):
        self.window._on_ready('intent_status', {'intents': intents})
        return self.window.status.text()

    def test_submit_is_offered_only_for_one_signed_never_submitted_intent(self):
        status = self._review([_signed()])
        self.assertTrue(self.window.resume.isEnabled())
        self.assertEqual(self.window.resume.text(), t('owner.submit_signed'))
        self.assertEqual(self.window._resumable_intent['classification'],
                         'SIGNED_NOT_SUBMITTED_RESUMABLE')
        self.assertIn(t('owner.intent_resumable'), status)
        self.assertIn(t('rec1.NOT_OBSERVED_LOCALLY'), status)
        self.assertEqual(self.history.states, {TXID: 'NOT_OBSERVED_LOCALLY'})

    def test_uncertain_mixed_unknown_and_non_signed_do_not_enable_submit(self):
        from wam_regtest.fusion_pages import rec1_status_line
        cases = (
            _signed(classification='UNCERTAIN_NOT_OBSERVED_RESUMABLE',
                    state='uncertain', rec1_state='NOT_OBSERVED_LOCALLY'),
            _signed(classification='OPERATOR_REVIEW_MIXED_STATE',
                    state='mixed', rec1_state='CORRUPTED_EVIDENCE'),
            _signed(classification='OPERATOR_REVIEW_OBSERVATION_CONTRADICTION',
                    state='unknown', rec1_state='BROADCAST_OUTCOME_UNCERTAIN'),
            _signed(state='broadcast', rec1_state='IN_LOCAL_MEMPOOL'),
            _signed(classification='NOT_A_KNOWN_CLASS', state='unknown', rec1_state=None),
        )
        for item in cases:
            with self.subTest(classification=item['classification'], state=item['state']):
                self.window._resumable_intent = _signed()
                status = self._review([item])
                self.assertFalse(self.window.resume.isEnabled())
                self.assertIsNone(self.window._resumable_intent)
                self.assertNotIn(t('owner.intent_resumable'), status)
                self.assertIn(t('owner.intent_protected'), status)
                expected = rec1_status_line(item.get('rec1_state'))
                self.assertIn(expected, status)
                self.assertNotIn('rebroadcast available', status.lower())
                self.assertNotIn('eligible', status.lower())

    def test_a_second_signed_intent_is_not_offered(self):
        other = _signed(token='ef' * 16, txid='12' * 32)
        self._review([_signed(), other])
        self.assertFalse(self.window.resume.isEnabled())
        self.assertIsNone(self.window._resumable_intent)

    def test_race_refusal_is_localized_and_clears_the_offer(self):
        self.assertEqual(
            operation_error('resume_intent', WalletSessionError(REC2)), REC2)
        self._review([_signed()])
        self.assertTrue(self.window.resume.isEnabled())
        self.window._on_denied(REC2)
        shown = self.window.status.text()
        self.assertIn(t('errors.REC2_UNCERTAIN_RESUBMIT_DEFERRED'), shown)
        self.assertNotIn(REC2, shown)
        self.assertFalse(self.window.resume.isEnabled())
        self.assertIsNone(self.window._resumable_intent)

    def test_history_detail_renders_each_state_in_every_locale(self):
        from wam_regtest import bip39_locale
        from wam_regtest.fusion_pages import HistoryPage
        from wam_regtest.fusion_pages import rec1_status_line
        from wam_regtest.wallet_read import HistoryRow, WalletReadSnapshot
        snap = WalletReadSnapshot(
            'regtest', 4, '34' * 32, '', 1000, 1,
            (HistoryRow(TXID, 3, 2, 1000, 0),), '56' * 32)
        for language in SUPPORTED_LANGUAGES:
            for state in STATES:
                with self.subTest(language=language, state=state), patch.object(
                        bip39_locale, '_lang', return_value=language):
                    page = HistoryPage()
                    self.addCleanup(page.deleteLater)
                    page.render_snapshot(snap)
                    page.set_rec1_states({TXID: state})
                    page.table.selectRow(0)
                    page.show_details()
                    line = rec1_status_line(state, language)
                    self.assertIn(line, page.detail_values.text())
                    self.assertNotIn('rebroadcast available', page.detail_values.text().lower())
                    self.assertNotIn('eligible', page.detail_values.text().lower())
                    page.hide()
