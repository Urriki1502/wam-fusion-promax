"""PM-100: regression test for FC-27 F3-11/signed-recovery owner GUI offer.

WalletExecutor._run wraps every backend result in immutable() (FrozenDict +
tuple). The owner GUI intent_status handler and fusion_pages helpers must
accept both raw (dict/list) and immutable (FrozenDict/tuple) shapes, returning
the window to idle with _resumable_intent set and resume enabled for a single
signed never-submitted intent, while still refusing uncertain/mixed/unknown
and multi-intent offers.
"""
import os
import unittest
from types import SimpleNamespace

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from wam_regtest.bip39_locale import t
from wam_regtest.desktop import qt_application
from wam_regtest.wallet_executor import ExecutorState, WalletExecutor, immutable

TXID = 'ab' * 32
TOKEN = 'cd' * 16


def _backend_intent_status(intents):
    """Exact dict shape returned by bip39_spend_session._intent_status_unlocked."""
    return {
        'status': 'Q06_SIGNED_INTENT_STATUS',
        'height': 102,
        'tip': '6a' * 32,
        'intents': intents,
        'write_attempted': False,
        'automatic_resume': False,
        'abandon_available': False,
        'mainnet_allowed': False,
        'rec1_quarantined_tokens': [],
        'rec1_quarantine': {},
    }


def _signed_never_submitted_item(**extra):
    item = {
        'token': TOKEN,
        'state': 'signed',
        'input_count': 1,
        'txid': TXID,
        'evidence': 'verified',
        'observation': {
            'state': 'NOT_SEEN_LOCALLY',
            'h': None,
            'height': None,
            'block_hash': None,
            'conflict_heights': [],
            'depth': None,
            'core_ibd': False,
        },
        'recipient': 'wamrtsp1example',
        'atoms': 100_000,
        'fee': 310,
        'classification': 'SIGNED_NOT_SUBMITTED_RESUMABLE',
        'rec1_state': 'NOT_OBSERVED_LOCALLY',
        'rec1_reason': 'REBROADCAST_DEFERRED',
        'quarantined': False,
    }
    item.update(extra)
    return item


class _FakeIntentBackend:
    def __init__(self, status_payload):
        self._payload = status_payload
        self._core_alive = True

    def public_state(self):
        return {
            'locked': False,
            'faulted': False,
            'reauthentication_required': False,
            'core_alive': self._core_alive,
            'runtime_preserved': False,
        }

    def execute(self, action, args, kwargs):
        if action == 'intent_status':
            return self._payload
        if action == 'quit':
            self._core_alive = False
            return {'runtime_preserved': False, 'codes': ()}
        raise AssertionError('unexpected action: ' + action)


class ImmutableIntentStatusRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = qt_application()

    def _make_window(self, cls):
        owner = SimpleNamespace(
            state=ExecutorState(locked=False, faulted=False, core_alive=True),
            busy=False,
            closed=False,
        )
        window = cls(owner)
        window._poll.stop()
        window._ready = True
        window._spend_enabled = True
        window._set_actions()
        self.addCleanup(self._cleanup_window, window)
        return window

    def _cleanup_window(self, window):
        window._poll.stop()
        window.deleteLater()
        self.app.processEvents()

    def test_on_ready_immutable_signed_never_submitted_offers_submit(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.bip39_owner_gui import Bip39TrialWindow

        payload = immutable(_backend_intent_status([_signed_never_submitted_item()]))
        for window_cls in (Bip39TrialWindow, Bip39FusionWindow):
            with self.subTest(window_cls=window_cls.__name__):
                window = self._make_window(window_cls)
                window._on_ready('intent_status', payload)
                self.assertIsNotNone(window._resumable_intent)
                self.assertEqual(
                    window._resumable_intent['classification'],
                    'SIGNED_NOT_SUBMITTED_RESUMABLE',
                )
                self.assertEqual(window._resumable_intent['state'], 'signed')
                self.assertIsNone(window._worker)
                self.assertFalse(window._delivering_result)
                self.assertTrue(window.resume.isEnabled())
                self.assertIn(t('owner.intent_resumable'), window.status.text())
                self.assertIn(t('rec1.NOT_OBSERVED_LOCALLY'), window.status.text())
                if hasattr(window, 'history_page'):
                    self.assertEqual(
                        window.history_page._rec1_by_txid,
                        {TXID: 'NOT_OBSERVED_LOCALLY'},
                    )

    def test_intents_click_via_executor_returns_idle_with_submit_enabled(self):
        from PySide6.QtCore import QTimer
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow

        executor = WalletExecutor(
            lambda: _FakeIntentBackend(_backend_intent_status([_signed_never_submitted_item()]))
        )
        executor.request('intent_status')  # Ensure state reflects unlocked live core.
        window = Bip39FusionWindow(executor)
        window._poll.stop()
        window._ready = True
        window._spend_enabled = True
        window._set_actions()
        try:
            self.assertTrue(window.intents.isEnabled())
            window.intents.click()
            # Drain Qt events until the worker finishes and _on_ready runs.
            for _ in range(200):
                self.app.processEvents()
                if (window._worker is None and not window._delivering_result
                        and not executor.busy and window._resumable_intent is not None):
                    break
                QTimer.singleShot(10, self.app.quit)
                self.app.exec()
            self.assertIsNone(window._worker)
            self.assertFalse(window._delivering_result)
            self.assertFalse(executor.busy)
            self.assertIsNotNone(window._resumable_intent)
            self.assertEqual(window._resumable_intent['txid'], TXID)
            self.assertTrue(window.resume.isEnabled())
            self.assertIn(t('owner.intent_resumable'), window.status.text())
            self.assertEqual(
                window.history_page._rec1_by_txid,
                {TXID: 'NOT_OBSERVED_LOCALLY'},
            )
        finally:
            window._poll.stop()
            window.deleteLater()
            self.app.processEvents()
            executor.request('quit')
            executor.join(5)

    def test_immutable_uncertain_mixed_unknown_and_multi_still_not_offered(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow

        cases = (
            [
                _signed_never_submitted_item(
                    classification='UNCERTAIN_NOT_OBSERVED_RESUMABLE',
                    state='uncertain',
                    rec1_state='NOT_OBSERVED_LOCALLY',
                )
            ],
            [
                _signed_never_submitted_item(
                    classification='OPERATOR_REVIEW_MIXED_STATE',
                    state='mixed',
                    rec1_state='CORRUPTED_EVIDENCE',
                )
            ],
            [
                _signed_never_submitted_item(
                    classification='OPERATOR_REVIEW_OBSERVATION_CONTRADICTION',
                    state='unknown',
                    rec1_state='BROADCAST_OUTCOME_UNCERTAIN',
                )
            ],
            [
                _signed_never_submitted_item(
                    state='broadcast',
                    rec1_state='IN_LOCAL_MEMPOOL',
                )
            ],
            [
                _signed_never_submitted_item(),
                _signed_never_submitted_item(token='ef' * 16, txid='12' * 32),
            ],
        )
        window = self._make_window(Bip39FusionWindow)
        for intents in cases:
            with self.subTest(intents=intents):
                window._resumable_intent = _signed_never_submitted_item()
                window._on_ready('intent_status', immutable(_backend_intent_status(intents)))
                self.assertIsNone(window._resumable_intent)
                self.assertFalse(window.resume.isEnabled())
                self.assertIn(t('owner.intent_protected'), window.status.text())
                self.assertNotIn(t('owner.intent_resumable'), window.status.text())
                self.assertNotIn(t('owner.no_intents'), window.status.text())


if __name__ == '__main__':
    unittest.main()
