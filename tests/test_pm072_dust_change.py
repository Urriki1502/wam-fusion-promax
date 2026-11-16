"""PM-072: real pinned selector refuses dust without reserving or saving."""
import re
import unittest
from unittest.mock import patch
import test_fee_integration as fee_test
from test_fee_integration import FOREIGN, _rows
from wam_regtest.gui_errors import operation_error
from wam_regtest.presentation.strings import CATALOG


class DustChange(unittest.TestCase):
    setUp = fee_test.AutomaticFee.setUp
    _fund = fee_test.AutomaticFee._fund

    def test_dust_boundaries_are_dedicated_and_leave_no_side_effects(self):
        for change in (1, 90, 329):
            with self.subTest(change=change):
                fixture = type(self)()
                fixture.setUp()
                self.addCleanup(fixture.doCleanups)
                fixture._fund((100_310 + change,))
                before = _rows(fixture.scanner)
                with self.assertRaises(ValueError) as caught:
                    fixture.session.prepare_auto(fixture.code, 100_000)
                self.assertEqual(operation_error('prepare_auto', caught.exception),
                                 'WALLET_CHANGE_BELOW_DUST')
                self.assertEqual(_rows(fixture.scanner), before)
                self.assertEqual(fixture.vault.saved, [])
                self.assertIsNone(fixture.session._prepared)
                self.assertIsNone(fixture.session._signed)

    def test_exact_and_minimum_change_succeed(self):
        for change in (0, 330):
            with self.subTest(change=change):
                fixture = type(self)()
                fixture.setUp()
                self.addCleanup(fixture.doCleanups)
                fixture._fund((100_310 + change,))
                review = fixture.session.prepare_auto(fixture.code, 100_000)
                self.assertEqual(review.change_atoms, change)
                fixture.session.cancel()

    def test_real_insufficiency_keeps_existing_code(self):
        self._fund((100_000,))
        with self.assertRaises(ValueError) as caught:
            self.session.prepare_auto(self.code, 100_000)
        self.assertEqual(operation_error('prepare_auto', caught.exception),
                         'WALLET_INPUT_FUNDS_UNAVAILABLE')
        self.assertEqual(_rows(self.scanner), [FOREIGN])

    def test_unexplained_selector_refusal_falls_back(self):
        self._fund((1_000_000,))
        from wam_sp.wallet import Wallet
        with patch.object(Wallet, 'propose', side_effect=ValueError('INSUFFICIENT_SINGLE_CLUSTER_FUNDS')):
            with self.assertRaises(ValueError) as caught:
                self.session.prepare_auto(self.code, 100_000)
        self.assertEqual(operation_error('prepare_auto', caught.exception),
                         'WALLET_INPUT_FUNDS_UNAVAILABLE')
        self.assertEqual(_rows(self.scanner), [FOREIGN])

    def test_input_count_fee_prevents_false_dust_diagnosis(self):
        # Initial 310 leaves 90; two-input fee is 424, so funds are insufficient.
        self._fund((60_000, 40_400))
        with self.assertRaises(ValueError) as caught:
            self.session.prepare_auto(self.code, 100_000)
        self.assertEqual(operation_error('prepare_auto', caught.exception),
                         'WALLET_INPUT_FUNDS_UNAVAILABLE')
        self.assertEqual(_rows(self.scanner), [FOREIGN])

    def test_separate_clusters_are_not_combined_for_diagnosis(self):
        self._fund((60_000, 40_400))
        self.scanner.store.db.execute(
            "UPDATE coins SET label=1 WHERE atoms=40400")
        with self.assertRaises(ValueError) as caught:
            self.session.prepare_auto(self.code, 100_000)
        self.assertEqual(operation_error('prepare_auto', caught.exception),
                         'WALLET_INPUT_FUNDS_UNAVAILABLE')

    def test_reserved_coin_does_not_prove_dust(self):
        self._fund((100_400,))
        from wam_sp.wallet import Wallet
        coin, = self.scanner.coins()
        Wallet(self.scanner).lock([(coin['txid'], coin['vout'])])
        before = _rows(self.scanner)
        with self.assertRaises(ValueError) as caught:
            self.session.prepare_auto(self.code, 100_000)
        self.assertEqual(operation_error('prepare_auto', caught.exception),
                         'WALLET_INPUT_FUNDS_UNAVAILABLE')
        self.assertEqual(_rows(self.scanner), before)

    def test_changed_facts_fall_back(self):
        self._fund((100_400,))
        from wam_regtest import wallet_session
        real = wallet_session._selection_facts
        before = real(__import__('wam_sp.wallet', fromlist=['Wallet']).Wallet(self.scanner))
        with patch.object(wallet_session, '_selection_facts', side_effect=[before, None]):
            with self.assertRaises(ValueError) as caught:
                self.session.prepare_auto(self.code, 100_000)
        self.assertEqual(operation_error('prepare_auto', caught.exception),
                         'WALLET_INPUT_FUNDS_UNAVAILABLE')

    def test_lower_input_count_rate_alternative_makes_dust_ambiguous(self):
        # At the attempted 1004 fee the seven-coin prefix leaves 90. A
        # separate single coin cannot fund 1004, but at its quoted 310 fee
        # would leave 390, so the explanation must remain inconclusive.
        self._fund((100_700,) + (14_442,) * 7)
        self.scanner.store.db.execute(
            "UPDATE coins SET label=1 WHERE atoms=100700")
        from wam_sp.wallet import Wallet, Intent
        from wam_regtest.wallet_session import _propose_with_change_reason
        with self.assertRaises(ValueError) as caught:
            _propose_with_change_reason(Wallet(self.scanner),
                                       Intent(self.code, 100_000), 1004, 2000)
        self.assertEqual(operation_error('prepare_auto', caught.exception),
                         'WALLET_INPUT_FUNDS_UNAVAILABLE')
        self.assertEqual(_rows(self.scanner), [FOREIGN])

    def test_all_six_locales_have_placeholder_parity(self):
        key = 'errors.WALLET_CHANGE_BELOW_DUST'
        self.assertEqual(len(CATALOG), 6)
        for locale, catalog in CATALOG.items():
            self.assertIn(key, catalog, locale)
            self.assertEqual(re.findall(r'\{[^}]*\}', catalog[key]), [])
            self.assertIn('330', catalog[key])
