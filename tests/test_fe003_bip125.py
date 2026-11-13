"""FE-003 signalling contract; real pinned WSP, synthetic disposable chain."""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from test_fee_integration import FOREIGN, _rows
import test_fee_integration as fixtures
from wam_sp.psbt import PSBT
from wam_sp.wallet import Signer, Wallet
from wam_regtest.wallet_session import WalletSessionError


def doctored(prepared, sequences):
    psbt = PSBT.decode(prepared.psbt)
    tx = replace(psbt.tx, sequence=sequences[0], sequences=tuple(sequences))
    return replace(prepared, psbt=replace(psbt, tx=tx).encode())


class Signalling(unittest.TestCase):
    setUp = fixtures.AutomaticFee.setUp
    _fund = fixtures.AutomaticFee._fund

    def test_each_prepared_input_signals_for_both_prepare_paths(self):
        self._fund((30_000, 30_000))
        for auto in (False, True):
            review = (self.session.prepare_auto(self.code, 50_000) if auto else
                      self.session.prepare(self.code, 50_000, 500))
            self.assertIs(review.replaceable, True)
            sequences = PSBT.decode(self.session._prepared.psbt).tx.sequence_values()
            self.assertEqual(len(sequences), 2)
            self.assertTrue(all(s <= 0xFFFFFFFD for s in sequences))
            self.session.cancel()

    def test_prepare_refuses_any_non_signalling_input_before_save(self):
        self._fund((30_000, 30_000))
        real = Signer.prepare
        for auto in (False, True):
            for bad in (0xFFFFFFFE, 0xFFFFFFFF):
                with self.subTest(auto=auto, sequence=bad):
                    with patch.object(Signer, 'prepare', lambda signer, proposal:
                                      doctored(real(signer, proposal), (0xFFFFFFFD, bad))):
                        with self.assertRaisesRegex(WalletSessionError, '^RBF_SIGNALLING_MISSING$'):
                            if auto:
                                self.session.prepare_auto(self.code, 50_000)
                            else:
                                self.session.prepare(self.code, 50_000, 500)
                    self.assertEqual(_rows(self.scanner), [FOREIGN])
                    self.assertEqual(self.vault.saved, [])
                    self.assertIsNone(self.session._prepared)
                    self.assertIsNone(self.session._signed)

    def test_prepare_accepts_signalling_sequence_boundary_and_lower_values(self):
        self._fund((100_000,))
        real = Signer.prepare
        for sequence in (0, 0xFFFFFFFC, 0xFFFFFFFD):
            with patch.object(Signer, 'prepare', lambda signer, proposal:
                              doctored(real(signer, proposal), (sequence,))):
                review = self.session.prepare_auto(self.code, 50_000)
            self.assertIs(review.replaceable, True)
            self.session.cancel()

    def test_refusal_release_failure_faults_and_preserves_foreign_reservation(self):
        self._fund((100_000,))
        real = Signer.prepare
        with patch.object(Signer, 'prepare', lambda signer, proposal:
                          doctored(real(signer, proposal), (0xFFFFFFFF,))), \
                patch.object(Wallet, 'release_draft', side_effect=ValueError('RELEASE_DENIED')):
            with self.assertRaises(WalletSessionError):
                self.session.prepare_auto(self.code, 50_000)
        self.assertTrue(self.session.faulted)
        self.assertIn(FOREIGN, _rows(self.scanner))
        self.assertTrue(any(row[3] == 'draft' for row in _rows(self.scanner)))
        self.assertEqual(self.vault.saved, [])
        self.assertIsNone(self.session._signed)

    def test_sign_refuses_approved_non_signalling_psbt_and_releases_draft(self):
        self._fund((30_000, 30_000))
        for bad in (0xFFFFFFFE, 0xFFFFFFFF):
            self.session.prepare_auto(self.code, 50_000)
            self.session._prepared = doctored(self.session._prepared, (0xFFFFFFFD, bad))
            # Model a legacy approved draft, with commitment binding these exact bytes.
            commitment = sha256(self.session._prepared.psbt).hexdigest()
            self.session._review = replace(self.session._review, commitment=commitment)
            with patch.object(Wallet, 'mark_signed') as mark, patch.object(Signer, 'sign') as sign:
                with self.assertRaisesRegex(WalletSessionError, '^RBF_SIGNALLING_MISSING$'):
                    self.session.sign(commitment)
            mark.assert_not_called()
            sign.assert_not_called()
            self.assertIsNone(self.session._signed)
            self.assertIsNone(self.session._prepared)
            self.assertEqual(_rows(self.scanner), [FOREIGN])
            self.assertEqual(self.vault.saved[-1], [FOREIGN])


class Presentation(unittest.TestCase):
    def test_six_locale_review_dialog_and_public_error(self):
        from PySide6.QtWidgets import QApplication, QLabel
        from wam_regtest.fusion_pages import (PaymentApproval, fusion_review_text,
                                             owner_approval_text, operational_review_text)
        from wam_regtest.wallet_session import PaymentReview
        from wam_regtest.presentation.strings import CATALOG
        from wam_regtest.gui_errors import operation_error, error_text
        app = QApplication.instance() or QApplication([])
        review = PaymentReview('public test recipient', 50_000, 310, 49_690, 1, 'a' * 64,
                               replaceable=True)
        auto = replace(review, rate_atoms_per_kvb=2000, rate_source='NETWORK_FLOOR_2X',
                       rate_classification='UNAVAILABLE', total_debit=50_310,
                       available_before=100_000, available_after=0)
        for lang, catalog in CATALOG.items():
            with self.subTest(lang=lang), patch('wam_regtest.bip39_locale._lang', return_value=lang):
                line = catalog['payment.replaceable_yes']
                for candidate in (review, auto):
                    self.assertIn(line, fusion_review_text(candidate))
                    self.assertIn(line, owner_approval_text(candidate))
                    self.assertIn(line, operational_review_text(candidate))
                    dialog = PaymentApproval(candidate, 'sign', None)
                    self.assertTrue(any(line in label.text() for label in dialog.findChildren(QLabel)))
                    dialog.close()
                self.assertNotIn(line, fusion_review_text(replace(review, replaceable=False)))
                for action in ('prepare', 'prepare_auto', 'sign'):
                    self.assertEqual(operation_error(action, WalletSessionError('RBF_SIGNALLING_MISSING')),
                                     'RBF_SIGNALLING_MISSING')
                self.assertEqual(error_text('RBF_SIGNALLING_MISSING'),
                                 catalog['errors.RBF_SIGNALLING_MISSING'])
        self.assertEqual(CATALOG['en']['payment.replaceable_yes'],
                         'Replaceable: yes (fee can be increased later)')
        manifest = json.loads((Path(__file__).parent / 'l10n_security_review_keys.json').read_text())
        keys = {item['key'] for item in manifest['keys']}
        self.assertTrue({'payment.replaceable_yes', 'errors.RBF_SIGNALLING_MISSING'} <= keys)
