"""D3-A durable commands: reuse TX-03's real WSP/native encrypted evidence fixture.

Only its existing synthetic RPC/vault/owner binding boundaries are reused.
These are disposable session tests, never genuine Core/frozen qualification.
"""
from unittest.mock import patch
import unittest

import test_tx03_signed_intent_recovery as tx03
from wam_regtest.wallet_session import WalletSessionError
from wam_sp.wallet import Wallet, Signer


class SessionEvidence(tx03.SignedIntentRecovery):
    def test_prepare_decline_releases_one_unsigned_draft_without_sign_or_send(self):
        self.vault = tx03._Vault(self.keys)
        session = self._session(self.scanner, self.vault)
        with patch.object(session, 'prepare', wraps=session.prepare) as prepare, \
                patch.object(Wallet, 'mark_signed', autospec=True,
                             side_effect=Wallet.mark_signed) as mark, \
                patch.object(Signer, 'sign', autospec=True,
                             side_effect=Signer.sign) as sign, \
                patch.object(Wallet, 'release_draft', autospec=True,
                             side_effect=Wallet.release_draft) as release:
            review = session.prepare(self.code, 50000, 1000)
            self.assertEqual(prepare.call_count, 1)
            self.assertEqual(tx03._states(self.scanner), {'draft'})
            self.assertEqual(self.vault.saved, [{'draft'}])
            self.assertEqual((mark.call_count, sign.call_count, release.call_count), (0, 0, 0))
            self.assertEqual(self.core.calls, [])
            session.cancel()
            self.assertEqual(release.call_count, 1)
            self.assertEqual((mark.call_count, sign.call_count), (0, 0))
            self.assertEqual(tx03._states(self.scanner), set())
            self.assertEqual(self.vault.saved[-1], set())
            self.assertEqual(self.core.calls, [])
            self.assertEqual(len(review.commitment), 64)

    def test_explicit_sign_marks_once_and_broadcast_decline_keeps_durable_signed(self):
        self.vault = tx03._Vault(self.keys)
        session = self._session(self.scanner, self.vault)
        review = session.prepare(self.code, 50000, 1000)
        with patch.object(Wallet, 'mark_signed', autospec=True,
                          side_effect=Wallet.mark_signed) as mark, \
                patch.object(Signer, 'sign', autospec=True,
                             side_effect=Signer.sign) as sign, \
                patch.object(Wallet, 'release_draft', autospec=True,
                             side_effect=Wallet.release_draft) as release:
            session.sign(review.commitment)
            self.assertEqual((mark.call_count, sign.call_count, release.call_count), (1, 1, 0))
            self.assertEqual(tx03._states(self.scanner), {'signed'})
            self.assertEqual(self.vault.saved, [{'draft'}, {'signed'}])
            token = session._prepared.proposal.token
            evidence = session._read_payment_evidence(token, 'signed')
            self.assertEqual(evidence['signed_psbt'], session._signed.hex())
            self.assertEqual(self.core.calls, [])
            # Declining Broadcast has no backend action. A forbidden unsigned
            # cancellation is independently refused by the actual session.
            with self.assertRaisesRegex(WalletSessionError, 'ONLY_UNSIGNED_DRAFT'):
                session.cancel()
            self.assertEqual(release.call_count, 0)
            self.assertEqual(tx03._states(self.scanner), {'signed'})
            self.assertEqual(self.core.calls, [])

    def test_stale_sign_and_broadcast_commitments_do_not_mark_sign_or_submit(self):
        self.vault = tx03._Vault(self.keys)
        session = self._session(self.scanner, self.vault)
        review = session.prepare(self.code, 50000, 1000)
        with patch.object(Wallet, 'mark_signed', autospec=True,
                          side_effect=Wallet.mark_signed) as mark, \
                patch.object(Signer, 'sign', autospec=True,
                             side_effect=Signer.sign) as sign:
            with self.assertRaisesRegex(WalletSessionError, 'EXACT_INTENT_APPROVAL'):
                session.sign('f' * 64)
            self.assertEqual((mark.call_count, sign.call_count), (0, 0))
            self.assertEqual(tx03._states(self.scanner), {'draft'})
            session.sign(review.commitment)
            before = list(self.vault.saved)
            with self.assertRaisesRegex(WalletSessionError, 'BROADCAST_APPROVAL'):
                session.broadcast('f' * 64)
            self.assertEqual(self.vault.saved, before)
            self.assertEqual((mark.call_count, sign.call_count), (1, 1))
            self.assertEqual(self.core.calls, [])

    def test_explicit_broadcast_once_has_write_ahead_evidence_and_no_second_submission(self):
        session, review = self._signed_session()
        observed = []
        original = self.core.call
        def rpc(method, params=None):
            if method == 'sendrawtransaction':
                observed.append((tx03._states(self.scanner),
                                 session._read_payment_evidence(self.token, 'uncertain')))
            return original(method, params)
        with patch.object(self.core, 'call', side_effect=rpc):
            self.assertEqual(session.broadcast(review.commitment), self.txid)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][0], {'uncertain'})
        self.assertEqual(observed[0][1]['signed_psbt'], self.signed.hex())
        self.assertEqual(self.vault.saved[-2:], [{'uncertain'}, {'broadcast'}])
        self.assertEqual(session._read_payment_evidence(self.token, 'broadcast')['txid'], self.txid)
        with self.assertRaisesRegex(WalletSessionError, 'BROADCAST_APPROVAL'):
            session.broadcast(review.commitment)
        self.assertEqual(self.core.calls.count('sendrawtransaction'), 1)

    def test_uncertain_and_reopen_read_only_never_resume_release_or_rebroadcast(self):
        session, review = self._signed_session()
        self.core.send = RuntimeError('D3A_PUBLIC_RESPONSE_LOST')
        with self.assertRaisesRegex(WalletSessionError, 'UNCERTAIN'):
            session.broadcast(review.commitment)
        self.assertEqual(tx03._states(self.scanner), {'uncertain'})
        before = list(self.vault.saved)
        with patch.object(type(session), 'resume_signed_intent', autospec=True,
                          side_effect=type(session).resume_signed_intent) as resume, \
                patch.object(Wallet, 'release_draft', autospec=True,
                             side_effect=Wallet.release_draft) as release, \
                patch.object(Signer, 'sign', autospec=True,
                             side_effect=Signer.sign) as sign:
            restarted = self._restart()
            for _ in range(2):
                [item] = self._item(restarted)
                self.assertEqual(item['state'], 'uncertain')
                self.assertEqual(item['txid'], self.txid)
            self.assertEqual((resume.call_count, release.call_count, sign.call_count), (0, 0, 0))
            self.assertEqual(self.vault.saved, before)
            self.assertEqual(tx03._states(restarted.scanner), {'uncertain'})
            self.assertEqual(self.core.calls.count('sendrawtransaction'), 1)

    def test_signed_reopen_read_only_preserves_bytes_and_reservations(self):
        session, review = self._signed_session()
        before = list(self.vault.saved)
        with patch.object(type(session), 'resume_signed_intent', autospec=True,
                          side_effect=type(session).resume_signed_intent) as resume, \
                patch.object(Wallet, 'release_draft', autospec=True,
                             side_effect=Wallet.release_draft) as release:
            restarted = self._restart()
            [item] = self._item(restarted)
            self.assertEqual(item['classification'], 'SIGNED_NOT_SUBMITTED_RESUMABLE')
            self.assertEqual(item['txid'], self.txid)
            self.assertEqual(tx03._states(restarted.scanner), {'signed'})
            self.assertEqual(self.vault.saved, before)
            self.assertEqual(self.core.calls, [])
            self.assertEqual((resume.call_count, release.call_count), (0, 0))


def load_tests(loader, tests, pattern):
    # Reuse setup/helpers without duplicating TX-03's inherited test inventory.
    return unittest.TestSuite(SessionEvidence(name) for name in sorted(
        name for name in SessionEvidence.__dict__ if name.startswith('test_')))
