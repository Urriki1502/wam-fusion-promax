"""PM-102 regression: real WSP scanner/crypto/checkpoint, synthetic Core/OS.

These are pure source contracts, not genuine Core/native/frozen acceptance.
"""
from hashlib import sha256
import importlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_q06_bip39_native_checkpoint as native
from test_q06_bip39_native_checkpoint import SOURCE, PASSWORD
from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend, Q06ReadOnlyError
from wam_regtest.bip39_spend_session import Q06OwnedSpendSession, _Q06NativeScannerVault
from wam_regtest.wallet_session import WalletSession
from wam_regtest.wsp_live import REGTEST_GENESIS
from wam_sp.core import Input, pub, send
from wam_sp.transaction import p2wpkh


class Chain:
    def __init__(self):
        self.blocks = [dict(height=0, hash=REGTEST_GENESIS, tx=[])]
        self.calls = []
        self._transport = None

    def attest(self):
        self.calls.append('attest')

    def call(self, method, args=None):
        self.calls.append(method)
        if method == 'getblockcount': return len(self.blocks) - 1
        if method == 'getbestblockhash': return self.blocks[-1]['hash']
        if method == 'getblockhash': return self.blocks[args[0]]['hash']
        if method == 'getblock':
            return next(b for b in self.blocks if b['hash'] == args[0])
        raise AssertionError(method)

    def fund(self, rpc, code, address, record):
        start = len(self.blocks) - 1
        txid = sha256(str(start).encode()).hexdigest()
        coin = Input('05' * 32, 0, p2wpkh(91),
                     witness=(bytes(72), pub(91)), secret=91)
        output = send([coin], [code])[0]
        tx = dict(txid=txid, vin=[dict(txid=coin.txid, vout=0,
            scriptSig={'hex': ''}, txinwitness=[v.hex() for v in coin.witness],
            prevout={'scriptPubKey': {'hex': coin.script.hex()}})],
            vout=[dict(n=0, value=0.001,
                       scriptPubKey={'hex': (b'\x51\x20' + output).hex()})])
        for height in range(start + 1, start + 103):
            self.blocks.append(dict(height=height,
                hash=sha256(str(height).encode()).hexdigest(),
                previousblockhash=self.blocks[-1]['hash'],
                tx=[tx] if height == start + 102 else []))
        return txid, 100_000, start + 102


class ActiveFundingContracts(unittest.TestCase):
    def setUp(self):
        # Publish a REAL encrypted generation 1, exactly the activated state
        # that the former unanchored success test failed to model.
        native.NativeCandidateContracts.setUp(self)
        self.chain = Chain()
        self.owner.core = self.parent
        self.owner.cli = self.parent / 'synthetic-cli'
        self.owner.receipt = {'wamd_sha256': '0' * 64}
        self.owner.read = self.chain
        self.guard = SimpleNamespace(check=lambda: None)
        for p in (
            patch('wam_regtest.bip39_native_checkpoint._owned_tip',
                  side_effect=lambda _: (len(self.chain.blocks)-1, self.chain.blocks[-1]['hash'])),
            patch('wam_regtest.bip39_spend_session._owned'),
            patch('wam_regtest.bip39_spend_session._native', return_value=(self.storage, self.anchor)),
            patch('wam_regtest.managed_wallet_checkpoint._owned'),
            patch('wam_regtest.managed_wallet_session.RuntimeGuard',
                  side_effect=self._scratch_guard),
            patch.object(WalletSession, '_rpc', lambda _: self.chain),
            patch('wam_regtest.wallet_session.WalletCoreCli', return_value=self.chain),
            patch('wam_regtest.wsp_live.public_regtest_mining_address', return_value='public-fixture'),
            patch('wam_regtest.regtest_funding.fund_checkpoint_fixture', side_effect=self.chain.fund),
        ):
            p.start(); self.addCleanup(p.stop)
        native.NativeCandidateContracts.publish(self)
        self.first_cipher = (self.snapshot_folder / 'snapshot-000000001.enc').read_bytes()
        self.vault = _Q06NativeScannerVault(self.owner, self.seed_folder, SOURCE, PASSWORD.encode(), None)
        self.session = Q06OwnedSpendSession(self.owner, SOURCE, self.crypto_keys,
            self.scan, self.guard, self.vault, PASSWORD.encode())
        self.session._ensure_core_identity = lambda: (self.owner.cli, self.owner.receipt)
        self.backend = Bip39ReadOnlyBackend(self.parent, self.parent, SOURCE)
        self.backend._core = lambda: self.owner
        self.backend._secret = bytearray(PASSWORD.encode())
        self.backend._public = self.crypto_keys.public_metadata()
        self.backend._seed_folder = self.seed_folder
        self.backend._spend_session = self.session

    @staticmethod
    def _scratch_guard(path):
        def remove():
            for suffix in ('', '-journal', '-wal', '-shm'):
                path.with_name(path.name + suffix).unlink(missing_ok=True)
        return SimpleNamespace(check=lambda: None, close=lambda: None, remove_owned=remove)

    def test_activated_idle_profile_funds_twice_and_advances_authenticated_checkpoint(self):
        for generation in (2, 3):
            receipt = self.backend.execute('mine', (), {})
            self.assertEqual(self.anchor.read()[0], generation)
            self.assertEqual(self.vault._expected, self.anchor.read())
            snapshot = self.session.snapshot()
            self.assertEqual(snapshot.confirmed_atoms, (generation-1)*100_000)
            self.assertTrue(any(r.txid == receipt['txid'] and r.credit_atoms == receipt['atoms']
                                and r.confirmations > 0 for r in snapshot.history))
            self.assertEqual(native.NativeCandidateContracts.read(self)[1]['generation'], generation)
            self.assertEqual((self.snapshot_folder / 'snapshot-000000001.enc').read_bytes(), self.first_cipher)

    def test_allow_requires_readable_empty_owned_mempool_spend_evidence(self):
        queries = []
        self.scan.store.db.set_trace_callback(queries.append)
        try:
            self.assertFalse(self.backend._fund_in_flight())
        finally:
            self.scan.store.db.set_trace_callback(None)
        self.assertTrue(any('mempool_spends' in q and 'coins' in q for q in queries))
        # An unrelated Core mempool input is not this wallet's payment.
        self.scan.store.db.execute('INSERT INTO mempool_spends VALUES(?,?,?)',
                                   ('f' * 64, 0, 'e' * 64))
        self.assertFalse(self.backend._fund_in_flight())
        self.scan.store.db.execute('DROP TABLE mempool_spends')
        self.assertTrue(self.backend._fund_in_flight())

    def test_owned_mempool_payment_refuses_even_without_a_reservation(self):
        self.chain.fund(None, self.backend._public['receive_code'], None, {})
        self.scan.sync(self.chain)
        txid, vout = self.scan.store.db.execute('SELECT txid,vout FROM coins').fetchone()
        self.scan.store.db.execute('INSERT INTO mempool_spends VALUES(?,?,?)',
                                   (txid, vout, 'e' * 64))
        self.assertEqual(self.scan.store.db.execute('SELECT count(*) FROM reservations').fetchone()[0], 0)
        self._assert_no_rpc()

    def test_confirmed_input_with_stale_mempool_row_allows_funding_but_rollback_refuses(self):
        self.chain.fund(None, self.backend._public['receive_code'], None, {})
        self.scan.sync(self.chain)
        txid, vout = self.scan.store.db.execute('SELECT txid,vout FROM coins').fetchone()
        self.scan.store.db.execute('INSERT INTO mempool_spends VALUES(?,?,?)',
                                   (txid, vout, 'e' * 64))
        self.assertTrue(self.backend._fund_in_flight())
        # WSP _block marks the owned input spent; sync does not clear mempool rows.
        self.scan.store.db.execute('UPDATE coins SET spent=102 WHERE txid=? AND vout=?',
                                   (txid, vout))
        self.assertFalse(self.backend._fund_in_flight())
        self.assertEqual(self.scan.store.db.execute('SELECT count(*) FROM mempool_spends').fetchone()[0], 1)
        self.scan.store.db.execute('UPDATE coins SET spent=NULL WHERE txid=? AND vout=?',
                                   (txid, vout))
        self._assert_no_rpc()

    def test_anchored_non_session_funding_still_requires_reconciliation(self):
        self.backend._spend_session = None
        with self.assertRaisesRegex(Q06ReadOnlyError, 'ANCHORED_SCANNER_REQUIRES_RECONCILIATION'):
            self.backend.execute('mine', (), {})
        self.assertEqual(self.chain.calls, [])
        self.assertEqual(self.anchor.read()[0], 1)

    def test_postcheck_rejects_missing_wrong_atoms_or_unconfirmed_receive(self):
        for fault in ('missing', 'atoms', 'unconfirmed'):
            with self.subTest(fault=fault):
                def wrong_receive(rpc, code, address, record):
                    txid, atoms, height = self.chain.fund(rpc, code, address, record)
                    if fault == 'missing': self.chain.blocks[-1]['tx'] = []
                    if fault == 'atoms': atoms += 1
                    return txid, atoms, height
                self.session.faulted = self.session._q06_uncertain = False
                real_snapshot = self.session.snapshot
                def snapshot():
                    result = real_snapshot()
                    if fault == 'unconfirmed':
                        from dataclasses import replace
                        result = replace(result, history=tuple(
                            replace(row, confirmations=0) for row in result.history))
                    return result
                with (patch('wam_regtest.regtest_funding.fund_checkpoint_fixture', side_effect=wrong_receive),
                      patch.object(self.session, 'snapshot', side_effect=snapshot)):
                    with self.assertRaisesRegex(Q06ReadOnlyError, 'TEST_FUNDING_UNVERIFIED'):
                        self.backend.execute('mine', (), {})
                self.assertTrue(self.session.faulted)
                self.assertTrue(self.session._q06_uncertain)

    def _reservation(self, state, token='a'*32, txid='b'*64):
        with self.scan.store.transaction():
            self.scan.store.db.execute('INSERT INTO reservations VALUES(?,?,?,?,?)',
                                      (txid, 0, token, state, 1))

    def _assert_no_rpc(self):
        self.chain.calls.clear()
        with patch('wam_regtest.shared_regtest.peer_status') as peers:
            with self.assertRaisesRegex(Q06ReadOnlyError, 'TEST_FUNDING_IN_FLIGHT'):
                self.backend.execute('mine', (), {})
            peers.assert_not_called()
        self.assertEqual(self.chain.calls, [])

    def test_all_unresolved_reservations_refuse_before_rpc(self):
        for state in ('draft', 'signed', 'uncertain', 'broadcast'):
            with self.subTest(state=state):
                self.scan.store.db.execute('DELETE FROM reservations')
                self._reservation(state)
                self._assert_no_rpc()

    def _signed_broadcast(self):
        from wam_sp.wallet import Wallet, Signer, Intent
        from wam_sp.psbt import PSBT
        self.chain.fund(None, self.backend._public['receive_code'], None, {})
        self.scan.sync(self.chain)
        wallet = Wallet(self.scan)
        intent = Intent(self.backend._public['receive_code'], 50_000)
        proposal = wallet.propose((intent,), 1_000)
        signer = Signer(self.crypto_keys)
        signed = signer.sign(signer.prepare(proposal), (intent,), 1_000)
        with self.scan.store.transaction():
            self.scan.store.db.execute("UPDATE reservations SET state='broadcast' WHERE token=?",
                                       (proposal.token,))
        return proposal.token, {'txid': PSBT.decode(signed).txid(), 'signed_psbt': signed.hex()}

    def test_broadcast_rec_quarantine_multiple_candidates_and_not_observed_refuse(self):
        token, body = self._signed_broadcast()
        evidence = {token: body}
        # Authentic signed broadcast, absent from verified confirmed history:
        # NOT_OBSERVED must refuse without attempting RPC observation/mining.
        with patch.object(self.session, '_read_payment_evidence',
                          side_effect=lambda token, stage: evidence.get(token)):
            self._assert_no_rpc()
            other, other_body = self._signed_broadcast()
            evidence[other] = other_body
            self.session._q06_pending_confirm = None  # multiple healthy REC candidates
            self._assert_no_rpc()
            self.session._q06_rec1_quarantine = {token: 'EVIDENCE_MISSING'}
            self._assert_no_rpc()

    def test_each_in_memory_payment_or_recovery_flag_refuses_before_rpc(self):
        for attr in ('_review', '_prepared', '_signed', '_q06_pending_confirm',
                     '_q06_uncertain', 'faulted', '_core_reauthentication_required'):
            original = getattr(self.session, attr, None)
            with self.subTest(flag=attr):
                setattr(self.session, attr, True)
                self._assert_no_rpc()
                setattr(self.session, attr, original)

    def test_shared_coordinator_approved_payment_refuses_before_peer_status(self):
        self.backend.shared_profile = SimpleNamespace(coordinator=True)
        self.session._review = object()
        self._assert_no_rpc()

    def test_confirmed_broadcast_needs_authentic_exact_input_evidence(self):
        token, body = self._signed_broadcast()
        with self.scan.store.transaction():
            self.scan.store.db.execute('INSERT INTO history VALUES(?,?,?,?)',
                                      (body['txid'], 102, 49_000, 100_000))
        with patch.object(self.session, '_read_payment_evidence', return_value=body):
            self.assertFalse(self.backend._fund_in_flight())
        for invalid in (None, dict(body, txid='f'*64), dict(body, signed_psbt='00')):
            with patch.object(self.session, '_read_payment_evidence', return_value=invalid):
                self.assertTrue(self.backend._fund_in_flight())


class FundingConsentContracts(unittest.TestCase):
    def test_six_locales_describe_disposable_chain_fixture_mining_then_wallet_payment(self):
        terms = {
            'en': ('disposable REGTEST chain', 'public fixture', 'then pays'),
            'vi': ('chuỗi REGTEST dùng một lần', 'công khai', 'sau đó'),
            'id': ('rantai REGTEST sekali pakai', 'publik', 'lalu'),
            'ja': ('使い捨て REGTEST チェーン', '公開', 'その後'),
            'ko': ('일회용 REGTEST 체인', '공개', '그런 다음'),
            'zh_hans': ('一次性 REGTEST 链', '公开', '然后'),
        }
        for locale, required in terms.items():
            values = getattr(importlib.import_module('wam_regtest.presentation.locales.' + locale), locale.upper())
            for key in ('owner.fund_consent', 'wallet.fund_consent'):
                with self.subTest(locale=locale, key=key):
                    for term in required: self.assertIn(term, values[key])
        en = importlib.import_module('wam_regtest.presentation.locales.en').EN
        self.assertEqual(en['owner.fund_receive'], 'Add test funds')
        self.assertEqual(en['wallet.fund_title'], 'Add test funds')
