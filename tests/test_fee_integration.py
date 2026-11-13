"""FEE-2: automatic fee on the payment session. Synthetic chain and RPC.

Real pinned WSP selects coins, builds the PSBT and signs. The fee quote uses
the captured empty-REGTEST policy fixture, not a live node. Real-Core
qualification is FEE-3. Explicit prepare(code, atoms, fee) stays available
for the historical tests; these cases drive prepare_auto.
"""
from contextlib import nullcontext
from hashlib import sha256
import importlib.util
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mnemonic import Mnemonic
from wam_regtest.bip39_12 import Bip39Regtest12Keys
from wam_regtest.domain.fee_policy import (
    FeePolicyError, check_fee_limits, fee_for_vsize)
from wam_regtest.infrastructure.tx_size import (
    estimated_one_input_vsize, psbt_vsize, serialized_vsize)
from wam_sp.core import Input, pub, send
from wam_sp.psbt import PSBT
from wam_sp.scanner import Scanner
from wam_sp.transaction import p2wpkh
from wam_sp.wallet import Signer, Wallet
from wam_sp.watcher import GENESIS

SOURCE = Path(importlib.util.find_spec("wam_sp").origin).resolve().parents[2]
PASSWORD = b"fee-2 disposable public test password"
FOREIGN = ("ee" * 32, 7, "f" * 32, "signed", 1)
ROOT = Path(__file__).resolve().parents[1]


def _rows(scanner):
    return sorted(tuple(row) for row in scanner.store.db.execute(
        "SELECT txid,vout,token,state,created FROM reservations"))


def _policy():
    import copy
    import json
    from decimal import Decimal
    import re
    number = re.compile(r'-?\d+(\.\d+)?(E[+-]?\d+)?\Z', re.I)

    def decimalize(value, key=None):
        if isinstance(value, dict):
            return {name: decimalize(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [decimalize(item) for item in value]
        if isinstance(value, str) and key != 'subversion' and number.match(value):
            return Decimal(value)
        return value

    return decimalize(json.loads(
        (ROOT / 'tests/fixtures/fee_rpc_regtest_v013_empty.json').read_text()))


POLICY = _policy()


class _Chain:
    def __init__(self, block):
        self.block = block

    def attest(self):
        return None

    def call(self, method, params=None):
        if method == "getbestblockhash":
            return self.block["hash"]
        if method == "getblockcount":
            return 1
        if method == "getblockhash":
            return GENESIS if params[0] == 0 else self.block["hash"]
        if method == "getblock":
            return self.block
        raise ValueError("FEE2_SYNTHETIC_RPC_METHOD_DENIED")


class _Vault:
    def __init__(self, keys, fail=False):
        self.keys, self.fail, self.saved = keys, fail, []
        self.anchor = SimpleNamespace(wallet_id="d" * 32, value=(1, "a" * 64),
                                      lease=lambda: nullcontext())
        self.anchor.read = lambda: self.anchor.value
        self._expected = self.anchor.value

    def save(self, keys, scanner, password):
        if self.fail:
            raise OSError("FEE2_PUBLIC_SAVE_FAULT")
        self.saved.append(_rows(scanner))
        self.anchor.value = (self.anchor.value[0] + 1,
                             sha256(scanner.checkpoint(password)).hexdigest())
        self._expected = self.anchor.value


class _FeeRpc:
    """Empty-REGTEST fee policy plus the chain reads Sign already performs."""

    def __init__(self, outputs, tip_hash):
        self.outputs, self.tip_hash = outputs, tip_hash
        self.mempoolminfee = POLICY["getmempoolinfo"]["mempoolminfee"]
        self.calls = []

    @property
    def verified_network(self):
        return "regtest"

    def attest(self):
        return None

    def call(self, method, params=None):
        self.calls.append(method)
        if method == "getnetworkinfo":
            return dict(POLICY["getnetworkinfo"])
        if method == "getmempoolinfo":
            info = dict(POLICY["getmempoolinfo"])
            info["mempoolminfee"] = self.mempoolminfee
            return info
        if method == "estimatesmartfee":
            return dict(POLICY["estimatesmartfee_%d_conservative" % params[0]])
        if method == "estimaterawfee":
            return POLICY["estimaterawfee_%d" % params[0]]
        if method == "getbestblockhash":
            return self.tip_hash
        if method == "gettxout":
            coin = self.outputs[(params[0], params[1])]
            atoms = coin["atoms"]
            value = "%d.%08d" % divmod(atoms, 100_000_000)
            return {"value": value,
                    "scriptPubKey": {"hex": "5120" + coin["public_key"]}}
        raise ValueError("FEE2_RPC_METHOD_DENIED")


class Estimate(unittest.TestCase):
    def test_first_guess_is_one_input_and_two_outputs(self):
        self.assertEqual(estimated_one_input_vsize(), 155)


class AutomaticFee(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="fee2-")
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        self.keys = Bip39Regtest12Keys(Mnemonic("english").to_mnemonic(bytes(16)),
                                       source=SOURCE, authorized_disposable=True)
        recipient = Bip39Regtest12Keys(Mnemonic("english").to_mnemonic(bytes([2] * 16)),
                                       source=SOURCE, authorized_disposable=True)
        self.addCleanup(self.keys.close)
        self.addCleanup(recipient.close)
        self.code = recipient.accounts()[0].payment_code()
        self.fees = []

    def _fund(self, amounts):
        account = self.keys.accounts()[0].payment_code()
        transactions = []
        for index, atoms in enumerate(amounts):
            secret = 91 + index
            funding = Input("%02x" % (index + 5) * 32, 0, p2wpkh(secret),
                            witness=(bytes(72), pub(secret)), secret=secret)
            output = send([funding], [account])[0]
            whole, fraction = divmod(atoms, 100_000_000)
            transactions.append({
                "txid": "%02x" % (index + 10) * 32,
                "vin": [{"txid": funding.txid, "vout": 0, "scriptSig": {"hex": ""},
                         "txinwitness": [item.hex() for item in funding.witness],
                         "prevout": {"scriptPubKey": {"hex": funding.script.hex()}}}],
                "vout": [{"n": 0, "value": "%d.%08d" % (whole, fraction),
                          "scriptPubKey": {"hex": (b"\x51\x20" + output).hex()}}]})
        block = {"height": 1, "hash": sha256(repr(amounts).encode()).hexdigest(),
                 "previousblockhash": GENESIS, "tx": transactions}
        self.scanner = Scanner(self.path / "runtime.sqlite", self.keys.accounts())
        self.addCleanup(self.scanner.close)
        self.scanner.sync(_Chain(block))
        self.scanner.assert_current()
        self.scanner.store.db.execute(
            "INSERT INTO reservations VALUES(?,?,?,?,?)", FOREIGN)
        self.outputs = {(coin["txid"], coin["vout"]): coin
                        for coin in self.scanner.coins()}
        self.rpc = _FeeRpc(self.outputs, self.scanner.store.tip()[1])
        self.vault = _Vault(self.keys)
        from wam_regtest.wallet_session import WalletSession
        self.session = WalletSession(self.path, self.path, SOURCE, self.keys,
                                     self.scanner, self.vault, PASSWORD, None)
        self.session.snapshot = lambda *args: None
        self.session._rpc = lambda: self.rpc
        real_propose = Wallet.propose

        def propose(wallet, intents, fee, *args, **kwargs):
            self.fees.append(fee)
            return real_propose(wallet, intents, fee, *args, **kwargs)

        patcher = patch.object(Wallet, "propose", propose)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _states(self):
        return {row[3] for row in _rows(self.scanner)}

    def test_one_input_with_change_converges_on_the_first_fee(self):
        self._fund((100_000,))
        review = self.session.prepare_auto(self.code, 50_000)
        self.assertEqual(self.fees, [155])
        self.assertEqual(review.fee, 155)
        self.assertEqual(review.vsize, 155)
        self.assertEqual(review.overpay_atoms, 0)
        self.assertEqual(review.change_atoms, 100_000 - 50_000 - 155)
        self.assertGreater(review.change_atoms, 330)
        self.assertEqual(review.input_count, 1)
        self.assertEqual(review.total_debit, 50_155)
        self.assertEqual(review.available_before, 100_000)
        self.assertEqual(review.available_after, 0)
        self.assertEqual(review.rate_atoms_per_kvb, 1000)
        self.assertEqual(review.rate_source, "NETWORK_FLOOR")
        self.assertEqual(review.rate_classification, "UNAVAILABLE")
        self.assertGreaterEqual(
            review.fee, fee_for_vsize(review.vsize, review.fee_quote.floor_atoms_per_kvb))
        self.assertEqual(review.commitment, sha256(self.session._prepared.psbt).hexdigest())
        self.assertEqual(len(self.vault.saved), 1)
        self.assertEqual(self._states(), {"draft", "signed"})

    def test_change_dust_oscillation_accepts_the_higher_fee(self):
        # Coins 10_155 and 20_000, amount 10_000. Fee 112 makes the exact coin
        # dusty, so the lower attempt is released and the covering fee returns.
        self._fund((10_155, 20_000))
        review = self.session.prepare_auto(self.code, 10_000)
        self.assertEqual(self.fees, [155, 112, 155])
        self.assertLessEqual(len(self.fees), 6)
        self.assertEqual(review.input_count, 1)
        self.assertEqual(review.change_atoms, 0)
        self.assertEqual(review.vsize, 112)
        self.assertEqual(review.fee, 155)
        self.assertEqual(review.overpay_atoms, 43)
        self.assertGreater(review.available_after, 0)
        self.assertEqual(review.total_debit, 10_155)

    def test_stable_small_payment_steps_down_to_the_exact_fee(self):
        from wam_regtest.wallet_session import quoted_fee_holds
        self._fund((1_112, 1_155))
        review = self.session.prepare_auto(self.code, 1_000)
        self.assertEqual(self.fees, [155, 112])
        self.assertLessEqual(len(self.fees), 6)
        self.assertTrue(quoted_fee_holds(review))
        self.assertEqual(review.fee, 112)
        self.assertEqual(review.vsize, 112)
        self.assertEqual(review.overpay_atoms, 0)
        self.assertEqual(review.change_atoms, 0)
        self.assertEqual(review.input_count, 1)
        self.assertEqual(review.total_debit, 1_112)
        self.assertEqual(len(self.vault.saved), 1)

    def test_small_oscillation_is_refused_as_disproportionate_and_released(self):
        from wam_regtest.wallet_session import WalletSessionError
        self._fund((1_155, 2_000))
        with self.assertRaisesRegex(WalletSessionError, "FEE_DISPROPORTIONATE"):
            self.session.prepare_auto(self.code, 1_000)
        self.assertEqual(self.fees, [155, 112, 155])
        self.assertLessEqual(len(self.fees), 6)
        self.assertEqual(_rows(self.scanner), [FOREIGN])
        self.assertEqual(self.vault.saved, [])
        self.assertIsNone(self.session._prepared)
        self.assertFalse(self.session.faulted)

    def test_two_inputs_retry_once_and_keep_the_higher_fee(self):
        self._fund((800, 800))
        review = self.session.prepare_auto(self.code, 400)
        self.assertEqual(review.input_count, 2)
        self.assertGreater(review.change_atoms, 0)
        self.assertEqual(self.fees, [155, review.fee])
        self.assertGreater(review.fee, 155)
        self.assertEqual(review.overpay_atoms, 0)
        self.assertEqual(review.vsize, 212)
        self.assertEqual(review.fee, 212)
        self.assertIn(FOREIGN, _rows(self.scanner))
        self.assertEqual(sum(row[3] == "draft" for row in _rows(self.scanner)), 2)

    def test_amount_at_the_dust_floor_uses_the_network_minimum(self):
        self._fund((100_000,))
        review = self.session.prepare_auto(self.code, 330)
        self.assertEqual(review.fee, 155)
        self.assertEqual(review.vsize, 155)
        self.assertEqual(review.total_debit, 485)
        self.assertGreaterEqual(review.change_atoms, 330)

    def test_a_payment_that_fits_without_the_fee_is_refused(self):
        self._fund((10_000,))
        with self.assertRaisesRegex(ValueError, "INSUFFICIENT_SINGLE_CLUSTER_FUNDS"):
            # 9_600 alone leaves spendable change; 9_600 + the fee does not.
            self.session.prepare_auto(self.code, 9_600)
        self.assertEqual(_rows(self.scanner), [FOREIGN])
        self.assertEqual(self.vault.saved, [])

    def test_change_below_dust_is_refused_before_save(self):
        self._fund((800,))
        with self.assertRaisesRegex(ValueError, "INSUFFICIENT_SINGLE_CLUSTER_FUNDS"):
            # 330 + 155 leaves a change below the 330 dust floor.
            self.session.prepare_auto(self.code, 330)
        self.assertEqual(_rows(self.scanner), [FOREIGN])
        self.assertEqual(self.vault.saved, [])

    def test_unstable_structure_releases_every_unsaved_draft(self):
        from wam_regtest.wallet_session import WalletSessionError
        self._fund((100_000,))
        released = []
        real = Wallet.release_draft

        def release(wallet, token):
            rows = wallet.db.execute(
                "SELECT token,state FROM reservations WHERE token=?", (token,)).fetchall()
            self.assertTrue(rows)
            self.assertTrue(all(state == "draft" for _, state in rows))
            self.assertNotEqual(token, FOREIGN[2])
            self.assertEqual(self.vault.saved, [])
            released.append(token)
            return real(wallet, token)

        sizes = iter((1000, 2000, 3000, 4000))
        with patch.object(Wallet, "release_draft", release), \
                patch("wam_regtest.infrastructure.tx_size.psbt_vsize",
                      side_effect=lambda _psbt: next(sizes)):
            with self.assertRaisesRegex(WalletSessionError, "FEE_STRUCTURE_UNSTABLE"):
                self.session.prepare_auto(self.code, 50_000)
        self.assertEqual(self.fees, [155, 1000, 2000, 3000])
        self.assertEqual(self.fees, sorted(self.fees))
        self.assertLessEqual(len(self.fees), 6)
        self.assertEqual(len(released), 4)
        self.assertEqual(_rows(self.scanner), [FOREIGN])
        self.assertFalse(self.session.faulted)
        self.assertIsNone(self.session._prepared)

    def test_downward_attempt_stops_within_six_proposals(self):
        from wam_regtest.wallet_session import quoted_fee_holds
        self._fund((100_000,))
        sizes = iter((200, 300, 400, 300, 400, 300))
        with patch("wam_regtest.infrastructure.tx_size.psbt_vsize",
                   side_effect=lambda _psbt: next(sizes)):
            review = self.session.prepare_auto(self.code, 50_000)
        self.assertEqual(self.fees, [155, 200, 300, 400, 300, 400])
        self.assertEqual(len(self.fees), 6)
        self.assertTrue(quoted_fee_holds(review))
        self.assertEqual(review.fee, 400)
        self.assertEqual(review.vsize, 300)
        self.assertEqual(review.overpay_atoms, 100)
        self.assertEqual(len(self.vault.saved), 1)

    def test_uncertain_save_retains_the_accepted_draft(self):
        from wam_regtest.wallet_session import WalletSessionError
        self._fund((100_000,))
        self.vault.fail = True
        with self.assertRaisesRegex(WalletSessionError, "WALLET_PREPARE_DENIED"):
            self.session.prepare_auto(self.code, 50_000)
        self.assertTrue(self.session.faulted)
        self.assertIsNone(self.session._prepared)
        self.assertEqual(self.vault.saved, [])
        self.assertEqual(self._states(), {"draft", "signed"})

    def test_absolute_limit_is_refused_before_a_draft_exists(self):
        from wam_regtest.wallet_session import WalletSessionError
        self._fund((100_000,))
        with patch("wam_regtest.infrastructure.tx_size.estimated_one_input_vsize",
                   return_value=2_000_000):
            with self.assertRaisesRegex(WalletSessionError, "FEE_ABSOLUTE_LIMIT"):
                self.session.prepare_auto(self.code, 50_000)
        self.assertEqual(self.fees, [])
        self.assertEqual(_rows(self.scanner), [FOREIGN])

    def test_fee_above_the_amount_is_refused_and_the_draft_is_released(self):
        from wam_regtest.wallet_session import WalletSessionError
        self._fund((100_000,))
        with patch("wam_regtest.infrastructure.tx_size.psbt_vsize", return_value=400):
            with self.assertRaisesRegex(WalletSessionError, "FEE_EXCEEDS_AMOUNT"):
                self.session.prepare_auto(self.code, 330)
        self.assertEqual(_rows(self.scanner), [FOREIGN])
        self.assertEqual(self.vault.saved, [])

    def test_a_fee_below_the_floor_is_unreachable_and_still_refused(self):
        self._fund((100_000,))
        review = self.session.prepare_auto(self.code, 50_000)
        floor_fee = fee_for_vsize(review.vsize, review.fee_quote.floor_atoms_per_kvb)
        self.assertGreaterEqual(review.fee, floor_fee)
        self.assertGreaterEqual(review.fee_quote.rate_atoms_per_kvb,
                                review.fee_quote.floor_atoms_per_kvb)
        with self.assertRaisesRegex(FeePolicyError, "FEE_BELOW_NETWORK_FLOOR"):
            check_fee_limits(floor_fee - 1, review.atoms, review.vsize, review.fee_quote)

    def test_stale_quote_signs_nothing_and_a_fresh_prepare_works(self):
        from wam_regtest.wallet_session import WalletSessionError
        self._fund((100_000,))
        review = self.session.prepare_auto(self.code, 50_000)
        self.rpc.mempoolminfee = POLICY["getmempoolinfo"]["mempoolminfee"] * 2
        with patch.object(Wallet, "mark_signed") as mark, patch.object(Signer, "sign") as sign:
            with self.assertRaisesRegex(WalletSessionError, "FEE_QUOTE_STALE"):
                self.session.sign(review.commitment)
        mark.assert_not_called()
        sign.assert_not_called()
        self.assertIsNone(self.session._signed)
        self.assertFalse(self.session.faulted)
        self.assertIn("draft", self._states())
        self.session.cancel()
        self.assertEqual(_rows(self.scanner), [FOREIGN])
        self.rpc.mempoolminfee = POLICY["getmempoolinfo"]["mempoolminfee"]
        again = self.session.prepare_auto(self.code, 50_000)
        self.assertEqual(again.fee, review.fee)
        self.assertIsNotNone(self.session._prepared)

    def test_signed_vsize_must_match_or_the_payment_faults_without_broadcast(self):
        from wam_regtest.wallet_session import WalletSessionError
        self._fund((100_000,))
        review = self.session.prepare_auto(self.code, 50_000)
        with patch("wam_regtest.infrastructure.tx_size.serialized_vsize",
                   return_value=review.vsize + 1):
            with self.assertRaisesRegex(WalletSessionError,
                                        "WALLET_SIGN_UNCERTAIN_LOCK_RETAINED"):
                self.session.sign(review.commitment)
        self.assertTrue(self.session.faulted)
        self.assertIsNone(self.session._signed)
        self.assertNotIn("sendrawtransaction", self.rpc.calls)
        self.assertEqual(self._states(), {"signed"})
        # No signed bytes were retained, so broadcast has nothing to approve.
        with self.assertRaisesRegex(WalletSessionError, "WALLET_BROADCAST_APPROVAL_REQUIRED"):
            self.session.broadcast(review.commitment)
        self.assertTrue(self.session.faulted)
        self.assertNotIn("sendrawtransaction", self.rpc.calls)

    def test_a_matching_signature_keeps_the_quoted_vsize(self):
        self._fund((100_000,))
        review = self.session.prepare_auto(self.code, 50_000)
        self.session.sign(review.commitment)
        raw = PSBT.decode(self.session._signed).finalize()
        self.assertEqual(serialized_vsize(raw), review.vsize)
        self.assertEqual(psbt_vsize(self.session._prepared.psbt), review.vsize)
        self.assertIsNotNone(self.session._signed)
        self.assertNotIn("sendrawtransaction", self.rpc.calls)
        self.assertFalse(self.session.faulted)

    def test_tampered_commitment_is_refused_before_signing(self):
        from wam_regtest.wallet_session import WalletSessionError
        self._fund((100_000,))
        review = self.session.prepare_auto(self.code, 50_000)
        with patch.object(Wallet, "mark_signed") as mark, patch.object(Signer, "sign") as sign:
            with self.assertRaisesRegex(WalletSessionError,
                                        "WALLET_EXACT_INTENT_APPROVAL_REQUIRED"):
                self.session.sign("0" * 64)
        mark.assert_not_called()
        sign.assert_not_called()
        self.assertEqual(review.commitment, sha256(self.session._prepared.psbt).hexdigest())
        self.session.sign(review.commitment)
        self.assertIsNotNone(self.session._signed)

    def test_explicit_fee_prepare_still_skips_the_quote(self):
        self._fund((100_000,))
        review = self.session.prepare(self.code, 50_000, 1_000)
        self.assertIsNone(review.fee_quote)
        self.assertIsNone(review.vsize)
        self.assertEqual(review.fee, 1_000)
        self.session.sign(review.commitment)
        self.assertIsNotNone(self.session._signed)
        self.assertNotIn("estimatesmartfee", self.rpc.calls)

    def test_sole_coin_subdust_downward_refusal_keeps_the_covering_fee(self):
        # D-FEE2-1. Coin 100_155, amount 100_000. Fee 155 spends it exactly
        # (vsize 112, overpay 43). Fee 112 leaves rest 43, so the selector
        # refuses before reserving and the covering fee is proposed again.
        from wam_regtest.domain.fee_policy import check_fee_limits
        from wam_regtest.wallet_session import quoted_fee_holds
        self._fund((100_155,))
        trace = []
        built = []
        current = Wallet.propose

        def propose(wallet, intents, fee, *args, **kwargs):
            try:
                proposal = current(wallet, intents, fee, *args, **kwargs)
            except ValueError as error:
                if (type(error) is ValueError
                        and error.args == ("INSUFFICIENT_SINGLE_CLUSTER_FUNDS",)):
                    self.assertEqual(_rows(self.scanner), [FOREIGN])
                    trace.append("%d-refused" % fee)
                raise
            trace.append(fee)
            built.append(proposal.token)
            return proposal

        seen = []
        real_limits = check_fee_limits

        def limits(fee_atoms, amount_atoms, vsize, quote_):
            seen.append((fee_atoms, amount_atoms, vsize))
            return real_limits(fee_atoms, amount_atoms, vsize, quote_)

        with patch.object(Wallet, "propose", propose), \
                patch("wam_regtest.domain.fee_policy.check_fee_limits", limits):
            review = self.session.prepare_auto(self.code, 100_000)
        self.assertEqual(trace, [155, "112-refused", 155])
        self.assertEqual(self.fees, [155, 112, 155])
        self.assertLessEqual(len(self.fees), 6)
        self.assertTrue(quoted_fee_holds(review))
        self.assertEqual(review.fee, 155)
        self.assertEqual(review.change_atoms, 0)
        self.assertEqual(review.vsize, 112)
        self.assertEqual(review.overpay_atoms, 43)
        self.assertEqual(review.input_count, 1)
        self.assertEqual(review.total_debit, 100_155)
        self.assertEqual(review.available_before, 100_155)
        self.assertEqual(review.available_after, 0)
        self.assertEqual(seen, [(155, 100_000, 112)])
        drafts = [row for row in _rows(self.scanner) if row[3] == "draft"]
        self.assertEqual([row[2] for row in drafts], [built[-1]])
        self.assertNotIn(built[0], {row[2] for row in _rows(self.scanner)})
        self.assertIn(FOREIGN, _rows(self.scanner))
        self.assertEqual(len(self.vault.saved), 1)
        self.assertFalse(self.session.faulted)

    def test_higher_reproposal_that_grows_is_unstable_and_released(self):
        # The lower fee is refused, then the covering fee is proposed again.
        # If that re-proposal fails to cover because its measured need grew,
        # the result is FEE_STRUCTURE_UNSTABLE and every draft is released.
        from wam_regtest.wallet_session import WalletSessionError
        self._fund((100_155,))
        anchor = self.vault.anchor.value
        released = []
        real = Wallet.release_draft

        def release(wallet, token):
            rows = wallet.db.execute(
                "SELECT token,state FROM reservations WHERE token=?", (token,)).fetchall()
            self.assertTrue(rows)
            self.assertTrue(all(state == "draft" for _, state in rows))
            self.assertNotEqual(token, FOREIGN[2])
            self.assertEqual(self.vault.saved, [])
            released.append(token)
            return real(wallet, token)

        sizes = iter((112, 1000))
        with patch.object(Wallet, "release_draft", release), \
                patch("wam_regtest.infrastructure.tx_size.psbt_vsize",
                      side_effect=lambda _psbt: next(sizes)):
            with self.assertRaisesRegex(WalletSessionError, "FEE_STRUCTURE_UNSTABLE"):
                self.session.prepare_auto(self.code, 100_000)
        self.assertEqual(self.fees, [155, 112, 155])
        self.assertLessEqual(len(self.fees), 6)
        self.assertEqual(len(released), 2)
        self.assertEqual(len(set(released)), 2)
        self.assertEqual(_rows(self.scanner), [FOREIGN])
        self.assertEqual(self.vault.saved, [])
        self.assertFalse(self.session.faulted)
        self.assertIsNone(self.session._prepared)
        self.assertEqual(self.vault.anchor.value, anchor)

    def test_downward_non_funds_exception_still_maps(self):
        from wam_regtest.gui_errors import operation_error
        self._fund((100_155,))
        anchor = self.vault.anchor.value
        current = Wallet.propose

        def propose(wallet, intents, fee, *args, **kwargs):
            if fee != 155:
                raise ValueError("FEE_POLICY")
            return current(wallet, intents, fee, *args, **kwargs)

        with patch.object(Wallet, "propose", propose):
            with self.assertRaises(ValueError) as caught:
                self.session.prepare_auto(self.code, 100_000)
        self.assertIs(type(caught.exception), ValueError)
        self.assertEqual(caught.exception.args, ("FEE_POLICY",))
        self.assertEqual(operation_error("prepare_auto", caught.exception),
                         "WALLET_INPUT_FEE_INVALID")
        self.assertEqual(self.fees, [155])
        self.assertEqual(_rows(self.scanner), [FOREIGN])
        self.assertEqual(self.vault.saved, [])
        self.assertFalse(self.session.faulted)
        self.assertIsNone(self.session._prepared)
        self.assertEqual(self.vault.anchor.value, anchor)

    def test_downward_prepare_failure_still_denies_and_releases(self):
        # A constructable lower fee whose prepare fails still maps inside
        # propose_once. WalletSessionError is a ValueError and is not retried.
        from wam_regtest.wallet_session import WalletSessionError
        self._fund((10_155, 20_000))
        anchor = self.vault.anchor.value
        calls = {"n": 0}
        real = Signer.prepare

        def prepare(signer, proposal):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("FEE2_PUBLIC_PREPARE_FAULT")
            return real(signer, proposal)

        with patch.object(Signer, "prepare", prepare):
            with self.assertRaisesRegex(WalletSessionError, "WALLET_PREPARE_DENIED"):
                self.session.prepare_auto(self.code, 10_000)
        self.assertEqual(calls["n"], 2)
        self.assertEqual(_rows(self.scanner), [FOREIGN])
        self.assertEqual(self.vault.saved, [])
        self.assertFalse(self.session.faulted)
        self.assertIsNone(self.session._prepared)
        self.assertEqual(self.vault.anchor.value, anchor)

    def test_subdust_remainder_without_exact_fee_is_characterized_as_refused(self):
        # Characterization only (D-FEE2-2). Do not absorb the remainder.
        # Owner decision: absorb at most 329 atoms of sub-dust remainder into
        # the fee, or refuse. Coin 100_200 and amount 100_000 leave rest 45
        # over the quoted fee of 155, below the 330-atom change floor. The
        # loop never computes a zero-remainder fee. Public code of this
        # first-round refusal: WALLET_INPUT_FUNDS_UNAVAILABLE.
        from wam_regtest.gui_errors import operation_error
        coin, amount, quoted_fee = 100_200, 100_000, 155
        rest = coin - amount - quoted_fee
        self.assertGreater(rest, 0)
        self.assertLess(rest, 330)
        self._fund((coin,))
        anchor = self.vault.anchor.value
        with self.assertRaises(ValueError) as caught:
            self.session.prepare_auto(self.code, amount)
        self.assertIs(type(caught.exception), ValueError)
        self.assertEqual(caught.exception.args, ("INSUFFICIENT_SINGLE_CLUSTER_FUNDS",))
        self.assertEqual(operation_error("prepare_auto", caught.exception),
                         "WALLET_INPUT_FUNDS_UNAVAILABLE")
        self.assertEqual(self.fees, [quoted_fee])
        self.assertNotIn(coin - amount, self.fees)
        self.assertEqual(_rows(self.scanner), [FOREIGN])
        self.assertEqual(self.vault.saved, [])
        self.assertFalse(self.session.faulted)
        self.assertIsNone(self.session._prepared)
        self.assertIsNone(self.session._review)
        self.assertEqual(self.vault.anchor.value, anchor)


class ProductionPrepare(unittest.TestCase):
    def test_shipped_backends_refuse_an_explicit_fee(self):
        from wam_regtest import ui_settings
        from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend
        from wam_regtest.wallet_executor import ManagedWalletBackend, WalletExecutorError
        previous = ui_settings._native
        ui_settings.use_native_store()
        try:
            managed = ManagedWalletBackend.__new__(ManagedWalletBackend)
            owner = Bip39ReadOnlyBackend.__new__(Bip39ReadOnlyBackend)
            with self.assertRaisesRegex(WalletExecutorError, "FEE_EXPLICIT_PREPARE_DENIED"):
                managed.execute("prepare", ("code", 1_000, 155), {})
            with self.assertRaisesRegex(WalletExecutorError, "FEE_EXPLICIT_PREPARE_DENIED"):
                owner.execute("prepare", ("code", 1_000, 155), {})
        finally:
            ui_settings._native = previous
        self.assertFalse(ui_settings.native_store_enabled())
        managed = ManagedWalletBackend.__new__(ManagedWalletBackend)
        with self.assertRaises(Exception) as caught:
            managed.execute("prepare", ("code", 1_000, 155), {})
        self.assertNotEqual(caught.exception.args[:1], ("FEE_EXPLICIT_PREPARE_DENIED",))


class RemovedFeeWidget(unittest.TestCase):
    def test_qualification_code_does_not_drive_a_removed_fee_widget(self):
        root = Path(__file__).resolve().parents[1]
        needles = ("fee_input", ".fee.setText")
        paths = [
            root / "src/wam_regtest/qualification",
            root / "src/wam_regtest/wallet_probe.py",
            root / "src/wam_regtest/linux_qt_probe.py",
            root / "src/wam_regtest/shared_network_probe.py",
            root / "src/wam_regtest/q05_gui_scenario.py",
            root / "src/wam_regtest/q06_spend_probe.py",
            root / "src/wam_regtest/q06_platform_probe.py",
            root / "scripts/owner_acceptance.py",
            root / "src/wam_regtest/bip39_fusion_gui.py",
            root / "src/wam_regtest/bip39_owner_gui.py",
            root / "src/wam_regtest/operational_gui.py",
        ]
        hits = []
        for path in paths:
            files = sorted(path.rglob("*.py")) if path.is_dir() else [path]
            for source in files:
                text = source.read_text()
                for needle in needles:
                    if needle in text:
                        hits.append(f"{source.relative_to(root)}:{needle}")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
