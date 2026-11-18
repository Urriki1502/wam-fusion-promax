"""REC-2 (PM-077): uncertain and signed resume share one preflight boundary.

Real pinned-WSP scanner/PSBT/signer/reservations and real encrypted create-only
payment evidence (macOS native storage); synthetic Core RPC and anchored-vault
doubles. A definitive typed policy rejection on resume must keep the ORIGINAL
state, locks, bytes and provenance without a new fault, a new uncertainty latch,
a send, a re-sign or a fee rewrite. Malformed/untrusted/transport preflight
failures keep today's fault. A non-signalling stored PSBT refuses before any
RPC. The allowlisted token alone crosses session → executor → GUI.
"""
from preflight_fixtures import accepted_reply
from contextlib import nullcontext
from dataclasses import replace
from hashlib import sha256
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from mnemonic import Mnemonic
from wam_regtest.bip39_12 import Bip39Regtest12Keys
from wam_sp.core import Input, pub, send
from wam_sp.psbt import PSBT
from wam_sp.scanner import Scanner
from wam_sp.transaction import p2wpkh
from wam_sp.wallet import Signer, Wallet
from wam_sp.watcher import GENESIS

SOURCE = Path(importlib.util.find_spec("wam_sp").origin).resolve().parents[2]
PASSWORD = b"rec2 disposable public test password"
KEY = "errors.WALLET_BROADCAST_REJECTED_LOCK_RETAINED"
ENGLISH = ("The local node rejected this attempt before submission. "
           "No transaction was sent in this attempt. Your inputs remain "
           "reserved. An earlier attempt may still have been submitted. "
           "Nothing is retried or released automatically.")
LANGUAGES = ("en", "zh-Hans", "vi", "ko", "id", "ja")
# The retired copy claimed every reservation 'stays signed'; no language may
# carry that signed-only claim any more.
OLD_SIGNED_CLAIMS = ("signed", "已签名", "đã ký", "서명된", "ditandatangani", "署名済み")


class Crash(BaseException):
    pass


def _states(scanner):
    return {r[0] for r in scanner.store.db.execute("SELECT state FROM reservations")}


def _reservations(scanner):
    return tuple(scanner.store.db.execute(
        "SELECT txid,vout,token,state,created FROM reservations ORDER BY token,txid,vout"
    ).fetchall())


def _evidence_files(session):
    directory = session._evidence_store()._folder()
    return {p.name: p.read_bytes() for p in sorted(directory.iterdir())}


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
        raise ValueError("REC2_SYNTHETIC_RPC_METHOD_DENIED")


class _Core:
    """Synthetic Core: a mempool set, spent outpoints and a send behaviour."""

    def __init__(self, test):
        self.test, self.mempool, self.spent = test, set(), set()
        self.accept, self.send, self.calls = True, None, []

    def attest(self):
        return None

    def _call(self, method, params):
        if method == "getrawmempool":
            return sorted(self.mempool)
        if method == "getblockchaininfo":
            # OBS-01a: whole-acquisition prerequisite 1 (equal heights).
            return {"blocks": 1, "headers": 1, "initialblockdownload": False}
        raise ValueError("REC2_RPC_DENIED")

    def call(self, method, params=None):
        if method == "getbestblockhash":
            return self.test.tip
        if method == "getblockcount":
            return 1
        if method == "getblockhash":
            return GENESIS if params[0] == 0 else self.test.tip
        if method == "gettxout":
            if (params[0], params[1]) in self.spent:
                return None
            return {"bestblock": self.test.tip, "value": 0.001,
                    "scriptPubKey": {"hex": "5120" + self.test.coin["public_key"]}}
        self.calls.append(method)
        if method == "testmempoolaccept":
            if isinstance(self.accept, BaseException):
                raise self.accept
            return (accepted_reply(self.test.signed) if self.accept is True else
                    [{"allowed": self.accept}])
        if method == "sendrawtransaction":
            raw = PSBT.decode(self.test.signed)
            if isinstance(self.send, BaseException):
                if getattr(self.send, "reached_core", False):
                    self.mempool.add(raw.txid())
                raise self.send
            self.mempool.add(raw.txid())
            return raw.txid()
        raise ValueError("REC2_RPC_DENIED")


class _Vault:
    def __init__(self, keys):
        self.keys, self.saved, self.cipher = keys, [], None
        self.anchor = SimpleNamespace(wallet_id="d" * 32, value=(1, "a" * 64),
                                      lease=lambda: nullcontext())
        self.anchor.read = lambda: self.anchor.value
        self._expected = self.anchor.value

    def save(self, keys, scanner, password):
        self.saved.append(_states(scanner))
        self.cipher = scanner.checkpoint(password)
        self.anchor.value = (self.anchor.value[0] + 1, sha256(self.cipher).hexdigest())
        self._expected = self.anchor.value


@unittest.skipUnless(sys.platform == "darwin", "native macOS encrypted evidence storage")
class UncertainResumePreflight(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="rec2-")
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name).resolve()
        self.keys = Bip39Regtest12Keys(Mnemonic("english").to_mnemonic(bytes(16)),
                                       source=SOURCE, authorized_disposable=True)
        recipient = Bip39Regtest12Keys(Mnemonic("english").to_mnemonic(bytes([1] * 16)),
                                       source=SOURCE, authorized_disposable=True)
        self.addCleanup(self.keys.close)
        self.addCleanup(recipient.close)
        self.code = recipient.accounts()[0].payment_code()
        funding = Input("05" * 32, 0, p2wpkh(91), witness=(bytes(72), pub(91)), secret=91)
        output = send([funding], [self.keys.accounts()[0].payment_code()])[0]
        self.block = {"height": 1, "hash": sha256(b"rec2 synthetic chain").hexdigest(),
                      "previousblockhash": GENESIS, "tx": [{
                          "txid": "ab" * 32,
                          "vin": [{"txid": funding.txid, "vout": 0, "scriptSig": {"hex": ""},
                                   "txinwitness": [v.hex() for v in funding.witness],
                                   "prevout": {"scriptPubKey": {"hex": funding.script.hex()}}}],
                          "vout": [{"n": 0, "value": 0.001,
                                    "scriptPubKey": {"hex": (b"\x51\x20" + output).hex()}}]}]}
        self.scanner = self._scanner("runtime.sqlite")
        self.coin = self.scanner.coins()[0]
        self.tip = self.scanner.store.tip()[1]
        self.core = _Core(self)
        for p in (patch("wam_regtest.bip39_spend_session._owned"),
                  patch("wam_regtest.bip39_spend_session._owner_binding",
                        return_value="public-test-owner-binding")):
            p.start()
            self.addCleanup(p.stop)

    def _scanner(self, name, cipher=None):
        scanner = Scanner(self.path / name, self.keys.accounts())
        self.addCleanup(scanner.close)
        if cipher is not None:
            scanner.restore(cipher, PASSWORD)
        scanner.sync(_Chain(self.block))
        scanner.assert_current()
        return scanner

    def _session(self, scanner, vault):
        from wam_regtest.bip39_spend_session import Q06OwnedSpendSession
        from wam_regtest.wallet_session import WalletSession
        owner = SimpleNamespace(core=self.path, directory=self.path, cli=self.path,
                                receipt={"wamd_sha256": "0" * 64})
        guard = SimpleNamespace(check=lambda: None, close=lambda: None)
        session = Q06OwnedSpendSession(owner, SOURCE, self.keys, scanner, guard, vault, PASSWORD)
        p = patch.object(WalletSession, "_rpc", lambda _self: self.core)
        p.start()
        self.addCleanup(p.stop)
        session.snapshot = lambda *a, **k: SimpleNamespace(height=1, tip=self.tip)
        return session

    def _signed_session(self):
        self.vault = _Vault(self.keys)
        session = self._session(self.scanner, self.vault)
        review = session.prepare(self.code, 50_000, 1000)
        session.sign(review.commitment)
        self.signed = session._signed
        self.txid = PSBT.decode(self.signed).txid()
        self.token = session._prepared.proposal.token
        return session, review

    def _restart(self):
        """Crash recovery: fresh runtime restored from the last anchored checkpoint."""
        scanner = self._scanner("restart-%d.sqlite" % len(self.vault.saved), self.vault.cipher)
        return self._session(scanner, self.vault)

    def _item(self, session, token):
        status = session.signed_intent_status()
        self.assertFalse(status["write_attempted"] or status["automatic_resume"]
                         or status["abandon_available"])
        return next(i for i in status["intents"] if i["token"] == token)

    def _reject_core(self, reason):
        """A definitive policy rejection with the typed Core reason attached."""
        original_call = self.core.call

        def call(method, params=None):
            reply = original_call(method, params)
            if (method == "testmempoolaccept" and type(reply) is list and len(reply) == 1
                    and type(reply[0]) is dict and reply[0].get("allowed") is False):
                reply[0]["reject-reason"] = reason
            return reply
        self.core.call = call

    # ---- same preflight boundary for 'uncertain' (REC-2 §5 bullet 1) ------
    def test_uncertain_resume_policy_rejection_refuses_and_keeps_everything(self):
        for reason, expected_token in (
                ("min relay fee not met", "FEE_POLICY_REJECTED"),
                ("dust", "POLICY_REJECTED"),
                ("txn-already-in-mempool", "ALREADY_IN_MEMPOOL"),
        ):
            with self.subTest(reason=reason):
                self.setUp()
                session, review = self._signed_session()
                self.core.send = Crash()
                with self.assertRaises(Crash):
                    session.broadcast(review.commitment)
                restarted = self._restart()
                self.assertEqual(self.vault.saved[-1], {"uncertain"})
                self.assertEqual(self._item(restarted, self.token)["classification"],
                                 "UNCERTAIN_NOT_OBSERVED_RESUMABLE")
                self.core.accept = False
                self._reject_core(reason)
                self.core.calls.clear()
                before_files = _evidence_files(restarted)
                before_rows = _reservations(restarted.scanner)
                before_saved = list(self.vault.saved)
                from wam_regtest.wallet_session import WalletSessionError
                with self.assertRaises(WalletSessionError) as caught:
                    restarted.resume_signed_intent(self.token, self.txid, approved=True)
                self.assertEqual(caught.exception.args,
                                 ("WALLET_BROADCAST_REJECTED_LOCK_RETAINED",))
                self.assertEqual(caught.exception.preflight_rejection, expected_token)
                self.assertEqual(self.core.calls, ["testmempoolaccept"])
                # The ORIGINAL uncertain state, locks, bytes and provenance are kept.
                self.assertEqual(_states(restarted.scanner), {"uncertain"})
                self.assertEqual(_reservations(restarted.scanner), before_rows)
                self.assertEqual(self.vault.saved, before_saved)
                self.assertEqual(_evidence_files(restarted), before_files)
                # No new session fault or uncertainty latch; historical uncertainty
                # is NOT cleared, and the inventory stays reachable for review.
                self.assertFalse(restarted.faulted)
                self.assertFalse(restarted._q06_uncertain)
                self.assertEqual(self._item(restarted, self.token)["classification"],
                                 "UNCERTAIN_NOT_OBSERVED_RESUMABLE")

    def test_uncertain_resume_still_requires_explicit_approval(self):
        session, review = self._signed_session()
        self.core.send = Crash()
        with self.assertRaises(Crash):
            session.broadcast(review.commitment)
        restarted = self._restart()
        self.core.calls.clear()
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        with self.assertRaisesRegex(Q06SpendSessionError, "EXPLICIT_APPROVAL_REQUIRED"):
            restarted.resume_signed_intent(self.token, self.txid)
        self.assertEqual(self.core.calls, [])
        self.assertEqual(_states(restarted.scanner), {"uncertain"})

    def test_uncertain_accepted_preflight_submits_exactly_once(self):
        session, review = self._signed_session()
        self.core.send = Crash()
        with self.assertRaises(Crash):
            session.broadcast(review.commitment)
        self.core.send = None
        restarted = self._restart()
        self.core.calls.clear()
        result = restarted.resume_signed_intent(self.token, self.txid, approved=True)
        self.assertEqual((result["txid"], result["resigned"], result["automatic"]),
                         (self.txid, False, False))
        # REC-2: product preflight runs first, then WSP's own preflight + send.
        self.assertEqual(self.core.calls,
                         ["testmempoolaccept", "testmempoolaccept", "sendrawtransaction"])
        self.assertEqual(self.vault.saved[-1], {"broadcast"})
        self.assertEqual(_states(restarted.scanner), {"broadcast"})
        self.assertEqual(restarted._q06_pending_confirm, self.txid)
        self.assertFalse(restarted.faulted or restarted._q06_uncertain)

    def test_uncertain_malformed_preflight_latches_and_is_never_relabelled(self):
        session, review = self._signed_session()
        self.core.send = Crash()
        with self.assertRaises(Crash):
            session.broadcast(review.commitment)
        restarted = self._restart()
        original_call = self.core.call

        def call(method, params=None):
            reply = original_call(method, params)
            if method == "testmempoolaccept":
                reply[0]["txid"] = "f" * 64
            return reply
        self.core.call = call
        self.core.calls.clear()
        before_saved = list(self.vault.saved)
        before_files = _evidence_files(restarted)
        before_rows = _reservations(restarted.scanner)
        from wam_regtest.wallet_session import WalletSessionError
        with self.assertRaises(WalletSessionError) as caught:
            restarted.resume_signed_intent(self.token, self.txid, approved=True)
        # Trust refusal preserved; UNKNOWN is not a policy rejection.
        self.assertEqual(caught.exception.args,
                         ("WALLET_BROADCAST_NOT_SUBMITTED_LOCK_RETAINED",))
        self.assertFalse(hasattr(caught.exception, "preflight_rejection"))
        self.assertNotIn("sendrawtransaction", self.core.calls)
        self.assertEqual(_states(restarted.scanner), {"uncertain"})
        self.assertEqual(_reservations(restarted.scanner), before_rows)
        self.assertEqual(self.vault.saved, before_saved)
        self.assertEqual(_evidence_files(restarted), before_files)
        self.assertTrue(restarted.faulted)
        # Nothing reached send, so no new submission uncertainty was created.
        self.assertFalse(restarted._q06_uncertain)

    def test_uncertain_transport_and_untrusted_preflight_latch_never_relabelled(self):
        from wam_regtest.wallet_session import WalletSessionError
        for failure in (RuntimeError("PUBLIC_RPC_LOSS"),
                        WalletSessionError("WALLET_CORE_IDENTITY_DENIED")):
            with self.subTest(failure=type(failure).__name__):
                self.setUp()
                session, review = self._signed_session()
                self.core.send = Crash()
                with self.assertRaises(Crash):
                    session.broadcast(review.commitment)
                restarted = self._restart()
                self.core.accept = failure
                self.core.calls.clear()
                before_saved = list(self.vault.saved)
                before_files = _evidence_files(restarted)
                with self.assertRaises(WalletSessionError) as caught:
                    restarted.resume_signed_intent(self.token, self.txid, approved=True)
                self.assertEqual(caught.exception.args,
                                 ("WALLET_BROADCAST_NOT_SUBMITTED_LOCK_RETAINED",))
                self.assertFalse(hasattr(caught.exception, "preflight_rejection"))
                self.assertNotIn("sendrawtransaction", self.core.calls)
                self.assertEqual(_states(restarted.scanner), {"uncertain"})
                self.assertEqual(self.vault.saved, before_saved)
                self.assertEqual(_evidence_files(restarted), before_files)
                self.assertTrue(restarted.faulted)
                self.assertFalse(restarted._q06_uncertain)

    # ---- the same boundary stays exact for 'signed' ------------------------
    def test_signed_resume_policy_rejection_refuses_and_keeps_everything(self):
        session, review = self._signed_session()
        self.core.accept = Crash()
        with self.assertRaises(Crash):
            session.broadcast(review.commitment)
        restarted = self._restart()
        self.assertEqual(self.vault.saved[-1], {"signed"})
        self.assertEqual(self._item(restarted, self.token)["classification"],
                         "SIGNED_NOT_SUBMITTED_RESUMABLE")
        self.core.accept = False
        self._reject_core("min relay fee not met")
        self.core.calls.clear()
        before_files = _evidence_files(restarted)
        before_rows = _reservations(restarted.scanner)
        before_saved = list(self.vault.saved)
        from wam_regtest.wallet_session import WalletSessionError
        with self.assertRaises(WalletSessionError) as caught:
            restarted.resume_signed_intent(self.token, self.txid, approved=True)
        self.assertEqual(caught.exception.args, ("WALLET_BROADCAST_REJECTED_LOCK_RETAINED",))
        self.assertEqual(caught.exception.preflight_rejection, "FEE_POLICY_REJECTED")
        self.assertEqual(self.core.calls, ["testmempoolaccept"])
        self.assertEqual(_states(restarted.scanner), {"signed"})
        self.assertEqual(_reservations(restarted.scanner), before_rows)
        self.assertEqual(self.vault.saved, before_saved)
        self.assertEqual(_evidence_files(restarted), before_files)
        self.assertFalse(restarted.faulted)
        self.assertFalse(restarted._q06_uncertain)
        self.assertEqual(self._item(restarted, self.token)["classification"],
                         "SIGNED_NOT_SUBMITTED_RESUMABLE")

    # ---- RBF-RESUME-01 ------------------------------------------------------
    def _install_nonsignalling_intent(self, sequence=0xFFFFFFFF):
        """A second stored intent whose PSBT no longer signals replaceability.

        The stored bytes are sealed by the real evidence store, and matching
        reservation + coin rows are inserted directly; the resume path must
        refuse on the local BIP125 check before any preflight or send RPC.
        """
        from wam_regtest.bip39_spend_session import _owner_binding
        base = PSBT.decode(self.signed)
        nonsignalling = replace(base, tx=replace(base.tx, inputs=(("07" * 32, 0),),
                                                 sequence=sequence)).encode()
        self.assertEqual(PSBT.decode(nonsignalling).tx.sequence_values(), (sequence,))
        token = "c" * 32
        txid = PSBT.decode(nonsignalling).txid()
        session = self._restart()
        with session.scanner.store.transaction():
            session.scanner.store.db.execute(
                "INSERT INTO coins(txid,vout,account,epoch,atoms,public_key,tweak,label,k,received,spent) "
                "SELECT ?,0,account,epoch,atoms,public_key,tweak,label,k,received,NULL "
                "FROM coins WHERE txid=? AND vout=?",
                ("07" * 32, self.coin["txid"], self.coin["vout"]))
            session.scanner.store.db.execute(
                "INSERT INTO reservations(txid,vout,token,state,created) VALUES (?,?,?,?,?)",
                ("07" * 32, 0, token, "signed", 0))
        session._evidence_store().write(
            "signed", signed=nonsignalling,
            review=SimpleNamespace(commitment=sha256(b"rec2 rbf fixture").hexdigest(),
                                   code=self.code, atoms=50_000, fee=1000),
            token=token, owner_binding=lambda: _owner_binding(None),
            account_id=lambda: session.ring.public_metadata()["account_id"],
            password=PASSWORD, legacy_unrecorded=True)
        return session, token, txid

    def test_nonsignalling_stored_psbt_refuses_before_any_rpc(self):
        from wam_regtest.wallet_session import WalletSessionError
        for sequence in (0xFFFFFFFF, 0xFFFFFFFE):
            with self.subTest(sequence=hex(sequence)):
                self.setUp()
                self._signed_session()
                session, token, txid = self._install_nonsignalling_intent(sequence)
                self.assertEqual(self._item(session, token)["classification"],
                                 "SIGNED_NOT_SUBMITTED_RESUMABLE")
                self.core.calls.clear()
                before_saved = list(self.vault.saved)
                before_rows = _reservations(session.scanner)
                with self.assertRaises(WalletSessionError) as caught:
                    session.resume_signed_intent(token, txid, approved=True)
                self.assertEqual(caught.exception.args, ("RBF_SIGNALLING_MISSING",))
                self.assertFalse(hasattr(caught.exception, "preflight_rejection"))
                # Refused before any preflight or submission; the state is kept.
                self.assertEqual(self.core.calls, [])
                self.assertEqual(_reservations(session.scanner), before_rows)
                self.assertEqual(self.vault.saved, before_saved)
                self.assertFalse(session.faulted)
                self.assertFalse(session._q06_uncertain)

    def test_uncertain_nonsignalling_stored_psbt_refuses_before_any_rpc(self):
        from wam_regtest.wallet_session import WalletSessionError
        self._signed_session()
        session, token, txid = self._install_nonsignalling_intent()
        # Move the same stored intent to 'uncertain' as a prior attempt would.
        with session.scanner.store.transaction():
            session.scanner.store.db.execute(
                "UPDATE reservations SET state='uncertain' WHERE token=?", (token,))
        self.assertEqual(self._item(session, token)["classification"],
                         "UNCERTAIN_NOT_OBSERVED_RESUMABLE")
        self.core.calls.clear()
        before_saved = list(self.vault.saved)
        before_rows = _reservations(session.scanner)
        with self.assertRaises(WalletSessionError) as caught:
            session.resume_signed_intent(token, txid, approved=True)
        self.assertEqual(caught.exception.args, ("RBF_SIGNALLING_MISSING",))
        self.assertEqual(self.core.calls, [])
        self.assertEqual(_reservations(session.scanner), before_rows)
        self.assertEqual(self.vault.saved, before_saved)
        self.assertFalse(session.faulted)
        self.assertFalse(session._q06_uncertain)


class AllowlistAndPropagation(unittest.TestCase):
    """§5.1: only the fixed allowlisted token crosses session → executor → GUI."""

    def _executor(self, failure):
        from wam_regtest.wallet_executor import WalletExecutor

        class _Backend:
            def __init__(self):
                self.failure = failure

            def execute(self, action, args, kwargs):
                if action == "quit":
                    return {}
                raise self.failure

            def public_state(self):
                return {"locked": True, "faulted": False,
                        "reauthentication_required": False, "core_alive": False}

        return WalletExecutor(_Backend)

    def _deny(self, failure):
        executor = self._executor(failure)
        try:
            with self.assertRaises(Exception) as caught:
                executor.submit("resume_intent", "a" * 32, "b" * 64, True).result(timeout=30)
            return caught.exception
        finally:
            executor.submit("quit").result(timeout=30)

    def _session_rejection(self, token=None, *, cls=None,
                           code="WALLET_BROADCAST_REJECTED_LOCK_RETAINED"):
        from wam_regtest.wallet_session import WalletSessionError
        error = (WalletSessionError if cls is None else cls)(code)
        if token is not None:
            error.preflight_rejection = token
        return error

    def test_allowlist_matches_the_preflight_classifier(self):
        from wam_regtest.domain.preflight import PREFLIGHT_REJECT_REASONS
        from wam_regtest.wallet_session import PREFLIGHT_REJECTION_TOKENS
        self.assertEqual(PREFLIGHT_REJECTION_TOKENS,
                         set(PREFLIGHT_REJECT_REASONS.values()) | {"POLICY_REJECTED"})

    def test_allowlisted_token_reaches_the_executor_typed(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        from wam_regtest.wallet_executor import WalletExecutorError
        from wam_regtest.wallet_session import WalletSessionError
        for cls in (WalletSessionError, Q06SpendSessionError):
            for token in ("FEE_POLICY_REJECTED", "POLICY_REJECTED", "ALREADY_IN_MEMPOOL"):
                with self.subTest(cls=cls.__name__, token=token):
                    error = self._deny(self._session_rejection(token, cls=cls))
                    self.assertIs(type(error), WalletExecutorError)
                    self.assertEqual(error.args, ("WALLET_BROADCAST_REJECTED_LOCK_RETAINED",))
                    self.assertEqual(getattr(error, "preflight_rejection", None), token)

    def test_unlisted_missing_or_untrusted_tokens_never_cross(self):
        from wam_regtest.gui_errors import preflight_rejection
        from wam_regtest.wallet_session import WalletSessionError

        class HostileValueError(ValueError):
            def __str__(self):
                raise AssertionError("str() must not be called")

        error = self._deny(self._session_rejection("MALICIOUS_CUSTOM_TOKEN"))
        self.assertIsNone(getattr(error, "preflight_rejection", None))
        self.assertEqual(error.args, ("WALLET_BROADCAST_REJECTED_LOCK_RETAINED",))
        self.assertIsNone(preflight_rejection(error))
        error = self._deny(self._session_rejection(None))
        self.assertIsNone(getattr(error, "preflight_rejection", None))
        self.assertIsNone(preflight_rejection(error))
        # Untrusted ValueError / RuntimeError or non-rejection codes never cross.
        for bad in (
                self._session_rejection("FEE_POLICY_REJECTED", cls=ValueError),
                self._session_rejection("FEE_POLICY_REJECTED", cls=HostileValueError),
                self._session_rejection("FEE_POLICY_REJECTED", cls=WalletSessionError,
                                        code="WALLET_BROADCAST_NOT_SUBMITTED_LOCK_RETAINED"),
        ):
            delivered = self._deny(bad)
            self.assertIsNone(getattr(delivered, "preflight_rejection", None))
            self.assertIsNone(preflight_rejection(bad))
            self.assertIsNone(preflight_rejection(delivered))

    def test_arbitrary_exception_text_never_reaches_the_result(self):
        from wam_regtest.wallet_executor import WalletExecutorError
        secret = ValueError("unexpected rpc error with SECRET rpc detail")
        error = self._deny(secret)
        self.assertIs(type(error), WalletExecutorError)
        self.assertEqual(error.args, ("WALLET_EXECUTOR_DENIED",))
        self.assertIsNone(getattr(error, "preflight_rejection", None))
        self.assertNotIn("SECRET", " ".join(str(a) for a in error.args))

    def test_gui_sees_the_public_category_and_neutral_copy_after_executor_transport(self):
        from PySide6.QtWidgets import QApplication
        from wam_regtest.bip39_owner_gui import Bip39TrialWindow
        from wam_regtest.gui_errors import error_text, operation_error, preflight_rejection
        from wam_regtest.wallet_executor import ExecutorState, WalletExecutorError
        delivered = self._deny(self._session_rejection("FEE_POLICY_REJECTED"))
        code = operation_error("resume_intent", delivered)
        self.assertEqual(code, "WALLET_BROADCAST_REJECTED_LOCK_RETAINED")
        self.assertEqual(preflight_rejection(delivered), "FEE_POLICY_REJECTED")
        self.assertEqual(error_text(code), ENGLISH)

        app = QApplication.instance() or QApplication([])

        class Owner:
            state = ExecutorState(locked=False, core_alive=True)
            busy = False
            closed = False

        window = Bip39TrialWindow(Owner())
        try:
            window._on_denied(code)
            self.assertEqual(window._last_error_code, "WALLET_BROADCAST_REJECTED_LOCK_RETAINED")
            self.assertIn(ENGLISH, window.status.text())
        finally:
            window._poll.stop()
            window.hide()
            window.deleteLater()
            app.processEvents()


class CatalogParity(unittest.TestCase):
    def test_all_six_locales_carry_the_neutral_attempt_copy(self):
        from wam_regtest.presentation.strings import CATALOG
        for language in LANGUAGES:
            with self.subTest(language=language):
                value = CATALOG[language][KEY]
                self.assertIsInstance(value, str)
                self.assertTrue(value)
                for claim in OLD_SIGNED_CLAIMS:
                    self.assertNotIn(claim, value, (language, value))
        self.assertEqual(CATALOG["en"][KEY], ENGLISH)
        # Full key-set parity across the six shipped languages.
        en_keys = set(CATALOG["en"])
        for language in LANGUAGES[1:]:
            self.assertEqual(set(CATALOG[language]), en_keys, language)


if __name__ == "__main__":
    unittest.main()
