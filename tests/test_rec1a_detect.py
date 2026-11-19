"""PM-087 REC-1a (UAT): read-only detection, per-token isolation, typed keys.

One corrupted token must quarantine only itself and every token linked to
it through a shared/dependent input. Independent healthy tokens continue
to be classified and, for pending-broadcast recovery, the single healthy
in-mempool broadcast is still recovered. Profile-level custody/owner
failures stay global. No path here may call a write RPC, release a
reservation, re-sign, or report a not-observed token as gone/eligible.
"""
from contextlib import contextmanager
import importlib.util
import sqlite3
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

WSP_AVAILABLE = importlib.util.find_spec("wam_sp") is not None

TX_A, TX_B, TX_C = "a" * 64, "b" * 64, "c" * 64
IN_1, IN_2 = ("1" * 64, 0), ("2" * 64, 1)
IN_3, IN_4 = ("3" * 64, 0), ("4" * 64, 0)
TIP = (5, "e" * 64)
READ_ONLY_RPC = {"getblockchaininfo", "getbestblockhash", "getblockcount",
                 "getblockhash", "getrawmempool", "gettxout"}

PSBT_INPUTS = {b"\x01": [IN_1], b"\x02": [IN_2], b"\x03": [IN_1, IN_2],
               b"\x04": [IN_3], b"\x05": [IN_4], b"\x06": [IN_3, IN_4]}


def _decode(raw):
    return SimpleNamespace(tx=SimpleNamespace(inputs=PSBT_INPUTS[raw]))


def _body(txid, key, **extra):
    body = {"txid": txid, "signed_psbt": key.hex(), "recipient": "wamrtsp1public",
            "atoms": 50_000, "fee": 1000, "commitment": "f" * 64}
    body.update(extra)
    return body


def _session(rows, history=(), evidence=None, mempool=(), spent=None,
             txout_none=(), drop_coins=()):
    from wam_regtest.bip39_spend_session import Q06OwnedSpendSession
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE reservations(txid TEXT, vout INT, token TEXT, state TEXT)")
    db.execute("CREATE TABLE history(txid TEXT, height INT)")
    db.execute("CREATE TABLE blocks(height INTEGER PRIMARY KEY, hash TEXT, previous TEXT)")
    db.execute("CREATE TABLE coins(txid TEXT, vout INTEGER, atoms INTEGER,"
               " public_key TEXT, spent INTEGER)")
    db.execute("INSERT INTO blocks VALUES (?,?,?)", (TIP[0], TIP[1], "d" * 64))
    db.executemany("INSERT INTO reservations VALUES (?,?,?,?)", rows)
    db.executemany("INSERT INTO history VALUES (?,?)", history)
    spent = spent or {}
    for txid, vout, _token, _state in rows:
        if (txid, vout) in drop_coins:
            continue
        db.execute("INSERT INTO coins VALUES (?,?,?,?,?)",
                   (txid, vout, 100_000, "ab" * 32, spent.get((txid, vout))))

    @contextmanager
    def transaction():
        yield

    store = SimpleNamespace(db=db, transaction=transaction,
                            lock=threading.RLock(), tip=lambda: TIP)
    session = object.__new__(Q06OwnedSpendSession)
    session._lock = threading.RLock()
    session._q06_uncertain = False
    session.faulted = False
    session._q06_pending_confirm = None
    session.scanner = SimpleNamespace(store=store, ready=True, verified_tip=TIP)
    session.snapshot = lambda *a, **k: SimpleNamespace(height=TIP[0], tip=TIP)
    evidence = evidence or {}

    def read(token, stage):
        value = evidence.get(token)
        if isinstance(value, BaseException):
            raise value
        return value

    session._read_payment_evidence = read
    rpc_calls = []

    def _call(method, params):
        rpc_calls.append(method)
        if method == "getblockchaininfo":
            return {"blocks": TIP[0], "headers": TIP[0], "initialblockdownload": False}
        if method == "getrawmempool":
            return list(mempool)
        raise AssertionError("write-or-unknown RPC in REC-1a: " + method)

    def call(method, params=None):
        rpc_calls.append(method)
        if method == "getbestblockhash":
            return TIP[1]
        if method == "getblockcount":
            return TIP[0]
        if method == "getblockhash":
            return TIP[1]
        if method == "gettxout":
            if (params[0], params[1]) in txout_none:
                return None
            return {"bestblock": TIP[1], "value": 0.001,
                    "scriptPubKey": {"hex": "5120" + "ab" * 32}}
        raise AssertionError("write-or-unknown RPC in REC-1a: " + method)

    session._rpc = lambda: SimpleNamespace(_call=_call, call=call)
    session._rpc_calls = rpc_calls
    session._rows = lambda: db.execute(
        "SELECT txid,vout,token,state FROM reservations ORDER BY token,txid,vout").fetchall()
    return session


def _quarantine(session):
    return getattr(session, "_q06_rec1_quarantine", None)


@unittest.skipUnless(WSP_AVAILABLE, "Requires the pinned WSP source on sys.path")
class RecoverPerTokenIsolation(unittest.TestCase):
    def recover(self, session):
        with patch("wam_sp.psbt.PSBT.decode", side_effect=_decode):
            return session._recover_pending_broadcast()

    def test_corrupted_token_quarantined_healthy_token_still_recovered(self):
        s = _session(
            [(IN_1[0], IN_1[1], "tbad", "broadcast"),
             (IN_3[0], IN_3[1], "tgood", "broadcast")],
            evidence={"tbad": ValueError("Q06_PAYMENT_EVIDENCE_INVALID"),
                      "tgood": _body(TX_C, b"\x04")}, mempool=(TX_C,))
        before = s._rows()
        self.assertEqual(self.recover(s), TX_C)
        self.assertEqual(s._q06_pending_confirm, TX_C)
        self.assertEqual(_quarantine(s), {"tbad": "EVIDENCE_READ_FAILED"})
        self.assertEqual(s._rows(), before)  # reservations kept, evidence untouched
        self.assertLessEqual(set(s._rpc_calls), READ_ONLY_RPC)
        self.assertNotIn("sendrawtransaction", s._rpc_calls)

    def test_input_mismatch_quarantines_only_the_affected_token(self):
        s = _session(
            [(IN_1[0], IN_1[1], "tbad", "broadcast"),
             (IN_3[0], IN_3[1], "tgood", "broadcast")],
            evidence={"tbad": _body(TX_A, b"\x02"),
                      "tgood": _body(TX_C, b"\x04")}, mempool=(TX_C,))
        self.assertEqual(self.recover(s), TX_C)
        self.assertEqual(_quarantine(s), {"tbad": "EVIDENCE_INPUT_MISMATCH"})

    def test_linked_dependent_tokens_are_quarantined_together(self):
        s = _session(
            [(IN_1[0], IN_1[1], "tbad", "broadcast"),
             (IN_1[0], IN_1[1], "tdep", "broadcast"),
             (IN_2[0], IN_2[1], "tdep", "broadcast"),
             (IN_3[0], IN_3[1], "tgood", "broadcast")],
            evidence={"tbad": ValueError("Q06_PAYMENT_EVIDENCE_INVALID"),
                      "tdep": _body(TX_B, b"\x03"),
                      "tgood": _body(TX_C, b"\x04")}, mempool=(TX_B, TX_C))
        before = s._rows()
        self.assertEqual(self.recover(s), TX_C)  # tdep is never recovered
        self.assertEqual(set(_quarantine(s)), {"tbad", "tdep"})
        self.assertEqual(_quarantine(s)["tdep"], "LINKED_TO_CORRUPTED_EVIDENCE")
        self.assertEqual(s._rows(), before)

    def test_missing_evidence_quarantines_and_recovers_nothing(self):
        s = _session([(IN_1[0], IN_1[1], "t1", "broadcast")], evidence={})
        self.assertIsNone(self.recover(s))
        self.assertIsNone(s._q06_pending_confirm)
        self.assertEqual(_quarantine(s), {"t1": "EVIDENCE_MISSING"})

    def test_profile_level_custody_failure_stays_global(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        s = _session(
            [(IN_1[0], IN_1[1], "tbad", "broadcast"),
             (IN_3[0], IN_3[1], "tgood", "broadcast")],
            evidence={"tbad": Q06SpendSessionError("Q06_SPEND_OPEN_DENIED"),
                      "tgood": _body(TX_C, b"\x04")}, mempool=(TX_C,))
        with self.assertRaises(Q06SpendSessionError):
            self.recover(s)
        self.assertIsNone(s._q06_pending_confirm)


@unittest.skipUnless(WSP_AVAILABLE, "Requires the pinned WSP source on sys.path")
class IntentRec1Classification(unittest.TestCase):
    def status(self, session):
        with patch("wam_sp.psbt.PSBT.decode", side_effect=_decode):
            return session.signed_intent_status()

    def item(self, session, token="t1"):
        result = self.status(session)
        return result, next(i for i in result["intents"] if i["token"] == token)

    def test_confirmed_from_verified_history(self):
        s = _session([(IN_1[0], IN_1[1], "t1", "uncertain")],
                     history=((TX_A, TIP[0]),),
                     evidence={"t1": _body(TX_A, b"\x01")}, spent={IN_1: TIP[0]})
        _result, item = self.item(s)
        self.assertEqual(item["classification"], "CONFIRMED_IN_VERIFIED_HISTORY")
        self.assertEqual(item["rec1_state"], "CONFIRMED")
        self.assertIs(item["quarantined"], False)

    def test_in_local_mempool(self):
        s = _session([(IN_1[0], IN_1[1], "t1", "uncertain")],
                     evidence={"t1": _body(TX_A, b"\x01")}, mempool=(TX_A,))
        _result, item = self.item(s)
        self.assertEqual(item["rec1_state"], "IN_LOCAL_MEMPOOL")
        self.assertEqual(item["classification"], "IN_MEMPOOL_AWAITING_CONFIRMATION")

    def test_not_observed_locally_is_unresolved_never_gone_or_eligible(self):
        s = _session([(IN_1[0], IN_1[1], "t1", "uncertain")],
                     evidence={"t1": _body(TX_A, b"\x01")}, mempool=())
        before = s._rows()
        result, item = self.item(s)
        self.assertEqual(item["rec1_state"], "NOT_OBSERVED_LOCALLY")
        self.assertEqual(item["rec1_reason"], "REBROADCAST_DEFERRED")
        self.assertEqual(item["classification"], "UNCERTAIN_NOT_OBSERVED_RESUMABLE")
        self.assertEqual(s._rows(), before)  # reservation never released
        self.assertIs(result["write_attempted"], False)
        text = str(result)
        self.assertNotIn("ELIGIBLE_FOR_MANUAL_REBROADCAST", text)
        self.assertNotIn("REBROADCAST_ATTEMPT_CONSUMED", text)
        self.assertNotIn("gone", text.lower())
        self.assertLessEqual(set(s._rpc_calls), READ_ONLY_RPC)

    def test_conflicted_from_block_and_input_unavailable_observations(self):
        block = _session([(IN_1[0], IN_1[1], "t1", "uncertain")],
                         evidence={"t1": _body(TX_A, b"\x01")}, spent={IN_1: TIP[0]})
        _r, item = self.item(block)
        self.assertEqual(item["rec1_state"], "CONFLICTED")
        self.assertEqual(item["observation"]["state"], "BLOCK_CONFLICTED")
        unavailable = _session([(IN_1[0], IN_1[1], "t1", "uncertain")],
                               evidence={"t1": _body(TX_A, b"\x01")},
                               txout_none={IN_1})
        _r, item = self.item(unavailable)
        self.assertEqual(item["rec1_state"], "CONFLICTED")
        self.assertEqual(item["observation"]["state"], "INPUT_UNAVAILABLE")

    def test_rejected_by_policy_only_from_a_recorded_typed_rejection(self):
        s = _session([(IN_1[0], IN_1[1], "t1", "uncertain")],
                     evidence={"t1": _body(TX_A, b"\x01",
                                           preflight_rejection="DUST_REJECTED")})
        _r, item = self.item(s)
        self.assertEqual(item["rec1_state"], "REJECTED_BY_POLICY")
        self.assertEqual(item["rec1_reason"], "DUST_REJECTED")

    def test_broadcast_outcome_uncertain_from_unknown_observation(self):
        s = _session([(IN_1[0], IN_1[1], "t1", "uncertain")],
                     evidence={"t1": _body(TX_A, b"\x01")}, drop_coins={IN_1})
        _r, item = self.item(s)
        self.assertEqual(item["rec1_state"], "BROADCAST_OUTCOME_UNCERTAIN")
        self.assertEqual(item["observation"]["state"], "UNKNOWN")

    def test_corrupted_token_quarantined_healthy_token_still_classified(self):
        s = _session(
            [(IN_1[0], IN_1[1], "tbad", "signed"),
             (IN_3[0], IN_3[1], "tgood", "signed")],
            evidence={"tbad": ValueError("Q06_PAYMENT_EVIDENCE_INVALID"),
                      "tgood": _body(TX_C, b"\x04")}, mempool=(TX_C,))
        before = s._rows()
        result = self.status(s)
        items = {i["token"]: i for i in result["intents"]}
        self.assertEqual(items["tbad"]["rec1_state"], "CORRUPTED_EVIDENCE")
        self.assertIs(items["tbad"]["quarantined"], True)
        self.assertEqual(items["tbad"]["rec1_reason"], "EVIDENCE_READ_FAILED")
        self.assertEqual(items["tgood"]["rec1_state"], "IN_LOCAL_MEMPOOL")
        self.assertIs(items["tgood"]["quarantined"], False)
        self.assertEqual(s._rows(), before)
        self.assertLessEqual(set(s._rpc_calls), READ_ONLY_RPC)
        self.assertNotIn("sendrawtransaction", s._rpc_calls)

    def test_linked_token_in_status_is_quarantined_and_never_resumable(self):
        s = _session(
            [(IN_1[0], IN_1[1], "tbad", "signed"),
             (IN_1[0], IN_1[1], "tdep", "signed"),
             (IN_2[0], IN_2[1], "tdep", "signed")],
            evidence={"tbad": ValueError("Q06_PAYMENT_EVIDENCE_INVALID"),
                      "tdep": _body(TX_B, b"\x03")}, mempool=(TX_B,))
        result = self.status(s)
        items = {i["token"]: i for i in result["intents"]}
        self.assertEqual(items["tdep"]["rec1_state"], "CORRUPTED_EVIDENCE")
        self.assertIs(items["tdep"]["quarantined"], True)
        self.assertEqual(items["tdep"]["rec1_reason"], "LINKED_TO_CORRUPTED_EVIDENCE")
        self.assertNotIn("RESUMABLE", items["tdep"]["classification"])
        self.assertIsNone(items["tdep"]["observation"])


class TypedPreflightKeys(unittest.TestCase):
    def test_typed_keys_for_already_in_chain_and_dust_only(self):
        from wam_regtest.preflight import typed_preflight_key, verify_preflight_typed
        self.assertEqual(typed_preflight_key("txn-already-in-chain"), "ALREADY_IN_CHAIN")
        self.assertEqual(typed_preflight_key("dust"), "DUST_REJECTED")
        self.assertEqual(typed_preflight_key("txn-already-in-mempool"), "ALREADY_IN_MEMPOOL")
        self.assertEqual(typed_preflight_key("min relay fee not met"), "FEE_POLICY_REJECTED")
        self.assertEqual(typed_preflight_key("non-final"), "POLICY_REJECTED")
        self.assertEqual(typed_preflight_key("unknown private reason"), "POLICY_REJECTED")
        self.assertEqual(typed_preflight_key(None), "POLICY_REJECTED")
        for reason, key in (("dust", "DUST_REJECTED"),
                            ("txn-already-in-chain", "ALREADY_IN_CHAIN")):
            self.assertEqual(
                verify_preflight_typed([{"allowed": False, "reject-reason": reason}],
                                       txid=None, wtxid=None, vsize=None, fee_atoms=None),
                key)

    def test_shared_domain_preflight_contract_is_unchanged(self):
        from wam_regtest.domain.preflight import PREFLIGHT_REJECT_REASONS, verify_preflight
        self.assertNotIn("dust", PREFLIGHT_REJECT_REASONS)
        self.assertNotIn("txn-already-in-chain", PREFLIGHT_REJECT_REASONS)
        self.assertEqual(
            verify_preflight([{"allowed": False, "reject-reason": "dust"}],
                             txid=None, wtxid=None, vsize=None, fee_atoms=None),
            "POLICY_REJECTED")

    def test_rec1_state_vocabulary_has_no_deferred_rebroadcast_states(self):
        from wam_regtest.domain.payment_state import REC1_STATES
        self.assertEqual(REC1_STATES, frozenset((
            "CONFIRMED", "IN_LOCAL_MEMPOOL", "NOT_OBSERVED_LOCALLY", "CONFLICTED",
            "REJECTED_BY_POLICY", "BROADCAST_OUTCOME_UNCERTAIN", "CORRUPTED_EVIDENCE")))
        self.assertNotIn("ELIGIBLE_FOR_MANUAL_REBROADCAST", REC1_STATES)
        self.assertNotIn("REBROADCAST_ATTEMPT_CONSUMED", REC1_STATES)


if __name__ == "__main__":
    unittest.main()

