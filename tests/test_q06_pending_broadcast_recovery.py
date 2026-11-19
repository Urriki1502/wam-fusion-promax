"""Jeeves J-TX-01/J-TX-02: an unconfirmed broadcast must survive app restart.

The session re-identifies its single unconfirmed broadcast from anchored
'broadcast' reservations plus the encrypted 'broadcast' evidence, read-only,
so the existing exact-TXID confirmation is available again. Every ambiguity
must leave nothing pending (fail closed). No signing, resubmission, release
or mining is reachable from this path.
"""
from contextlib import contextmanager
import importlib.util
import sqlite3
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

WSP_AVAILABLE = importlib.util.find_spec("wam_sp") is not None
QT_AVAILABLE = importlib.util.find_spec("PySide6") is not None

TX_A, TX_B = "a" * 64, "b" * 64
IN_1, IN_2 = ("1" * 64, 0), ("2" * 64, 1)


def _session(rows, history=(), evidence=None, mempool=(TX_A,), uncertain=False, faulted=False):
    from wam_regtest.bip39_spend_session import Q06OwnedSpendSession
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE reservations(txid TEXT, vout INT, token TEXT, state TEXT)")
    db.execute("CREATE TABLE history(txid TEXT, height INT)")
    # OBS-01a: the authorizer-compatible store also carries blocks/coins,
    # and the scanner double reports a verified tip equal to the store tip.
    db.execute("CREATE TABLE blocks(height INTEGER PRIMARY KEY, hash TEXT, previous TEXT)")
    db.execute("CREATE TABLE coins(txid TEXT, vout INTEGER, atoms INTEGER,"
               " public_key TEXT, spent INTEGER)")
    tip = (5, "e" * 64)
    db.execute("INSERT INTO blocks VALUES (?,?,?)", (tip[0], tip[1], "d" * 64))
    db.executemany("INSERT INTO reservations VALUES (?,?,?,?)", rows)
    db.executemany("INSERT INTO history VALUES (?,?)", history)
    for txid, vout, _token, _state in rows:
        db.execute("INSERT INTO coins VALUES (?,?,?,?,NULL)",
                   (txid, vout, 100_000, "ab" * 32))

    @contextmanager
    def transaction():
        yield

    store = SimpleNamespace(db=db, transaction=transaction,
                            lock=threading.RLock(), tip=lambda: tip)
    session = object.__new__(Q06OwnedSpendSession)
    session._lock = threading.RLock()
    session._q06_uncertain = uncertain
    session.faulted = faulted
    session._q06_pending_confirm = None
    session.scanner = SimpleNamespace(store=store, ready=True, verified_tip=tip)
    calls = []
    session._read_payment_evidence = lambda token, stage: (
        calls.append((token, stage)) or (evidence or {}).get(token))
    rpc_calls = []

    def _call(method, params):
        rpc_calls.append(method)
        if method == "getblockchaininfo":
            return {"blocks": tip[0], "headers": tip[0], "initialblockdownload": False}
        if method == "getrawmempool":
            return list(mempool)
        raise AssertionError(method)

    def _rpc_call(method, params=None):
        rpc_calls.append(method)
        if method == "getbestblockhash":
            return tip[1]
        if method == "getblockcount":
            return tip[0]
        if method == "getblockhash":
            return tip[1]
        if method == "gettxout":
            return {"bestblock": tip[1], "value": 0.001,
                    "scriptPubKey": {"hex": "5120" + "ab" * 32}}
        raise AssertionError(method)

    session._rpc = lambda: SimpleNamespace(_call=_call, call=_rpc_call)
    session._calls, session._rpc_calls = calls, rpc_calls
    return session


def _body(txid, psbt_hex):
    return {"txid": txid, "signed_psbt": psbt_hex}


PSBT_INPUTS = {bytes.fromhex("01"): [IN_1], bytes.fromhex("02"): [IN_2],
               bytes.fromhex("03"): [IN_1, IN_2]}


def _decode(raw):
    return SimpleNamespace(tx=SimpleNamespace(inputs=PSBT_INPUTS[raw]))


@unittest.skipUnless(WSP_AVAILABLE, "Requires the pinned WSP source on sys.path")
class PendingBroadcastRecovery(unittest.TestCase):
    def recover(self, session):
        with patch("wam_sp.psbt.PSBT.decode", side_effect=_decode):
            return session._recover_pending_broadcast()

    def test_single_unconfirmed_broadcast_in_mempool_is_restored(self):
        s = _session([(IN_1[0], IN_1[1], "t1", "broadcast")], evidence={"t1": _body(TX_A, "01")})
        self.assertEqual(self.recover(s), TX_A)
        self.assertEqual(s._q06_pending_confirm, TX_A)
        self.assertEqual(s._calls, [("t1", "broadcast")])  # only the broadcast evidence is read
        # OBS-01a: one bracketed read-only acquisition replaces the single
        # getrawmempool read (chain info, tip, mempool endpoints, bracket).
        self.assertEqual(s._rpc_calls, ["getblockchaininfo", "getbestblockhash",
                                        "getrawmempool", "getrawmempool",
                                        "getbestblockhash", "getblockcount"])

    def test_multi_input_broadcast_matches_all_reserved_inputs(self):
        s = _session([(IN_1[0], IN_1[1], "t1", "broadcast"), (IN_2[0], IN_2[1], "t1", "broadcast")],
                     evidence={"t1": _body(TX_A, "03")})
        self.assertEqual(self.recover(s), TX_A)

    def assertNothingPending(self, session):
        self.assertIsNone(self.recover(session))
        self.assertIsNone(session._q06_pending_confirm)

    def test_no_broadcast_reservations(self):
        self.assertNothingPending(_session([(IN_1[0], IN_1[1], "t1", "signed")],
                                           evidence={"t1": _body(TX_A, "01")}))

    def test_two_unconfirmed_broadcast_tokens_are_ambiguous(self):
        self.assertNothingPending(_session(
            [(IN_1[0], IN_1[1], "t1", "broadcast"), (IN_2[0], IN_2[1], "t2", "broadcast")],
            evidence={"t1": _body(TX_A, "01"), "t2": _body(TX_B, "02")}, mempool=(TX_A, TX_B)))

    def test_missing_evidence(self):
        self.assertNothingPending(_session([(IN_1[0], IN_1[1], "t1", "broadcast")], evidence={}))

    def test_unreadable_evidence(self):
        s = _session([(IN_1[0], IN_1[1], "t1", "broadcast")])
        def broken(token, stage):
            raise ValueError("Q06_PAYMENT_EVIDENCE_INVALID")
        s._read_payment_evidence = broken
        self.assertNothingPending(s)

    def test_evidence_inputs_must_equal_reserved_inputs(self):
        self.assertNothingPending(_session([(IN_1[0], IN_1[1], "t1", "broadcast")],
                                           evidence={"t1": _body(TX_A, "02")}))

    def test_already_confirmed_is_not_pending(self):
        s = _session([(IN_1[0], IN_1[1], "t1", "broadcast")], history=((TX_A, 103),),
                     evidence={"t1": _body(TX_A, "01")})
        self.assertNothingPending(s)
        self.assertEqual(s._rpc_calls, [])

    def test_absent_from_mempool_is_not_pending(self):
        self.assertNothingPending(_session([(IN_1[0], IN_1[1], "t1", "broadcast")],
                                           evidence={"t1": _body(TX_A, "01")}, mempool=()))

    def test_faulted_or_uncertain_session_never_recovers(self):
        for flags in ({"uncertain": True}, {"faulted": True}):
            s = _session([(IN_1[0], IN_1[1], "t1", "broadcast")],
                         evidence={"t1": _body(TX_A, "01")}, **flags)
            self.assertNothingPending(s)
            self.assertEqual(s._rpc_calls, [])

    def test_existing_pending_txid_is_never_replaced(self):
        s = _session([(IN_1[0], IN_1[1], "t1", "broadcast")], evidence={"t1": _body(TX_A, "01")})
        s._q06_pending_confirm = TX_B
        self.assertIsNone(self.recover(s))
        self.assertEqual(s._q06_pending_confirm, TX_B)

    def test_confirmed_earlier_broadcast_plus_one_mempool_broadcast_restores_only_the_pending(self):
        s = _session([(IN_2[0], IN_2[1], "t0", "broadcast"), (IN_1[0], IN_1[1], "t1", "broadcast")],
                     history=((TX_B, 103),),
                     evidence={"t0": _body(TX_B, "02"), "t1": _body(TX_A, "01")})
        self.assertEqual(self.recover(s), TX_A)

    def test_unreadable_historical_evidence_suppresses_recovery(self):
        # REC-1a (PM-087) supersedes the old global suppression: the
        # unreadable token is quarantined with a typed reason and the
        # independent healthy broadcast is still recovered.
        s = _session([(IN_2[0], IN_2[1], "t0", "broadcast"), (IN_1[0], IN_1[1], "t1", "broadcast")],
                     history=((TX_B, 103),), evidence={"t1": _body(TX_A, "01")})
        def reader(token, stage):
            if token == "t0":
                raise ValueError("Q06_PAYMENT_EVIDENCE_INVALID")
            return _body(TX_A, "01")
        s._read_payment_evidence = reader
        self.assertEqual(self.recover(s), TX_A)
        self.assertEqual(s._q06_pending_confirm, TX_A)
        self.assertEqual(s._q06_rec1_quarantine, {"t0": "EVIDENCE_READ_FAILED"})
        self.assertNotEqual(s._rpc_calls, [])

    def test_malformed_mempool_reply_fails_closed(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        s = _session([(IN_1[0], IN_1[1], "t1", "broadcast")],
                     evidence={"t1": _body(TX_A, "01")}, mempool=("not-a-txid",))
        with self.assertRaises(Q06SpendSessionError):
            self.recover(s)
        self.assertIsNone(s._q06_pending_confirm)

    def test_session_open_runs_recovery_after_owned_rpc(self):
        import inspect
        from wam_regtest import bip39_spend_session as module
        code = inspect.getsource(module.open_owned_spend_session)
        self.assertLess(code.index("session._rpc()"), code.index("session._recover_pending_broadcast()"))
        self.assertLess(code.index("session._recover_pending_broadcast()"), code.index("transferred = True"))


@unittest.skipUnless(QT_AVAILABLE, "Requires native Qt-capable runner")
class ReopenedWindowShowsPendingBroadcast(unittest.TestCase):
    def test_snapshot_with_recovered_txid_restores_txid_confirm_and_status(self):
        from PySide6.QtWidgets import QApplication
        from wam_regtest.bip39_owner_gui import Bip39TrialWindow
        from wam_regtest.wallet_executor import ExecutorState, immutable
        app = QApplication.instance() or QApplication([])
        class Owner:
            state = ExecutorState(locked=False, core_alive=True)
            busy = False
            closed = False
        window = Bip39TrialWindow(Owner())
        try:
            window._ready = window._spend_enabled = True
            self.assertEqual(window.last_txid.text(), "")
            window._on_ready("snapshot", immutable({
                "signer_allowed": True, "broadcast_allowed": True,
                "mainnet_allowed": False, "receive_code": "wamrtsp1public",
                "confirmed_atoms": 5, "available_atoms": 0, "height": 102,
                "tip": "a" * 64, "history": (), "reservation_count": 1,
                "payment_review": None, "payment_signed": False,
                "pending_confirm_txid": TX_A,
            }))
            self.assertEqual(window._pending_confirm_txid, TX_A)
            self.assertEqual(window.last_txid.text(), TX_A)
            self.assertIn(TX_A, window.status.text())
            self.assertIn("do not send this payment again", window.status.text())
            self.assertTrue(window.confirm.isEnabled())
        finally:
            window._poll.stop()
            window.hide()
            window.deleteLater()
            app.processEvents()


    def test_reopened_fusion_window_shows_recovered_payment_without_auto_inspect(self):
        from PySide6.QtWidgets import QApplication
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.wallet_executor import ExecutorState, immutable
        app = QApplication.instance() or QApplication([])
        class Owner:
            state = ExecutorState(locked=False, core_alive=True)
            busy = False
            closed = False
        window = Bip39FusionWindow(Owner())
        try:
            window._ready = window._spend_enabled = True
            self.assertFalse(window._broadcast_complete)
            window._on_ready("snapshot", immutable({
                "signer_allowed": True, "broadcast_allowed": True,
                "mainnet_allowed": False, "receive_code": "wamrtsp1public",
                "confirmed_atoms": 5, "available_atoms": 0, "height": 102,
                "tip": "a" * 64, "history": (), "reservation_count": 1,
                "payment_review": None, "payment_signed": False,
                "pending_confirm_txid": TX_A,
            }))
            self.assertEqual(window.last_txid.text(), TX_A)
            self.assertIn(TX_A, window.send_result.text())
            self.assertIn("Confirmation is pending", window.send_result.text())
            self.assertIsNone(window._pending_action)  # no automatic inspect on reopen
            self.assertTrue(window.confirm.isEnabled())
        finally:
            window._poll.stop()
            window.hide()
            window.deleteLater()
            app.processEvents()


    def test_send_page_says_confirmed_only_after_the_exact_verified_confirm(self):
        from PySide6.QtWidgets import QApplication
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.wallet_executor import ExecutorState, immutable
        app = QApplication.instance() or QApplication([])
        class Owner:
            state = ExecutorState(locked=False, core_alive=True)
            busy = False
            closed = False
        for confirmed_txid, expect_confirmed in ((TX_A, True), (TX_B, False)):
            window = Bip39FusionWindow(Owner())
            try:
                window._ready = window._spend_enabled = True
                window._on_ready("broadcast", TX_A)
                window._on_ready("inspect_confirmed", immutable({
                    "status": "Q06_TX_NOT_IN_CONFIRMED_HISTORY", "in_mempool": True, "txid": TX_A}))
                self.assertIn("pending", window.send_result.text())
                window._on_ready("confirm", immutable({
                    "status": "Q06_REGTEST_EXACT_SEND_CONFIRMED", "height": 103,
                    "txid": confirmed_txid, "mainnet_allowed": False}))
                text = window.send_result.text()
                if expect_confirmed:
                    self.assertTrue(text.startswith("Confirmed on this REGTEST chain."), text)
                    self.assertIn(TX_A, text)
                else:  # identity mismatch: never claim confirmation
                    self.assertNotIn("Confirmed", text)
                    self.assertEqual(window._pending_confirm_txid, TX_A)
            finally:
                window._poll.stop()
                window.hide()
                window.deleteLater()
                app.processEvents()


if __name__ == "__main__":
    unittest.main()
