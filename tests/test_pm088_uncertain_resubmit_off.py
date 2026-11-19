"""PM-088 REC-2 (owner UAT policy): 'uncertain' intents are never re-submitted.

Recording fakes only (no Core, no native storage): an 'uncertain', mixed or
otherwise ambiguous intent is refused at session, backend and executor level
with WalletSessionError('REC2_UNCERTAIN_RESUBMIT_DEFERRED') and zero RPC,
zero vault saves and zero evidence writes. A provably 'signed' intent with
no 'uncertain' write-ahead ever recorded still resumes exactly as before.
Status stays read-only and keeps uncertain intents visible.
"""
from contextlib import contextmanager, nullcontext
import inspect
import sqlite3
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

TOKEN = "a" * 32
TXID = "b" * 64
IN_1, IN_2 = ("1" * 64, 0), ("2" * 64, 1)
TIP = (1, "e" * 64)
REC2 = "REC2_UNCERTAIN_RESUBMIT_DEFERRED"


def _body(**extra):
    body = {"txid": TXID, "signed_psbt": "01", "recipient": "wamrtsp1public",
            "atoms": 50_000, "fee": 1000, "commitment": "f" * 64,
            "fee_basis": {"kind": "legacy-unrecorded"}}
    body.update(extra)
    return body


class _Evidence:
    def __init__(self, values=None):
        self.values, self.writes, self.reads = values or {}, [], []

    def read(self, token, stage, **_kwargs):
        self.reads.append((token, stage))
        value = self.values.get((token, stage))
        if isinstance(value, BaseException):
            raise value
        return value

    def write(self, stage, **kwargs):
        self.writes.append((stage, kwargs.get("token"), kwargs.get("txid")))


class _Rpc:
    def __init__(self):
        self.calls = []

    def call(self, method, params=None):
        self.calls.append(method)
        raise AssertionError("RPC in a refused/read-only path: " + method)

    def _call(self, method, params):
        self.calls.append(method)
        raise AssertionError("RPC in a refused/read-only path: " + method)


class _Vault:
    def __init__(self):
        self.saves = []
        self.anchor = SimpleNamespace(lease=lambda: nullcontext(),
                                      read=lambda: (1, "a" * 64))
        self._expected = (1, "a" * 64)

    def save(self, keys, scanner, password):
        self.saves.append(True)


class _SelectFailingDB:
    """Delegate to a real connection and fail the REC-2 reservation SELECT."""

    def __init__(self, db, error):
        self._db = db
        self._error = error

    def execute(self, sql, parameters=()):
        if isinstance(sql, str) and sql.strip().startswith(
                "SELECT state FROM reservations WHERE token"):
            raise self._error
        return self._db.execute(sql, parameters)

    def __getattr__(self, name):
        return getattr(self._db, name)


def _session(rows, evidence=None, *, faulted=False, session_uncertain=False,
             locked=False):
    from wam_regtest.bip39_spend_session import Q06OwnedSpendSession
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE reservations(txid TEXT, vout INT, token TEXT,"
               " state TEXT, created INT)")
    db.execute("CREATE TABLE history(txid TEXT, height INT)")
    db.executemany("INSERT INTO reservations VALUES (?,?,?,?,0)", rows)

    @contextmanager
    def transaction():
        yield

    store = SimpleNamespace(db=db, transaction=transaction,
                            lock=threading.RLock(), tip=lambda: TIP)
    session = object.__new__(Q06OwnedSpendSession)
    session._lock = threading.RLock()
    session._q06_uncertain = session_uncertain
    session.faulted = faulted
    session._prepared = session._signed = session._review = None
    session._q06_pending_confirm = None
    session.ring = None if locked else SimpleNamespace(
        public_metadata=lambda: {"account_id": "acct"})
    session.scanner = SimpleNamespace(store=store)
    session.vault = _Vault()
    session._password = b"pm088 disposable password"
    session._q06_owner = SimpleNamespace(directory=None)
    session._q06_guard = SimpleNamespace(check=lambda: None)
    session._evidence_fake = _Evidence(evidence)
    session._evidence_store = lambda: session._evidence_fake
    session._rpc_fake = _Rpc()
    session._rpc = lambda: session._rpc_fake
    session.snapshot = lambda *a, **k: SimpleNamespace(height=1, tip=TIP[1])
    session._rows = lambda: db.execute(
        "SELECT txid,vout,token,state FROM reservations"
        " ORDER BY token,txid,vout").fetchall()
    return session


def _decode(_raw):
    return SimpleNamespace(
        txid=lambda: TXID,
        tx=SimpleNamespace(inputs=[IN_1], sequence_values=lambda: (0,)))


def _observe(_scanner, _rpc, intents):
    return {txid: {"state": "NOT_SEEN_LOCALLY", "height": 1,
                   "block_hash": TIP[1], "conflict_heights": [],
                   "depth": 0, "core_ibd": False} for txid in intents}


class _Patched(unittest.TestCase):
    def setUp(self):
        for target, fake in (
                ("wam_regtest.bip39_spend_session._owned", lambda _o: None),
                ("wam_regtest.bip39_spend_session._owner_binding",
                 lambda _o=None: "binding"),
                ("wam_sp.psbt.PSBT.decode", _decode),
                ("wam_regtest.tx_observation.observe_intents", _observe),
                ("wam_regtest.bip39_spend_session._verify_session_preflight",
                 lambda _rpc, _signed, _review: None)):
            p = patch(target, fake)
            p.start()
            self.addCleanup(p.stop)


class SessionRefusal(_Patched):
    def assertRefused(self, session):
        from wam_regtest.wallet_session import WalletSessionError
        before = session._rows()
        with self.assertRaises(WalletSessionError) as caught:
            session.resume_signed_intent(TOKEN, TXID, approved=True)
        self.assertEqual(caught.exception.args, (REC2,))
        self.assertEqual(session._rpc_fake.calls, [])       # zero RPC
        self.assertEqual(session.vault.saves, [])           # zero saves
        self.assertEqual(session._evidence_fake.writes, [])  # zero writes
        self.assertEqual(session._rows(), before)            # state kept
        self.assertIsNone(session._q06_pending_confirm)

    def test_uncertain_resume_refused_before_any_rpc_or_write(self):
        session = _session([(IN_1[0], IN_1[1], TOKEN, "uncertain")],
                           {(TOKEN, "signed"): _body()})
        self.assertRefused(session)
        self.assertFalse(session.faulted or session._q06_uncertain)

    def test_mixed_reservation_states_refused(self):
        for rows in (
                [(IN_1[0], IN_1[1], TOKEN, "signed"),
                 (IN_2[0], IN_2[1], TOKEN, "uncertain")],
                [(IN_1[0], IN_1[1], TOKEN, "signed"),
                 (IN_2[0], IN_2[1], TOKEN, "broadcast")],
                [(IN_1[0], IN_1[1], TOKEN, "signed"),
                 (IN_2[0], IN_2[1], TOKEN, "draft")],
                [(IN_1[0], IN_1[1], TOKEN, "manual")],
        ):
            with self.subTest(states=[r[3] for r in rows]):
                session = _session(rows, {(TOKEN, "signed"): _body()})
                self.assertRefused(session)

    def test_missing_rows_with_uncertain_evidence_refused(self):
        session = _session([], {(TOKEN, "uncertain"): _body()})
        self.assertRefused(session)

    def test_signed_rows_with_uncertain_write_ahead_refused(self):
        # Signed rows alone do not prove "never submitted": the durable
        # 'uncertain' write-ahead was already recorded for this token.
        session = _session([(IN_1[0], IN_1[1], TOKEN, "signed")],
                           {(TOKEN, "signed"): _body(),
                            (TOKEN, "uncertain"): _body()})
        self.assertRefused(session)

    def test_signed_rows_with_broadcast_evidence_refused(self):
        session = _session([(IN_1[0], IN_1[1], TOKEN, "signed")],
                           {(TOKEN, "signed"): _body(),
                            (TOKEN, "broadcast"): _body()})
        self.assertRefused(session)

    def test_corrupt_uncertain_or_broadcast_write_ahead_fails_closed(self):
        for stage in ("uncertain", "broadcast"):
            with self.subTest(stage=stage):
                session = _session([(IN_1[0], IN_1[1], TOKEN, "signed")],
                                   {(TOKEN, "signed"): _body(),
                                    (TOKEN, stage): ValueError("invalid")})
                self.assertRefused(session)

    def test_custody_failure_reading_write_ahead_propagates_global(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        session = _session([(IN_1[0], IN_1[1], TOKEN, "signed")],
                           {(TOKEN, "signed"): _body(),
                            (TOKEN, "uncertain"): Q06SpendSessionError("Q06_SPEND_CUSTODY_DENIED")})
        with self.assertRaises(Q06SpendSessionError) as caught:
            session.resume_signed_intent(TOKEN, TXID, approved=True)
        self.assertEqual(caught.exception.args, ("Q06_SPEND_CUSTODY_DENIED",))
        self.assertEqual(session._rpc_fake.calls, [])
        self.assertEqual(session.vault.saves, [])
        self.assertEqual(session._evidence_fake.writes, [])

    def test_reservation_read_sqlite_failure_is_rec2_before_any_rpc(self):
        from wam_regtest.wallet_session import WalletSessionError
        for error in (sqlite3.OperationalError("injected-read"),
                      sqlite3.DatabaseError("injected-db")):
            with self.subTest(error=type(error).__name__):
                session = _session([(IN_1[0], IN_1[1], TOKEN, "signed")],
                                   {(TOKEN, "signed"): _body()})
                before = session._rows()
                original = session.scanner.store.db
                session.scanner.store.db = _SelectFailingDB(original, error)
                try:
                    with self.assertRaises(WalletSessionError) as caught:
                        session.resume_signed_intent(TOKEN, TXID, approved=True)
                finally:
                    session.scanner.store.db = original
                self.assertEqual(caught.exception.args, (REC2,))
                self.assertEqual(session._rpc_fake.calls, [])
                self.assertEqual(session.vault.saves, [])
                self.assertEqual(session._evidence_fake.writes, [])
                self.assertEqual(session._rows(), before)
                self.assertIsNone(session._q06_pending_confirm)
                self.assertFalse(session.faulted or session._q06_uncertain)

    def test_reservation_read_storage_failure_is_rec2_before_any_rpc(self):
        from wam_regtest.wallet_session import WalletSessionError
        from wam_sp.errors import StorageError
        session = _session([(IN_1[0], IN_1[1], TOKEN, "signed")],
                           {(TOKEN, "signed"): _body()})
        before = session._rows()
        original = session.scanner.store.db
        session.scanner.store.db = _SelectFailingDB(
            original, StorageError("DATABASE_CORRUPTION"))
        try:
            with self.assertRaises(WalletSessionError) as caught:
                session.resume_signed_intent(TOKEN, TXID, approved=True)
        finally:
            session.scanner.store.db = original
        self.assertEqual(caught.exception.args, (REC2,))
        self.assertEqual(session._rpc_fake.calls, [])
        self.assertEqual(session.vault.saves, [])
        self.assertEqual(session._evidence_fake.writes, [])
        self.assertEqual(session._rows(), before)
        self.assertIsNone(session._q06_pending_confirm)

    def test_reservation_read_typed_wam_error_propagates_unchanged(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        from wam_regtest.sqlite_flush import SqliteFlushUnconfigured
        from wam_regtest.wallet_session import WalletSessionError
        cases = (
            (WalletSessionError("WALLET_TYPED_RESERVATION_TOKEN"),
             WalletSessionError, ("WALLET_TYPED_RESERVATION_TOKEN",)),
            (Q06SpendSessionError("Q06_TYPED_RESERVATION_TOKEN"),
             Q06SpendSessionError, ("Q06_TYPED_RESERVATION_TOKEN",)),
            (SqliteFlushUnconfigured(), SqliteFlushUnconfigured,
             ("SQLITE_FLUSH_UNCONFIGURED",)),
        )
        for error, error_type, expected_args in cases:
            with self.subTest(error_type=error_type.__name__):
                session = _session([(IN_1[0], IN_1[1], TOKEN, "signed")],
                                   {(TOKEN, "signed"): _body()})
                before = session._rows()
                original = session.scanner.store.db
                session.scanner.store.db = _SelectFailingDB(original, error)
                try:
                    with self.assertRaises(error_type) as caught:
                        session.resume_signed_intent(TOKEN, TXID, approved=True)
                finally:
                    session.scanner.store.db = original
                # Same token, not replaced by the REC-2 token.
                self.assertEqual(caught.exception.args, expected_args)
                self.assertNotEqual(caught.exception.args, (REC2,))
                if error_type is SqliteFlushUnconfigured:
                    self.assertIs(type(caught.exception), SqliteFlushUnconfigured)
                self.assertEqual(session._rpc_fake.calls, [])
                self.assertEqual(session.vault.saves, [])
                self.assertEqual(session._evidence_fake.writes, [])
                self.assertEqual(session._rows(), before)

    def test_locked_and_faulted_sessions_refused_without_rpc(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        for session in (_session([(IN_1[0], IN_1[1], TOKEN, "uncertain")],
                                 {(TOKEN, "signed"): _body()}, locked=True),
                        _session([(IN_1[0], IN_1[1], TOKEN, "signed")],
                                 {(TOKEN, "signed"): _body()}, faulted=True),
                        _session([(IN_1[0], IN_1[1], TOKEN, "signed")],
                                 {(TOKEN, "signed"): _body()},
                                 session_uncertain=True)):
            with self.assertRaises(Q06SpendSessionError) as caught:
                session.resume_signed_intent(TOKEN, TXID, approved=True)
            self.assertEqual(caught.exception.args,
                             ("Q06_RESUME_SESSION_NOT_IDLE",))
            self.assertEqual(session._rpc_fake.calls, [])
            self.assertEqual(session.vault.saves, [])
            self.assertEqual(session._evidence_fake.writes, [])

    def test_uncertain_resume_still_requires_explicit_approval_first(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        session = _session([(IN_1[0], IN_1[1], TOKEN, "uncertain")],
                           {(TOKEN, "signed"): _body()})
        with self.assertRaises(Q06SpendSessionError) as caught:
            session.resume_signed_intent(TOKEN, TXID)
        self.assertEqual(caught.exception.args,
                         ("Q06_RESUME_EXPLICIT_APPROVAL_REQUIRED",))
        self.assertEqual(session._rpc_fake.calls, [])

    def test_unknown_token_keeps_not_eligible_not_rec2(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        session = _session([(IN_1[0], IN_1[1], TOKEN, "signed")],
                           {(TOKEN, "signed"): _body()})
        with self.assertRaises(Q06SpendSessionError) as caught:
            session.resume_signed_intent("c" * 32, TXID, approved=True)
        self.assertEqual(caught.exception.args, ("Q06_RESUME_NOT_ELIGIBLE",))

    def test_status_keeps_uncertain_visible_and_read_only(self):
        session = _session([(IN_1[0], IN_1[1], TOKEN, "uncertain")],
                           {(TOKEN, "signed"): _body()})
        before = session._rows()
        result = session.signed_intent_status()
        [item] = result["intents"]
        self.assertEqual(item["classification"],
                         "UNCERTAIN_NOT_OBSERVED_RESUMABLE")
        self.assertEqual(item["state"], "uncertain")
        self.assertEqual(item["rec1_state"], "NOT_OBSERVED_LOCALLY")
        self.assertEqual(item["rec1_reason"], "REBROADCAST_DEFERRED")
        self.assertFalse(item["quarantined"])
        self.assertFalse(result["write_attempted"] or result["automatic_resume"])
        self.assertEqual(session._rows(), before)
        self.assertEqual(session.vault.saves, [])
        self.assertEqual(session._evidence_fake.writes, [])


class SignedResumeStillWorks(_Patched):
    def test_signed_never_submitted_resumes_exactly_as_before(self):
        session = _session([(IN_1[0], IN_1[1], TOKEN, "signed")],
                           {(TOKEN, "signed"): _body()})
        sent = []

        class _Wallet:
            def __init__(self, _scanner):
                pass

            def broadcast(self, signed, token, _rpc):
                sent.append((signed, token))
                with session.scanner.store.transaction():
                    session.scanner.store.db.execute(
                        "UPDATE reservations SET state='broadcast' WHERE token=?",
                        (token,))
                return TXID

        with patch("wam_sp.wallet.Wallet", _Wallet):
            result = session.resume_signed_intent(TOKEN, TXID, approved=True)
        self.assertEqual(result, {"status": "Q06_SIGNED_INTENT_RESUBMITTED",
                                  "txid": TXID, "resigned": False,
                                  "automatic": False, "mainnet_allowed": False})
        self.assertEqual(sent, [(b"\x01", TOKEN)])  # exact stored bytes, once
        self.assertEqual([w[0] for w in session._evidence_fake.writes],
                         ["uncertain", "broadcast"])  # write-ahead, then record
        self.assertEqual(len(session.vault.saves), 2)
        self.assertEqual(session._rows(), [(IN_1[0], IN_1[1], TOKEN, "broadcast")])
        self.assertEqual(session._q06_pending_confirm, TXID)
        self.assertFalse(session.faulted or session._q06_uncertain)


class BackendRefusal(_Patched):
    def _backend(self, session, *, control_fault=False):
        from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend
        backend = object.__new__(Bip39ReadOnlyBackend)
        backend._spend_session = session
        backend.shared_profile = None
        backend._control_fault = control_fault
        backend.owner = None
        backend._secret = None
        return backend

    def _fake_session(self, **state):
        from wam_regtest.wallet_session import WalletSessionError
        fake = SimpleNamespace(
            faulted=False, _q06_uncertain=False, locked=False,
            _core_reauthentication_required=False, calls=[])
        for key, value in state.items():
            setattr(fake, key, value)

        def resume(token, txid, *, approved=False):
            fake.calls.append((token, txid, approved))
            raise WalletSessionError(REC2)
        fake.resume_signed_intent = resume
        return fake

    def test_backend_propagates_rec2_unchanged_with_zero_rpc_or_writes(self):
        from wam_regtest.wallet_session import WalletSessionError
        session = _session([(IN_1[0], IN_1[1], TOKEN, "uncertain")],
                           {(TOKEN, "signed"): _body()})
        before = session._rows()
        backend = self._backend(session)
        with self.assertRaises(WalletSessionError) as caught:
            backend.execute("resume_intent", (TOKEN, TXID, True), {})
        self.assertEqual(caught.exception.args, (REC2,))
        self.assertEqual(session._rpc_fake.calls, [])
        self.assertEqual(session.vault.saves, [])
        self.assertEqual(session._evidence_fake.writes, [])
        self.assertEqual(session._rows(), before)

    def test_backend_locked_and_faulted_refuse_before_session(self):
        from wam_regtest.bip39_owner_backend import Q06ReadOnlyError
        with self.assertRaises(Q06ReadOnlyError):
            self._backend(None).execute("resume_intent", (TOKEN, TXID, True), {})
        for state, ctrl in (({"locked": True}, False),
                            ({"faulted": True}, False),
                            ({"_q06_uncertain": True}, False),
                            ({}, True)):
            with self.subTest(state=state, control_fault=ctrl):
                fake = self._fake_session(**state)
                with self.assertRaises(Q06ReadOnlyError):
                    self._backend(fake, control_fault=ctrl).execute(
                        "resume_intent", (TOKEN, TXID, True), {})
                self.assertEqual(fake.calls, [])


class ExecutorRefusal(_Patched):
    def _run_resume(self, failure, *, backend_factory=None):
        from wam_regtest.wallet_executor import WalletExecutor

        class _Backend:
            def execute(self, action, _args, _kwargs):
                if action == "quit":
                    return {}
                raise failure

            def public_state(self):
                return {"locked": True, "faulted": False,
                        "reauthentication_required": False, "core_alive": False}

        executor = WalletExecutor(backend_factory or _Backend)
        try:
            with self.assertRaises(Exception) as caught:
                executor.submit("resume_intent", TOKEN, TXID, True).result(timeout=30)
            return caught.exception
        finally:
            executor.submit("quit").result(timeout=30)
            executor.join(5)

    def test_executor_delivers_rec2_as_typed_wallet_error(self):
        from wam_regtest.wallet_executor import WalletExecutorError
        from wam_regtest.wallet_session import WalletSessionError
        error = self._run_resume(WalletSessionError(REC2))
        self.assertIs(type(error), WalletExecutorError)
        self.assertEqual(error.args, (REC2,))

    def test_executor_end_to_end_backend_session_refuses_with_zero_rpc_or_writes(self):
        from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend
        from wam_regtest.wallet_executor import WalletExecutorError
        session = _session([(IN_1[0], IN_1[1], TOKEN, "uncertain")],
                           {(TOKEN, "signed"): _body()})
        before = session._rows()
        backend = object.__new__(Bip39ReadOnlyBackend)
        backend._spend_session = session
        backend.shared_profile = None
        backend._control_fault = False
        backend.owner = None
        backend._secret = None
        backend._executor = None

        class _Facade:
            def attach_executor(self, executor):
                backend.attach_executor(executor)

            def execute(self, action, args, kwargs):
                if action == "quit":
                    return {}
                return backend.execute(action, args, kwargs)

            def public_state(self):
                return backend.public_state()

        error = self._run_resume(None, backend_factory=_Facade)
        self.assertIs(type(error), WalletExecutorError)
        self.assertEqual(error.args, (REC2,))
        self.assertEqual(session._rpc_fake.calls, [])
        self.assertEqual(session.vault.saves, [])
        self.assertEqual(session._evidence_fake.writes, [])
        self.assertEqual(session._rows(), before)

    def test_untrusted_rec2_text_never_crosses_executor(self):
        from wam_regtest.wallet_executor import WalletExecutorError
        from wam_regtest.wallet_session import WalletSessionError

        class HostileValueError(ValueError):
            def __str__(self):
                raise AssertionError("str() must not be called")

        for untrusted in (
                ValueError(REC2),
                HostileValueError(REC2),
                WalletSessionError(REC2, "extra"),
        ):
            with self.subTest(untrusted=type(untrusted).__name__):
                error = self._run_resume(untrusted)
                self.assertIs(type(error), WalletExecutorError)
                self.assertEqual(error.args, ("WALLET_EXECUTOR_DENIED",))


class ReopenNeverSubmits(_Patched):
    def test_open_recovers_pending_read_only_and_never_resumes(self):
        from wam_regtest import bip39_spend_session as module
        source = inspect.getsource(module.open_owned_spend_session)
        self.assertIn("_recover_pending_broadcast()", source)
        self.assertNotIn("resume_signed_intent", source)
        self.assertNotIn("sendrawtransaction", source)

    def test_recover_pending_broadcast_ignores_uncertain_and_writes_nothing(self):
        session = _session([(IN_1[0], IN_1[1], TOKEN, "uncertain")],
                           {(TOKEN, "uncertain"): _body()})
        before = session._rows()
        self.assertIsNone(session._recover_pending_broadcast())
        self.assertIsNone(session._q06_pending_confirm)
        self.assertEqual(session._rpc_fake.calls, [])
        self.assertEqual(session.vault.saves, [])
        self.assertEqual(session._evidence_fake.writes, [])
        self.assertEqual(session._rows(), before)


if __name__ == "__main__":
    unittest.main()
