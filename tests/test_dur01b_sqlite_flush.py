"""DUR-01b: one WAM SQLite factory, full-flush readback, typed fail-closed latch.

Power-loss durability is UNVERIFIED. Readback proves the connection accepted
the pragmas, not that each F_FULLFSYNC succeeded. DELETE + synchronous FULL
can lose the last commit on power loss. The live VFS name stays UNVERIFIED.
"""
import ast
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import nullcontext
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import wam_regtest  # install the WSP import guard before any wam_sp import
from wam_sp.core import pub
from wam_sp.errors import StorageError
from wam_sp.keystore import ScanAccount
from wam_sp.scanner import Scanner
from wam_sp.store import SCHEMA, Store

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = ROOT / "src" / "wam_regtest"
ACCOUNT = ScanAccount(0, 1, pub(2), birthday=1)


def _private(test):
    path = Path(tempfile.mkdtemp(prefix="dur01b-"))
    os.chmod(path, 0o700)
    test.addCleanup(shutil.rmtree, path, True)
    return path


def _factory():
    from wam_regtest import sqlite_flush
    return sqlite_flush


class Dur01bSqliteFlush(unittest.TestCase):
    def test_q3_constructor_writes_are_schema_meta_not_custody(self):
        """Fresh construction leaves reservations empty; __init__ never writes custody states."""
        source = inspect_source(Store.__init__)
        self.assertNotIn("state='signed'", source)
        self.assertNotIn("state='uncertain'", source)
        self.assertNotIn("state='broadcast'", source)
        self.assertIn(
            '("blocks", "coins", "history", "mempool_coins", "mempool_spends")',
            source)
        self.assertNotIn(
            '("blocks", "coins", "history", "mempool_coins", "mempool_spends", "reservations")',
            source)
        scanner_source = inspect_source(Scanner.__init__)
        self.assertNotIn("reservations", scanner_source)
        parent = _private(self)
        scanner = _factory().make_scanner(parent / "fresh.sqlite", (ACCOUNT,))
        self.addCleanup(scanner.close)
        rows = scanner.store.db.execute(
            "SELECT state FROM reservations").fetchall()
        self.assertEqual(rows, [])

    def test_r2_1_schema_and_transaction_boundaries_stay_in_inventory(self):
        statements = [part.strip() for part in SCHEMA.split(";") if part.strip()]
        creates = [part for part in statements if part.upper().startswith("CREATE")]
        self.assertEqual(creates, statements)
        tables = [part for part in creates if part.upper().startswith("CREATE TABLE")]
        indexes = [part for part in creates if part.upper().startswith("CREATE INDEX")]
        self.assertEqual(len(tables), 12)
        self.assertEqual(len(indexes), 2)
        joined = "\n".join(creates)
        for name in ("meta", "blocks", "coins", "cache", "contacts", "reservations",
                     "history", "mempool_coins", "mempool_spends", "labels",
                     "intents", "outbox"):
            self.assertIn("CREATE TABLE IF NOT EXISTS " + name, joined)
        self.assertIn("CREATE INDEX IF NOT EXISTS coins_account", joined)
        self.assertIn("CREATE INDEX IF NOT EXISTS coins_height", joined)
        store_source = (ROOT / "wsp-upstream/src/wam_sp/store.py").read_text()
        self.assertIn("for statement in SCHEMA.split", store_source)
        self.assertIn('self.db.execute(statement)', store_source)
        atomic = inspect_source(
            __import__("wam_sp.store", fromlist=["Atomic"]).Atomic.__exit__)
        self.assertIn('BEGIN IMMEDIATE', inspect_source(
            __import__("wam_sp.store", fromlist=["Atomic"]).Atomic.__enter__))
        self.assertIn('"COMMIT"', atomic)
        self.assertIn('"ROLLBACK"', atomic)

    def test_pragma_readback_is_per_connection(self):
        parent = _private(self)
        path = parent / "wallet.sqlite"
        scanner = _factory().make_scanner(path, (ACCOUNT,))
        self.addCleanup(scanner.close)
        db = scanner.store.db
        self.assertEqual(db.execute("PRAGMA fullfsync").fetchone()[0], 1)
        self.assertEqual(db.execute("PRAGMA checkpoint_fullfsync").fetchone()[0], 1)
        self.assertEqual(db.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0].upper(), "DELETE")
        other = sqlite3.connect(path, isolation_level=None)
        self.addCleanup(other.close)
        self.assertEqual(other.execute("PRAGMA fullfsync").fetchone()[0], 0)
        self.assertEqual(sqlite3.sqlite_version, _factory().sqlite_version())
        self.assertTrue(sqlite3.sqlite_version)
        text = _factory().DISCLOSURE
        self.assertIn("F_FULLFSYNC", text)
        self.assertIn("UNVERIFIED", text)
        self.assertIn("power loss", text)

    def test_set_and_readback_failures_close_and_do_not_fsync(self):
        flush = _factory()
        cases = []
        for name, setting in (("fullfsync", "ON"), ("checkpoint_fullfsync", "ON"),
                              ("synchronous", "FULL")):
            cases.append(("set:" + name, "PRAGMA " + name + "=" + setting, None))
            cases.append(("read:" + name, None, name))
        for label, failing_sql, bad_read in cases:
            with self.subTest(label=label):
                parent = _private(self)
                seen = []
                real_init = Scanner.__init__

                def init(self_scanner, *args, **kwargs):
                    real_init(self_scanner, *args, **kwargs)
                    seen.append(self_scanner)

                real_execute = flush._execute
                real_read = flush._read_pragma

                def execute(db, sql):
                    if failing_sql is not None and sql == failing_sql:
                        raise sqlite3.OperationalError("injected-set")
                    return real_execute(db, sql)

                def read(db, name):
                    if bad_read is not None and name == bad_read:
                        return 0
                    return real_read(db, name)

                fsyncs = []
                with patch.object(Scanner, "__init__", init), \
                        patch.object(flush, "_execute", execute), \
                        patch.object(flush, "_read_pragma", read), \
                        patch("os.fsync", side_effect=lambda fd: fsyncs.append(fd)):
                    with self.assertRaises(flush.SqliteFlushUnconfigured) as caught:
                        flush.make_scanner(parent / (label + ".sqlite"), (ACCOUNT,))
                self.assertEqual(caught.exception.args, (flush.SQLITE_FLUSH_UNCONFIGURED,))
                self.assertIs(caught.exception.faulted, False)
                self.assertIn("reopen/recreate", caught.exception.recovery)
                self.assertEqual(fsyncs, [])
                self.assertTrue(seen[0].store.closed)
                with self.assertRaises(sqlite3.ProgrammingError):
                    seen[0].store.db.execute("SELECT 1")

    def test_journal_mode_other_than_delete_fails_closed(self):
        flush = _factory()
        parent = _private(self)
        seen = []
        real_init = Scanner.__init__

        def init(self_scanner, *args, **kwargs):
            real_init(self_scanner, *args, **kwargs)
            seen.append(self_scanner)

        with patch.object(Scanner, "__init__", init), \
                patch.object(flush, "_journal_mode", return_value="wal"):
            with self.assertRaises(flush.SqliteFlushUnconfigured):
                flush.make_scanner(parent / "wal.sqlite", (ACCOUNT,))
        self.assertTrue(seen[0].store.closed)

    def test_store_constructor_failure_is_not_relabelled(self):
        flush = _factory()
        parent = _private(self)
        applied = []
        with patch.object(Store, "__init__", side_effect=StorageError("UNSAFE_PATH")), \
                patch.object(flush, "_apply_darwin_flush_pragmas",
                             side_effect=lambda db: applied.append(db)):
            with self.assertRaises(StorageError):
                flush.make_scanner(parent / "bad.sqlite", (ACCOUNT,))
        self.assertEqual(applied, [])

    def test_configuration_once_per_connection_before_wam_write(self):
        flush = _factory()
        parent = _private(self)
        log = []

        def connect(*args, **kwargs):
            db = real_connect(*args, **kwargs)
            db.set_trace_callback(lambda sql: log.append(" ".join(sql.split())))
            return db

        real_connect = sqlite3.connect
        with patch("wam_sp.store.sqlite3.connect", connect):
            first = flush.make_scanner(parent / "one.sqlite", (ACCOUNT,))
            self.addCleanup(first.close)
            from wam_sp.wallet import Wallet
            Wallet(first)
            with first.store.transaction():
                first.store.db.execute("SELECT count(*) FROM meta")
            second = flush.make_scanner(parent / "two.sqlite", (ACCOUNT,))
            self.addCleanup(second.close)
        sets = [i for i, sql in enumerate(log) if sql == "PRAGMA fullfsync=ON"]
        self.assertEqual(len(sets), 2)
        begins = [i for i, sql in enumerate(log) if sql == "BEGIN IMMEDIATE"]
        self.assertTrue(any(i < sets[0] for i in begins))
        self.assertTrue(any(i > sets[0] for i in begins))
        self.assertLess(log.index("PRAGMA journal_mode=DELETE"), sets[0])
        self.assertEqual(log.count("PRAGMA checkpoint_fullfsync=ON"), 2)

    def test_non_darwin_does_not_take_the_pragma_path(self):
        flush = _factory()
        parent = _private(self)
        applied = []
        with patch.object(flush.sys, "platform", "linux"), \
                patch.object(flush, "_apply_darwin_flush_pragmas",
                             side_effect=lambda db: applied.append(True)):
            scanner = flush.make_scanner(parent / "linux.sqlite", (ACCOUNT,))
        self.addCleanup(scanner.close)
        self.assertEqual(applied, [])
        self.assertEqual(scanner.store.db.execute("PRAGMA fullfsync").fetchone()[0], 0)
        self.assertEqual(
            scanner.store.db.execute("PRAGMA journal_mode").fetchone()[0].upper(),
            "DELETE")

    def test_uncertain_update_failure_never_calls_sendrawtransaction(self):
        from wam_sp.wallet import Wallet
        parent = _private(self)
        scanner = _factory().make_scanner(parent / "pay.sqlite", (ACCOUNT,))
        self.addCleanup(scanner.close)
        token = "ab" * 16
        txid = "cd" * 32
        scanner.store.db.execute(
            "INSERT INTO reservations VALUES (?,?,?,?,?)",
            (txid, 0, token, "signed", 1))
        scanner.ready = True
        calls = []

        class Rpc:
            def attest(self):
                return None

            def call(self, method, params=None):
                calls.append(method)
                if method == "gettxout":
                    return {"value": "0.00001000",
                            "scriptPubKey": {"hex": "5120" + "11" * 32}}
                if method == "testmempoolaccept":
                    return [{"allowed": True}]
                if method == "sendrawtransaction":
                    return "ee" * 32
                raise AssertionError(method)

        class Tx:
            inputs = [(txid, 0)]

        class Psbt:
            tx = Tx()
            utxos = [(1000, bytes.fromhex("5120" + "11" * 32))]

            def finalize(self):
                return b"\x01"

            def txid(self):
                return "ee" * 32

        original = scanner.store.db
        scanner.store.db = _FailingDB(
            original, lambda sql: isinstance(sql, str) and "state='uncertain'" in sql)
        try:
            with patch("wam_sp.wallet.PSBT.decode", return_value=Psbt()):
                with self.assertRaises(sqlite3.OperationalError):
                    Wallet(scanner).broadcast(b"unused", token, Rpc())
        finally:
            scanner.store.db = original
        self.assertNotIn("sendrawtransaction", calls)
        state = scanner.store.db.execute(
            "SELECT state FROM reservations WHERE token=?", (token,)).fetchone()[0]
        self.assertEqual(state, "signed")

    def test_payment_state_failures_do_not_reach_rpc(self):
        from wam_regtest.domain.payment_state import (
            mark_reservations_uncertain_before_submission)
        parent = _private(self)
        scanner = _factory().make_scanner(parent / "state.sqlite", (ACCOUNT,))
        self.addCleanup(scanner.close)
        token = "12" * 16
        scanner.store.db.execute(
            "INSERT INTO reservations VALUES (?,?,?,?,?)",
            ("34" * 32, 0, token, "signed", 1))
        failing = _FailingDB(
            scanner.store.db,
            lambda sql: isinstance(sql, str) and "state='uncertain'" in sql)
        for signed_rows_only in (False, True):
            with self.subTest(signed_rows_only=signed_rows_only):
                calls = []
                with self.assertRaises(sqlite3.OperationalError):
                    mark_reservations_uncertain_before_submission(
                        failing, token, signed_rows_only=signed_rows_only)
                    calls.append("sendrawtransaction")
                self.assertEqual(calls, [])
        state = scanner.store.db.execute(
            "SELECT state FROM reservations WHERE token=?", (token,)).fetchone()[0]
        self.assertEqual(state, "signed")

    def test_mark_signed_failure_blocks_the_next_step(self):
        from wam_sp.wallet import Wallet
        parent = _private(self)
        scanner = _factory().make_scanner(parent / "sign.sqlite", (ACCOUNT,))
        self.addCleanup(scanner.close)
        token = "56" * 16
        scanner.store.db.execute(
            "INSERT INTO reservations VALUES (?,?,?,?,?)",
            ("78" * 32, 0, token, "draft", 1))
        next_step = []
        original = scanner.store.db
        scanner.store.db = _FailingDB(
            original, lambda sql: isinstance(sql, str) and "state='signed'" in sql)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                Wallet(scanner).mark_signed(token)
                next_step.append("save")
        finally:
            scanner.store.db = original
        self.assertEqual(next_step, [])
        state = scanner.store.db.execute(
            "SELECT state FROM reservations WHERE token=?", (token,)).fetchone()[0]
        self.assertEqual(state, "draft")

    def test_positive_write_succeeds_after_configuration(self):
        parent = _private(self)
        scanner = _factory().make_scanner(parent / "ok.sqlite", (ACCOUNT,))
        self.addCleanup(scanner.close)
        with scanner.store.transaction():
            scanner.store.db.execute(
                "INSERT INTO meta VALUES('dur01b-probe','1')")
        value = scanner.store.db.execute(
            "SELECT value FROM meta WHERE key='dur01b-probe'").fetchone()[0]
        self.assertEqual(value, "1")
        self.assertEqual(scanner.store.db.execute("PRAGMA fullfsync").fetchone()[0], 1)

    def test_product_constructions_use_only_the_factory(self):
        factory_calls = []
        direct_calls = []
        connects = []
        for path in sorted(PRODUCT.rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=str(path))
            factory_names, wsp_names = _bindings(tree)
            rel = str(path.relative_to(ROOT))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if (path.name != "sqlite_flush.py" and isinstance(func, ast.Name)
                        and func.id in wsp_names):
                    direct_calls.append((rel, node.lineno, func.id))
                if isinstance(func, ast.Name) and func.id in factory_names:
                    factory_calls.append(rel)
                if isinstance(func, ast.Attribute) and func.attr == "Scanner":
                    if path.name != "sqlite_flush.py":
                        direct_calls.append((rel, node.lineno, "attribute"))
                if isinstance(func, ast.Attribute) and func.attr == "connect":
                    value = func.value
                    if isinstance(value, ast.Name) and value.id == "sqlite3":
                        connects.append((rel, node.lineno, ast.get_source_segment(
                            path.read_text(), node) or ""))
            if path.name == "sqlite_flush.py":
                self.assertIn("Scanner", wsp_names)
                self.assertTrue(any(
                    isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "Scanner" for node in ast.walk(tree)))
        self.assertEqual(direct_calls, [])
        for required in (
                "src/wam_regtest/wallet_session.py",
                "src/wam_regtest/managed_wallet_session.py",
                "src/wam_regtest/bip39_reconciliation.py",
                "src/wam_regtest/bip39_spend_session.py",
                "src/wam_regtest/vault.py"):
            self.assertIn(required, factory_calls)
        self.assertGreaterEqual(len(set(factory_calls)), 20)
        for rel, _lineno, segment in connects:
            self.assertTrue(
                ":memory:" in segment or "mode=ro&immutable=1" in segment,
                rel)
        for script in (
                "scripts/owner_acceptance.py",
                "scripts/probe_memory_profile.py",
                "scripts/probe_scanner_reorg.py"):
            text = (ROOT / script).read_text()
            self.assertIn("Scanner(", text)
            self.assertNotIn("sqlite_flush", text)

    def test_create_preserves_exact_token_and_faulted(self):
        from wam_regtest import custody
        from wam_regtest.wallet_session import WalletSession, WalletSessionError
        flush = _factory()
        datadir = _private(self)
        source = (ROOT / "wsp-upstream").resolve()
        ring = MagicMock()
        rpc = MagicMock()
        rpc.call.return_value = 102
        with patch("wam_regtest.wallet_session._pinned_source"), \
                patch("wam_regtest.wallet_session.verified_core_paths",
                      return_value=(None, "cli", {"platform": custody.platform_name()})), \
                patch("wam_regtest.wallet_session.WalletCoreCli", return_value=rpc), \
                patch("wam_regtest.wallet_session.custody.create_directory"), \
                patch("wam_regtest.wallet_session._public_fixture_payment"), \
                patch("wam_sp.keystore.Keyring", return_value=ring), \
                patch("wam_regtest.sqlite_flush.make_scanner",
                      side_effect=flush.SqliteFlushUnconfigured):
            with self.assertRaises(flush.SqliteFlushUnconfigured) as caught:
                WalletSession.create(
                    Path("/tmp/dur01b-core"), datadir, source,
                    b"public-test-password", "addr", authorized=True)
        self.assertEqual(caught.exception.args, (flush.SQLITE_FLUSH_UNCONFIGURED,))
        self.assertIs(caught.exception.faulted, True)
        self.assertNotIn("WALLET_CREATE_DENIED", caught.exception.args)
        ring.close.assert_called_once()
        with patch("wam_regtest.wallet_session._pinned_source"), \
                patch("wam_regtest.wallet_session.verified_core_paths",
                      return_value=(None, "cli", {"platform": custody.platform_name()})), \
                patch("wam_regtest.wallet_session.WalletCoreCli", return_value=rpc), \
                patch("wam_regtest.wallet_session.custody.create_directory"), \
                patch("wam_regtest.wallet_session._public_fixture_payment"), \
                patch("wam_sp.keystore.Keyring", return_value=ring), \
                patch("wam_regtest.sqlite_flush.make_scanner",
                      side_effect=RuntimeError("generic")):
            with self.assertRaises(WalletSessionError) as denied:
                WalletSession.create(
                    Path("/tmp/dur01b-core"), datadir, source,
                    b"public-test-password", "addr", authorized=True)
        self.assertEqual(denied.exception.args, ("WALLET_CREATE_DENIED",))

    def test_managed_open_preserves_exact_token_and_faulted(self):
        from wam_regtest.wallet_session import WalletSession, WalletSessionError
        from wam_regtest import managed_wallet_session as module
        flush = _factory()
        root = _private(self)
        owner = SimpleNamespace(
            directory=root / "owner", root=root / "supervisor", profile=None,
            cli=root / "cli", core=root / "core", receipt={}, process=object())
        owner.directory.mkdir(0o700)
        owner.root.mkdir(0o700)
        source = (ROOT / "wsp-upstream").resolve()

        class Lease:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class Anchor:
            def read(self):
                return None

            def lease(self):
                return Lease()

        vault = MagicMock()
        with patch.object(module, "_inputs"), \
                patch("wam_regtest.quit_notice.unacknowledged", return_value=()), \
                patch.object(module, "_owned"), \
                patch.object(module.custody, "anchor", return_value=Anchor()), \
                patch.object(module.custody, "create_directory"), \
                patch("wam_regtest.vault.CheckpointVault", return_value=vault), \
                patch("wam_regtest.wallet_session.WalletCoreCli", return_value=MagicMock()), \
                patch("wam_sp.keystore.Keyring", return_value=MagicMock()), \
                patch("wam_regtest.sqlite_flush.make_scanner",
                      side_effect=flush.SqliteFlushUnconfigured):
            with self.assertRaises(flush.SqliteFlushUnconfigured) as created:
                WalletSession.open_owned(
                    owner, source, b"public-test-password", authorized=True, create=True)
        self.assertEqual(created.exception.args, (flush.SQLITE_FLUSH_UNCONFIGURED,))
        self.assertIs(created.exception.faulted, True)
        self.assertNotIn("WALLET_MANAGED_OPEN_DENIED", created.exception.args)

        folder = owner.directory / "wallet-vault"
        vault.restore.side_effect = flush.SqliteFlushUnconfigured
        with patch.object(module, "_inputs"), \
                patch("wam_regtest.quit_notice.unacknowledged", return_value=()), \
                patch.object(module, "_owned"), \
                patch.object(module, "_read_reference", return_value="ab" * 16), \
                patch.object(module, "active_location",
                             return_value=(folder, "wallet-runtime.sqlite", None)), \
                patch.object(module, "_require_no_prior_runtime"), \
                patch.object(module.custody, "anchor", return_value=Anchor()), \
                patch("wam_regtest.wallet_recovery.require_recovery_source_equivalence"), \
                patch("wam_regtest.managed_wallet_checkpoint.require_checkpoint_namespace"), \
                patch("wam_regtest.vault.CheckpointVault", return_value=vault), \
                patch("wam_regtest.wallet_session.WalletCoreCli", return_value=MagicMock()):
            with self.assertRaises(flush.SqliteFlushUnconfigured) as opened:
                WalletSession.open_owned(
                    owner, source, b"public-test-password", authorized=True, create=False)
        self.assertEqual(opened.exception.args, (flush.SQLITE_FLUSH_UNCONFIGURED,))
        self.assertIs(opened.exception.faulted, True)

        with patch.object(module, "_inputs"), \
                patch("wam_regtest.quit_notice.unacknowledged", return_value=()), \
                patch.object(module, "_owned"), \
                patch.object(module.custody, "anchor", return_value=Anchor()), \
                patch.object(module.custody, "create_directory"), \
                patch("wam_regtest.vault.CheckpointVault", return_value=vault), \
                patch("wam_regtest.wallet_session.WalletCoreCli", return_value=MagicMock()), \
                patch("wam_sp.keystore.Keyring", return_value=MagicMock()), \
                patch("wam_regtest.sqlite_flush.make_scanner",
                      side_effect=RuntimeError("generic")):
            with self.assertRaises(WalletSessionError) as denied:
                WalletSession.open_owned(
                    owner, source, b"public-test-password", authorized=True, create=True)
        self.assertEqual(denied.exception.args, ("WALLET_MANAGED_OPEN_DENIED",))

    def test_restore_and_backup_open_preserve_exact_token(self):
        from wam_regtest.vault import CheckpointVault
        from wam_regtest.wallet_session import WalletSession
        from wam_regtest import custody
        from wam_sp.watcher import GENESIS
        flush = _factory()
        parent = _private(self)
        vault = object.__new__(CheckpointVault)
        vault._storage = SimpleNamespace(validate_directory=lambda path: None)
        vault.anchor = SimpleNamespace(read=lambda: (1, "a" * 64), lease=lambda: nullcontext())
        vault.directory = parent
        with patch.object(CheckpointVault, "_load_payload", return_value={"keys": "aGk="}), \
                patch("wam_sp.file_lock.exclusive_file_lock", return_value=nullcontext()), \
                patch("wam_sp.keystore.Keyring.restore", return_value=MagicMock()), \
                patch("wam_regtest.sqlite_flush.make_scanner",
                      side_effect=flush.SqliteFlushUnconfigured):
            with self.assertRaises(flush.SqliteFlushUnconfigured) as restored:
                vault.restore(parent / "wallet-runtime.sqlite", b"public-test-password")
        self.assertEqual(restored.exception.args, (flush.SQLITE_FLUSH_UNCONFIGURED,))
        self.assertNotEqual(restored.exception.args, ("VAULT_RESTORE_DENIED",))

        ciphertext = b"public-test-ciphertext"
        digest = sha256(ciphertext).hexdigest()
        payload = dict(custody.envelope_profile())
        payload.update(disposable_regtest=True, network=GENESIS, generation=1,
                       wallet_id="ab" * 16, keys="k", checkpoint="c")
        opened = MagicMock()
        opened.restore.side_effect = flush.SqliteFlushUnconfigured

        class Storage:
            def read(self, directory, name):
                return ciphertext

            def publish(self, *args, **kwargs):
                return None

        class Anchor:
            def read(self):
                return (1, digest)

        with patch("wam_regtest.wallet_session._pinned_source"), \
                patch("wam_regtest.wallet_session.custody.storage", return_value=Storage()), \
                patch("wam_regtest.wallet_session.custody.anchor", return_value=Anchor()), \
                patch("wam_regtest.wallet_session.custody.create_directory"), \
                patch("wam_sp.keystore.unseal",
                      return_value=__import__("json").dumps(payload).encode()), \
                patch("wam_regtest.wallet_session.CheckpointVault", return_value=opened):
            with self.assertRaises(flush.SqliteFlushUnconfigured) as backed:
                WalletSession.from_backup(
                    Path("/tmp/dur01b-core"), parent, (ROOT / "wsp-upstream").resolve(),
                    parent, "backup.enc", b"public-test-password", "addr",
                    authorized=True)
        self.assertEqual(backed.exception.args, (flush.SQLITE_FLUSH_UNCONFIGURED,))
        self.assertIs(backed.exception.faulted, True)
        self.assertNotEqual(backed.exception.args, ("WALLET_CROSS_SESSION_RECOVERY_DENIED",))


class _FailingDB:
    """Delegate to a real connection and fail selected statements."""

    def __init__(self, db, fail_if):
        self._db = db
        self._fail_if = fail_if

    def execute(self, sql, parameters=()):
        if self._fail_if(sql):
            raise sqlite3.OperationalError("injected")
        return self._db.execute(sql, parameters)

    def __getattr__(self, name):
        return getattr(self._db, name)


def inspect_source(obj):
    import inspect
    return inspect.getsource(obj)


def _bindings(tree):
    factory, wsp = set(), set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        for alias in node.names:
            bound = alias.asname or alias.name
            if node.module == "sqlite_flush" and node.level == 1 and alias.name == "make_scanner":
                factory.add(bound)
            if node.module == "wam_sp.scanner" and node.level == 0 and alias.name == "Scanner":
                wsp.add(bound)
    return factory, wsp


if __name__ == "__main__":
    unittest.main()
