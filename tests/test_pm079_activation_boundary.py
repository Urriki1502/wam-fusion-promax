"""PM-079 round 4: backend spending activation requires authenticated backup ack.

Source-only REGTEST contracts using the same synthetic owner and patched seed
container as tests/test_pm079_restore_ack_copy.py. No Core, profile, Keychain
or acceptance.
"""
from contextlib import contextmanager, nullcontext
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wam_regtest.bip39_12 import Bip39Regtest12Keys
from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend, Q06ReadOnlyError
from wam_regtest.wallet_read import WalletReadSnapshot

import test_q06_bip39_owner_backend as fixture

PASSWORD, PHRASE, SOURCE = fixture.PASSWORD, fixture.PHRASE, fixture.SOURCE
FOLDER_NAME = "bip39-12-" + ("0" * 32)
TIP = "ab" * 32


def _public_metadata():
    with Bip39Regtest12Keys(PHRASE, source=SOURCE, authorized_disposable=True) as keys:
        meta = keys.public_metadata()
    return {
        "profile": "q06",
        "account_id": meta["account_id"],
        "receive_code": meta["receive_code"],
    }


PUBLIC = _public_metadata()


class _FakeSpendSession:
    """Minimal duck-typed spend session for backend activation boundary tests."""

    def __init__(self, receive_code):
        self.faulted = False
        self._q06_uncertain = False
        self.locked = False
        self._core_reauthentication_required = False
        self._lock = nullcontext()
        self.payment_review = None
        self.payment_signed = False
        self.pending_confirm_txid = None
        db = sqlite3.connect(":memory:")
        db.executescript(
            "CREATE TABLE reservations(token TEXT,state TEXT);"
            "CREATE TABLE history(txid TEXT,height INTEGER);"
        )
        self._db = db
        self.scanner = SimpleNamespace(
            store=SimpleNamespace(db=db, transaction=nullcontext),
            mempool_ready=False,
        )
        self._read_payment_evidence = lambda token, stage: None
        self._item = WalletReadSnapshot(
            chain="regtest",
            height=1,
            tip=TIP,
            receive_code=receive_code,
            confirmed_atoms=0,
            confirmed_utxos=0,
            history=(),
            core_sha256="cd" * 32,
            reservation_count=0,
            signer_allowed=True,
            broadcast_allowed=True,
            mainnet_allowed=False,
        )

    def snapshot(self, history_offset=0):
        return self._item

    def recovered_unsigned_cancel_available(self):
        return False

    def lock(self):
        self.locked = True
        self._db.close()


class BackendActivationBoundary(unittest.TestCase):
    """execute('activate', (), {}) must enforce MAC-authenticated backup ack."""

    def setUp(self):
        if sys.platform == "darwin":
            from wam_regtest.custody import private_temporary_directory
            self.tmp = private_temporary_directory("pm079-activate-")
        else:
            self.tmp = tempfile.TemporaryDirectory(prefix="pm079-activate-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.owner = SimpleNamespace(directory=self.root, root=self.root)
        self.backend = self._new_backend()
        self.folder = self.root / FOLDER_NAME
        self.ack_path = self.root / "q06-gui-state" / "ack" / (FOLDER_NAME + ".json")

    def _new_backend(self):
        backend = Bip39ReadOnlyBackend(self.root, Path("/synthetic-core"), SOURCE)
        backend._core = lambda: self.owner
        return backend

    def _fake_opened_keys(self, generation=2):
        keys = Bip39Regtest12Keys(PHRASE, source=SOURCE, authorized_disposable=True)
        keys._q06_generation = generation
        return keys

    @contextmanager
    def _seed_container(self):
        with (patch("wam_regtest.bip39_seed_vault.read_seed_phrase", return_value=PHRASE),
              patch("wam_regtest.bip39_seed_vault._owner_binding", return_value="0" * 64),
              patch("wam_regtest.bip39_seed_vault.open_owned_seed_container") as opened):
            opened.return_value.__enter__ = lambda *a, **kw: self._fake_opened_keys()
            opened.return_value.__exit__ = lambda *a, **kw: None
            yield opened

    @contextmanager
    def _spend_session_opener(self):
        created = []

        def open_session(owner, seed_folder, source, password, *, authorized=False, keychain=None):
            session = _FakeSpendSession(PUBLIC["receive_code"])
            created.append(session)
            return session

        with (patch("wam_regtest.bip39_spend_session.open_owned_spend_session",
                    side_effect=open_session) as opener,
              patch("wam_sp.wallet.Wallet") as wallet):
            wallet.return_value._balance.return_value = {"available_atoms": 0}
            yield opener, created

    def _open_create(self, backend=None):
        backend = backend or self.backend
        with (patch("wam_regtest.bip39_12.generate_phrase", return_value=PHRASE),
              patch("wam_regtest.bip39_seed_vault.create_owned_seed_container",
                    return_value=(self.folder, dict(PUBLIC)))):
            return backend.execute("open", (PASSWORD, "create", ""), {})

    def _open_restore(self, backend=None):
        backend = backend or self.backend
        with patch("wam_regtest.bip39_seed_vault.create_owned_seed_container",
                   return_value=(self.folder, dict(PUBLIC))):
            return backend.execute("open", (PASSWORD, "restore", PHRASE), {})

    def _complete_challenge(self, backend=None):
        backend = backend or self.backend
        challenge = backend.execute("backup_challenge", (), {})
        answers = [PHRASE.split()[p - 1] for p in challenge["positions"]]
        self.assertIs(backend.execute("backup_verify", (challenge["challenge_id"], answers), {}), True)

    def _assert_activate_refused(self, backend=None):
        backend = backend or self.backend
        with self._spend_session_opener() as (opener, _created):
            with self.assertRaises(Q06ReadOnlyError) as refused:
                backend.execute("activate", (), {})
            self.assertEqual(refused.exception.args, ("Q06_GUI_BACKUP_ACK_REQUIRED",))
            opener.assert_not_called()
            self.assertIsNone(backend._spend_session)

    def _assert_activate_allowed(self, backend=None):
        backend = backend or self.backend
        with self._spend_session_opener() as (opener, _created):
            result = backend.execute("activate", (), {})
        opener.assert_called_once()
        self.assertTrue(result["signer_allowed"])
        self.assertTrue(result["broadcast_allowed"])
        self.assertFalse(result["mainnet_allowed"])
        self.assertEqual(result["receive_code"], PUBLIC["receive_code"])
        return result

    def test_created_deferred_profile_refused_until_backup_challenge_verified(self):
        opened = self._open_create()
        self.assertEqual(opened["backup_status"], "required")
        with self._seed_container():
            self._assert_activate_refused()
            self.backend.execute("acknowledge_create_pending", (str(self.folder),), {})
            self._assert_activate_refused()
            self.backend.execute("lock", (), {})
            if not self.folder.exists():
                self.folder.mkdir(parents=True)
            unlocked = self.backend.execute("unlock", (PASSWORD, False), {})
            self.assertEqual(unlocked["backup_status"], "deferred")
            self._assert_activate_refused()
            self._complete_challenge()
            self._assert_activate_allowed()
        self.backend.execute("lock", (), {})

    def test_restored_deferred_profile_refused_until_backup_challenge_verified(self):
        opened = self._open_restore()
        self.assertEqual(opened["backup_status"], "deferred")
        self.assertIs(opened["restored"], True)
        with self._seed_container():
            self._assert_activate_refused()
            self.backend._resume_spend = True
            self.backend.execute("lock", (), {})
            if not self.folder.exists():
                self.folder.mkdir(parents=True)
            unlocked = self.backend.execute("unlock", (PASSWORD, False), {})
            self.assertEqual(unlocked["backup_status"], "deferred")
            self.assertIsNone(self.backend._spend_session)
            self._assert_activate_refused()
            self._complete_challenge()
            self._assert_activate_allowed()
        self.backend.execute("lock", (), {})

    def test_tampered_or_unauthenticated_sidecar_refused_on_activate(self):
        cases = (
            ("no-mac", json.dumps({
                "version": 1, "acknowledged": True, "deferred": False,
                "seed_id": FOLDER_NAME,
            })),
            ("wrong-mac", json.dumps({
                "version": 1, "acknowledged": True, "deferred": False,
                "seed_id": FOLDER_NAME, "mac": "0" * 64,
            })),
            ("wrong-seed", json.dumps({
                "version": 1, "acknowledged": True, "deferred": False,
                "seed_id": "bip39-12-" + ("f" * 32), "mac": "0" * 64,
            })),
            ("malformed", "not-json"),
            ("missing", None),
        )
        for label, payload in cases:
            with self.subTest(case=label):
                self._open_restore()
                if payload is None:
                    self.ack_path.unlink()
                else:
                    self.ack_path.write_text(payload)
                with self._seed_container():
                    self._assert_activate_refused()
                self.backend.execute("lock", (), {})

    def test_post_verify_sidecar_tampering_refused_on_activate(self):
        self._open_restore()
        with self._seed_container():
            self._complete_challenge()
            # Tamper sidecar after verification while session remains unlocked.
            self.ack_path.write_text(json.dumps({
                "version": 1, "acknowledged": True, "deferred": False,
                "seed_id": FOLDER_NAME,
            }))
            self._assert_activate_refused()
        self.backend.execute("lock", (), {})

    def test_verified_profile_activate_and_unlock_auto_resume_unchanged(self):
        self._open_create()
        with self._seed_container():
            self._complete_challenge()
        self.backend.execute("lock", (), {})
        if not self.folder.exists():
            self.folder.mkdir(parents=True)

        restarted = self._new_backend()
        with self._seed_container():
            reopened = restarted.execute("open", (PASSWORD, "reopen", ""), {})
            self.assertEqual(reopened["backup_status"], "verified")
            self._assert_activate_allowed(restarted)
            restarted.execute("lock", (), {})
            self.assertTrue(restarted._resume_spend)
            with self._spend_session_opener() as (opener, _created):
                resumed = restarted.execute("unlock", (PASSWORD, False), {})
            opener.assert_called_once()
            self.assertEqual(resumed["backup_status"], "verified")
            self.assertTrue(resumed["signer_allowed"])
            self.assertTrue(resumed["broadcast_allowed"])
            self.assertFalse(resumed["mainnet_allowed"])
        restarted.execute("lock", (), {})


if __name__ == "__main__":
    unittest.main()
