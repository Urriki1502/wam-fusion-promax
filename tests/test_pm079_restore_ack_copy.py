"""PM-079: F-ACK-01 (a restore is not an acknowledged backup) and F-GAP-1 copy.

Source-only REGTEST contracts. The backend runs with the same synthetic owner
and patched seed container as tests/test_q06_bip39_owner_backend.py; the GUI
uses the production Bip39FusionWindow with the stub executor from
tests/test_q06_bip39_backup_ack.py. No Core, profile, Keychain or acceptance.
"""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend, Q06ReadOnlyError
from wam_regtest.presentation.strings import CATALOG, SUPPORTED_LANGUAGES, text

from wam_regtest.bip39_12 import Bip39Regtest12Keys
# Import the module, not its TestCase class, so that class is not re-run here.
import test_q06_bip39_owner_backend as fixture

PASSWORD, PHRASE, SOURCE = fixture.PASSWORD, fixture.PHRASE, fixture.SOURCE

KEYS = ("owner.restore_prompt", "wallet.restore_scope_notice", "wallet.backup_explanation_restored")
ENGLISH = {
    "owner.restore_prompt": (
        "Enter exactly 12 disposable REGTEST recovery words. Never enter mainnet words. "
        "Restoring recovers this wallet's keys and its confirmed history on this chain. "
        "Payments that were signed, pending or uncertain on the original profile are not "
        "copied: keep the original profile and check them there."),
    "wallet.restore_scope_notice": (
        "Restoring from 12 words recovers keys and confirmed history only. Signed, pending "
        "or uncertain payments stay with the profile that made them. A missing record here "
        "never means a payment failed or is safe to retry. If the original profile is "
        "unavailable, the status of its unfinished payments stays unknown."),
    "wallet.backup_explanation_restored": (
        "You entered your 12 words to restore this wallet. Confirm three of them to record "
        "that your backup is kept safe. This does not copy payments from the original profile."),
}
FOLDER_NAME = "bip39-12-" + "0" * 32
PUBLIC = {"profile": "q06", "account_id": "public-identity", "receive_code": "wamrtsp1public"}


class RestoreBackend(unittest.TestCase):
    """F-ACK-01 at the backend: typed restore words are never an acknowledgement."""

    def _fake_opened_keys(self, generation=2):
        keys = Bip39Regtest12Keys(PHRASE, source=SOURCE, authorized_disposable=True)
        keys._q06_generation = generation
        return keys

    def setUp(self):
        # Same private-root fixture as test_q06_bip39_owner_backend.setUp.
        import tempfile
        from types import SimpleNamespace
        if sys.platform == "darwin":
            from wam_regtest.custody import private_temporary_directory
            self.tmp = private_temporary_directory("pm079-restore-")
        else:
            self.tmp = tempfile.TemporaryDirectory(prefix="pm079-restore-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.owner = SimpleNamespace(directory=self.root, root=self.root)
        self.backend = Bip39ReadOnlyBackend(self.root, Path("/synthetic-core"), SOURCE)
        self.backend._core = lambda: self.owner
        self.folder = self.root / FOLDER_NAME
        self.ack_path = self.root / "q06-gui-state" / "ack" / (FOLDER_NAME + ".json")

    def restore(self, backend=None):
        backend = backend or self.backend
        with patch("wam_regtest.bip39_seed_vault.create_owned_seed_container",
                   return_value=(self.folder, dict(PUBLIC))) as create:
            result = backend.execute("open", (PASSWORD, "restore", PHRASE), {})
        self.assertEqual(create.call_args.args[3], PHRASE)
        return result

    @contextmanager
    def seed_container(self, failure=None):
        with (patch("wam_regtest.bip39_seed_vault.read_seed_phrase", return_value=PHRASE),
              patch("wam_regtest.bip39_seed_vault._owner_binding", return_value="0" * 64),
              patch("wam_regtest.bip39_seed_vault.open_owned_seed_container") as opened):
            if failure is not None:
                opened.side_effect = failure
            else:
                opened.return_value.__enter__ = lambda *a, **kw: self._fake_opened_keys()
                opened.return_value.__exit__ = lambda *a, **kw: None
            yield opened

    def restarted(self):
        backend = Bip39ReadOnlyBackend(self.root, Path("/synthetic-core"), SOURCE)
        backend._core = lambda: self.owner
        return backend

    def reopen(self, backend):
        if not self.folder.exists():
            self.folder.mkdir(parents=True)
        with self.seed_container():
            return backend.execute("open", (PASSWORD, "reopen", ""), {})

    def sidecar(self):
        return json.loads(self.ack_path.read_text())

    def verify(self, backend, words=None):
        challenge = backend.execute("backup_challenge", (), {})
        answers = words or [PHRASE.split()[p - 1] for p in challenge["positions"]]
        return backend.execute("backup_verify", (challenge["challenge_id"], answers), {})

    def test_restore_is_deferred_restored_and_reveals_nothing(self):
        with patch.object(Bip39ReadOnlyBackend, "_q06_write_ack",
                          autospec=True, wraps=Bip39ReadOnlyBackend._q06_write_ack) as write:
            result = self.restore()
        self.assertEqual(result["backup_status"], "deferred")
        self.assertIs(result["restored"], True)
        self.assertEqual(result["mnemonic_once"], "")
        self.assertFalse(result["signer_allowed"])
        # The only write is the existing deferred marker; never acknowledged=True.
        self.assertEqual([c.args[1:] for c in write.call_args_list], [(self.folder, False)])
        self.assertEqual([c.kwargs for c in write.call_args_list], [{"deferred": True}])
        data = self.sidecar()
        self.assertEqual((data["acknowledged"], data["deferred"]), (False, True))
        self.assertNotIn("mac", data)
        self.backend.execute("lock", (), {})

    def test_create_still_requires_backup_with_the_grid_and_no_restored_flag(self):
        with (patch("wam_regtest.bip39_12.generate_phrase", return_value=PHRASE),
              patch("wam_regtest.bip39_seed_vault.create_owned_seed_container",
                    return_value=(self.folder, dict(PUBLIC)))):
            result = self.backend.execute("open", (PASSWORD, "create", ""), {})
        self.assertEqual(result["backup_status"], "required")
        self.assertEqual(result["mnemonic_once"], PHRASE)
        self.assertNotIn("restored", result)
        self.backend.execute("lock", (), {})

    def test_challenge_success_records_authenticated_ack_and_restart_reopens_verified(self):
        self.restore()
        with self.seed_container():
            self.assertIs(self.verify(self.backend), True)
        data = self.sidecar()
        self.assertTrue(data["acknowledged"])
        self.assertRegex(data["mac"], r"\A[0-9a-f]{64}\Z")
        self.backend.execute("lock", (), {})
        reopened = self.reopen(self.restarted())
        self.assertEqual(reopened["backup_status"], "verified")
        self.assertNotIn("restored", reopened)
        self.assertEqual(reopened["mnemonic_once"], "")

    def test_before_the_challenge_lock_unlock_and_restart_stay_deferred(self):
        self.restore()
        self.backend._resume_spend = True  # even a prior spend consent cannot resume
        self.backend.execute("lock", (), {})
        if not self.folder.exists():
            self.folder.mkdir(parents=True)
        with self.seed_container(), patch.object(self.backend, "_activate_q06") as activate:
            unlocked = self.backend.execute("unlock", (PASSWORD, False), {})
        activate.assert_not_called()
        self.assertEqual(unlocked["backup_status"], "deferred")
        self.assertNotIn("restored", unlocked)
        self.backend.execute("lock", (), {})
        restarted = self.reopen(self.restarted())
        self.assertEqual(restarted["backup_status"], "deferred")
        self.assertNotIn("restored", restarted)
        self.assertEqual((self.sidecar()["acknowledged"], self.sidecar()["deferred"]), (False, True))

    def test_failed_answers_authentication_or_ack_write_never_become_verified(self):
        self.restore()
        with self.seed_container():
            self.assertIs(self.verify(self.backend, ["wrong"] * 3), False)
        with self.seed_container(failure=ValueError("PUBLIC_TEST_CONTAINER_UNAVAILABLE")):
            with self.assertRaises(Exception):
                self.verify(self.backend)
        with self.seed_container(), \
                patch("wam_regtest.domain.backup_ack._ack_write",
                      side_effect=OSError("PUBLIC_TEST_WRITE_FAILURE")):
            with self.assertRaises(Exception):
                self.verify(self.backend)
        data = self.sidecar()
        self.assertEqual((data["acknowledged"], data["deferred"]), (False, True))
        self.backend.execute("lock", (), {})
        self.assertEqual(self.reopen(self.restarted())["backup_status"], "deferred")

    def test_forged_or_wrong_seed_acknowledgement_after_restore_is_refused_on_restart(self):
        self.restore()
        self.backend.execute("lock", (), {})
        for label, forged in (
                ("bad-mac", {"version": 1, "acknowledged": True, "deferred": False,
                             "seed_id": FOLDER_NAME, "mac": "0" * 64}),
                ("wrong-seed", {"version": 1, "acknowledged": True, "deferred": False,
                                "seed_id": "bip39-12-" + "f" * 32, "mac": "0" * 64})):
            with self.subTest(label):
                self.ack_path.write_text(json.dumps(forged))
                with self.assertRaises(Q06ReadOnlyError) as refused:
                    self.reopen(self.restarted())
                self.assertIn("BACKUP_ACK_TAMPERED", str(refused.exception))


class RestoreCopyCatalog(unittest.TestCase):
    def test_exact_english_and_same_key_set_in_all_six_locales(self):
        for key, value in ENGLISH.items():
            self.assertEqual(CATALOG["en"][key], value, key)
        self.assertEqual(set(SUPPORTED_LANGUAGES), {"en", "vi", "ja", "zh-Hans", "ko", "id"})
        for language in SUPPORTED_LANGUAGES:
            for key in KEYS:
                with self.subTest(language=language, key=key):
                    value = CATALOG[language][key]
                    self.assertTrue(value.strip())
                    self.assertEqual(text(key, language), value)
                    if language != "en":
                        self.assertNotEqual(value, ENGLISH[key])  # actually translated
                    self.assertIn("12", value)

    def test_restored_copy_never_says_the_words_were_unsaved_or_shown_once(self):
        restored = ENGLISH["wallet.backup_explanation_restored"].lower()
        for phrase in ("not be shown", "shown again", "shown only once", "not saved", "were not"):
            self.assertNotIn(phrase, restored)
        self.assertIn("will not be shown again", CATALOG["en"]["wallet.backup_explanation"])


if importlib.util.find_spec("PySide6") is not None:
    from PySide6.QtWidgets import QLabel
    from test_q06_bip39_backup_ack import (
        _DISPLAY_PHRASE_WORDS, _find_button, _find_line_edits, _make_window, _open_result)


@unittest.skipIf(importlib.util.find_spec("PySide6") is None, "Qt widgets required")
class RestoreFusionGui(unittest.TestCase):
    def setUp(self):
        self.app, self.window = _make_window()

    def tearDown(self):
        self.window._poll.stop()
        worker = self.window._worker
        if worker is not None:
            self.assertTrue(worker.wait(2000))
        self.app.processEvents()
        self.window.hide()
        self.window.deleteLater()
        self.app.processEvents()

    def open(self, action="open", restored=True):
        result = _open_result("deferred", "", self.window.executor.seed_folder)
        if restored:
            result["restored"] = True
        self.window._on_ready(action, result)
        self.app.processEvents()

    def grid_words(self):
        return [w.text() for w in self.window.backup_page.findChildren(QLabel)
                if w.text() in _DISPLAY_PHRASE_WORDS.split()]

    def backup_dialog_text(self):
        from wam_regtest import bip39_fusion_gui
        consent = Mock()
        consent.return_value.exec.return_value = 0
        with patch.object(bip39_fusion_gui, "WalletConsent", consent):
            self.window._quick_backup()
        return consent.call_args.args[1]

    def test_first_restored_session_shows_challenge_without_grid_and_restored_copy(self):
        self.open()
        self.assertEqual(self.window.stack.currentWidget(), self.window.backup_page)
        self.assertEqual(self.grid_words(), [])
        self.assertEqual(self.window.status.text(), ENGLISH["wallet.backup_explanation_restored"])
        self.assertIn("backup_challenge", self.window.executor.requests)
        self.assertEqual(self.backup_dialog_text(), ENGLISH["wallet.backup_explanation_restored"])
        words = _DISPLAY_PHRASE_WORDS.split()
        for edit, position in zip(_find_line_edits(self.window.backup_page),
                                  self.window.backup_page._challenge_positions):
            edit.setText(words[position - 1])
        _find_button(self.window.backup_page, "Verify").click()
        self.app.processEvents()
        self.assertTrue(self.window.executor.verified)

    def test_generic_deferred_copy_after_unlock_or_restart(self):
        self.open()
        self.window._on_ready("lock", None)
        self.app.processEvents()
        self.open(action="unlock", restored=False)
        self.assertNotEqual(self.window.status.text(), ENGLISH["wallet.backup_explanation_restored"])
        self.assertEqual(self.backup_dialog_text(), CATALOG["en"]["wallet.backup_explanation"])
        self.window._on_ready("lock", None)
        self.app.processEvents()
        self.open(restored=False)  # a restart reopen never carries restored=True
        self.assertNotEqual(self.window.status.text(), ENGLISH["wallet.backup_explanation_restored"])
        self.assertEqual(self.backup_dialog_text(), CATALOG["en"]["wallet.backup_explanation"])

    def test_recovery_page_always_shows_the_scope_notice_under_the_subtitle(self):
        notice = self.window.restore_scope_notice
        self.assertEqual(notice.text(), ENGLISH["wallet.restore_scope_notice"])
        layout = notice.parentWidget().layout()
        widgets = [layout.itemAt(i).widget() for i in range(layout.count())]
        subtitle = [w for w in widgets if isinstance(w, QLabel)
                    and w.text() == CATALOG["en"]["wallet.recovery_subtitle"]]
        self.assertEqual(len(subtitle), 1)  # panel() keeps the subtitle in this layout
        # Directly under the recovery subtitle, before the recovery action.
        self.assertEqual(widgets.index(notice), widgets.index(subtitle[0]) + 1)
        self.assertLess(widgets.index(notice), widgets.index(self.window.recovery))
        self.open(restored=False)
        self.assertEqual(self.window.restore_scope_notice.text(), ENGLISH["wallet.restore_scope_notice"])


if __name__ == "__main__":
    unittest.main()
