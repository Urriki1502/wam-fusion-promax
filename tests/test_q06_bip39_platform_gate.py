"""Windows/Linux Q06 frozen qualification refuses source and scope bypass.

These are source-only denial checks. Real-Core, frozen Qt and native witness
acceptance must run inside the final OS-specific package, not this suite.
"""
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wam_regtest import q06_platform_probe as platform_probe
from wam_regtest.q06_platform_probe import (
    Q06PlatformQualificationError, qualify)
from wam_regtest.qualification import valid_optional_failure_exception
from wam_regtest.wallet_executor import WalletExecutorError


class Q06NativePlatformScope(unittest.TestCase):
    def test_source_import_never_grants_frozen_core_qualification(self):
        with tempfile.TemporaryDirectory(prefix="q06-platform-source-") as t:
            parent=Path(t).resolve()
            with self.assertRaisesRegex(
                    Q06PlatformQualificationError,
                    "Q06_PLATFORM_SCOPE_DENIED"):
                qualify(
                    parent/"untrusted-core", parent/"wsp",
                    parent/("wam-fusion-core-"+"a"*16),
                    parent/"receipt.json", confirmed=True)

    def test_windows_native_read_scanners_use_approved_acl_runtime_name(self):
        # Structural regression only; REAL Windows ACL/Qt/Core acceptance is
        # separately required from the final executable on Windows CI.
        import inspect
        from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend
        from wam_regtest.bip39_recovery_proof import verify_mnemonic_on_original_chain
        for function in (Bip39ReadOnlyBackend._scan_q06,
                         verify_mnemonic_on_original_chain):
            source=inspect.getsource(function)
            self.assertIn('"wallet-runtime.sqlite"', source)
            self.assertNotIn('"wallet.sqlite"', source)
            self.assertIn('if sys.platform == "win32":', source)
            self.assertIn('create_managed_runtime(', source)
            self.assertLess(source.index('create_managed_runtime('),
                            source.index('Scanner(', source.index('create_managed_runtime(')))
        from wam_regtest.bip39_spend_session import open_owned_spend_session
        spend=inspect.getsource(open_owned_spend_session)
        self.assertIn('create_managed_runtime(', spend)

    def test_missing_explicit_regtest_consent_denied_without_creating_profile(self):
        with tempfile.TemporaryDirectory(prefix="q06-platform-no-consent-") as t:
            parent=Path(t).resolve()
            profile=parent/("wam-fusion-core-"+"b"*16)
            with self.assertRaises(Q06PlatformQualificationError):
                qualify(parent/"core",parent/"source",profile,
                        parent/"proof.json",confirmed=False)
            self.assertFalse(profile.exists())
            self.assertFalse((parent/"proof.json").exists())

    def _drive_platform_failure(self, exc):
        with tempfile.TemporaryDirectory(prefix="q06-platform-exc-") as t:
            parent = Path(t).resolve()
            fake_adapter = SimpleNamespace(
                platform_id="linux-x86_64",
                official_signed=True,
                enforce_host=lambda: None,
                prepare_trust=lambda *_a, **_kw: (_ for _ in ()).throw(exc),
                teardown=lambda: None,
            )
            with (
                patch.object(sys, "frozen", True, create=True),
                patch.object(sys, "executable", __file__),
                patch.object(platform_probe.platform, "system", return_value="Linux"),
                patch.object(platform_probe, "detect_adapter", return_value=fake_adapter),
                patch.object(platform_probe, "_pinned_source", return_value=None),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                return qualify(
                    parent / "core",
                    parent / "wsp",
                    parent / ("wam-fusion-core-" + "c" * 16),
                    parent / "receipt.json",
                    confirmed=True,
                    headless=True,
                )

    def test_generic_fallback_records_class_name_without_message_or_secret(self):
        record = self._drive_platform_failure(
            BrokenPipeError(32, "/Users/alice/secret-seed-abandon")
        )
        self.assertEqual(record["status"], "FAIL")
        self.assertEqual(record["failure_code"], "Q06_NATIVE_ENGINE_DENIED")
        self.assertEqual(record["failure_exception"], "BrokenPipeError")
        encoded = json.dumps(record)
        self.assertNotIn("/Users/alice", encoded)
        self.assertNotIn("secret-seed-abandon", encoded)

    def test_specific_code_omits_failure_exception(self):
        for exc, code in (
            (Q06PlatformQualificationError("Q06_PLATFORM_TRUST_DENIED"), "Q06_PLATFORM_TRUST_DENIED"),
            (WalletExecutorError("WALLET_LOCKED"), "WALLET_LOCKED"),
        ):
            with self.subTest(code=code):
                record = self._drive_platform_failure(exc)
                self.assertEqual(record["status"], "FAIL")
                self.assertEqual(record["failure_code"], code)
                self.assertNotIn("failure_exception", record)

    def test_optional_failure_exception_validator(self):
        self.assertTrue(valid_optional_failure_exception({"status": "PASS"}))
        self.assertTrue(valid_optional_failure_exception({"failure_exception": None}))
        self.assertTrue(valid_optional_failure_exception({"failure_exception": "BrokenPipeError"}))
        self.assertTrue(valid_optional_failure_exception({"failure_exception": "_" + "a" * 63}))
        for bad in ("", "1abc", "A" * 65, "/tmp/secret", "Bad Error", "Err\n", 123, True):
            self.assertFalse(valid_optional_failure_exception({"failure_exception": bad}), repr(bad))


if __name__=="__main__":
    unittest.main()
