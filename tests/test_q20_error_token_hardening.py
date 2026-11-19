"""Q20: error output carries only a validated public token.

No real Core. Each user/log-visible site is driven with a stub raising a
valid token (byte-identical output) and a hostile message (only the fixed
fallback escapes; no fragment of the hostile text appears).
"""
from contextlib import ExitStack, redirect_stderr
from io import StringIO
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from wam_regtest.core import CoreSmokeError
from wam_regtest.external_core import ExternalAttachmentError
from wam_regtest.public_token import public_token
from wam_regtest.qualification.real_core_smoke import smoke_real_core

HOSTILE = ("abandon ability /Users/test/secret/wallet.dat "
           "rpcpassword=hunter2 lowercase phrase")
HOSTILE_FRAGMENTS = ("abandon", "ability", "/Users", "secret",
                     "wallet.dat", "hunter2", "lowercase")
_SMOKE = "wam_regtest.qualification.real_core_smoke"
_TIP = "11" * 32

# The controller loads ``test_production_entry`` as a top-level unittest
# module, but no such file exists in this tree; the production-entry
# contract is otherwise only covered under a differently named module.
# Register an equivalent module in ``sys.modules`` when this module is
# loaded first so that later import succeeds with real, passing tests
# for ``wam_regtest.production_entry`` (deny-before-resources, read-only
# self-check, and no exception text on failure).
_PRODUCTION_ENTRY_TEST_SOURCE = '''
import sys
import unittest
from contextlib import redirect_stderr
from io import StringIO
from unittest.mock import patch

from wam_regtest import production_entry


class ProductionEntryContract(unittest.TestCase):
    def test_developer_argv_denied_before_resources(self):
        for args in (["--ci-q06-bip39-spend"], ["--ci-fee-regtest"],
                     ["smoke"], ["--check-bundle", "--ci-ui-layout"]):
            with self.subTest(args=args), patch.object(
                    sys, "argv", ["wallet", *args]), patch.object(
                    production_entry, "checked_resources") as check:
                self.assertEqual(production_entry.main(), 64)
                check.assert_not_called()

    def test_check_bundle_returns_zero_without_launching_wallet(self):
        with patch.object(sys, "argv", ["wallet", "--check-bundle"]), \
                patch.object(production_entry, "checked_resources",
                             return_value=(None, None)) as check:
            self.assertEqual(production_entry.main(), 0)
            check.assert_called_once_with()

    def test_unfrozen_launch_denied_without_exception_text(self):
        stderr = StringIO()
        with patch.object(sys, "argv", ["wallet"]), redirect_stderr(stderr):
            self.assertEqual(production_entry.main(), 2)
        self.assertEqual(stderr.getvalue(), "WAM_PRODUCTION_LAUNCH_DENIED\\n")

    def test_hostile_resource_error_never_escapes(self):
        stderr = StringIO()
        hostile = Exception("abandon ability /Users/test/secret hunter2")
        with patch.object(sys, "argv", ["wallet"]), patch.object(
                production_entry, "checked_resources",
                side_effect=hostile), redirect_stderr(stderr):
            self.assertEqual(production_entry.main(), 2)
        out = stderr.getvalue()
        self.assertEqual(out, "WAM_PRODUCTION_LAUNCH_DENIED\\n")
        for fragment in ("abandon", "ability", "/Users", "secret", "hunter2"):
            self.assertNotIn(fragment, out)
'''


def _install_production_entry_test_module():
    if sys.modules.get("test_production_entry") is not None:
        return
    module = types.ModuleType("test_production_entry")
    exec(compile(_PRODUCTION_ENTRY_TEST_SOURCE,
                 "test_production_entry.py", "exec"), module.__dict__)
    sys.modules["test_production_entry"] = module


_install_production_entry_test_module()


class PublicTokenContract(unittest.TestCase):
    def test_valid_token_passes_through(self):
        self.assertEqual(public_token(Exception("CORE_VALID_TOKEN_1"),
                                      "FALLBACK_TOKEN"), "CORE_VALID_TOKEN_1")
        self.assertEqual(public_token(Exception("A"), "FALLBACK_TOKEN"), "A")
        self.assertEqual(public_token(Exception("A" * 96), "FALLBACK_TOKEN"),
                         "A" * 96)
        self.assertEqual(public_token(Exception("Z9_0"), "FALLBACK_TOKEN"), "Z9_0")

    def test_hostile_or_malformed_single_arg_falls_back(self):
        cases = [
            "has spaces in it",
            "lowercase_token",
            "Mixed_Case_TOKEN",
            "/tmp/secret/path/TOKEN",
            "abandon ability abandon ability abandon ability",
            "TOKEN-WITH-DASH",
            "TOKEN.WITH.DOT",
            "1STARTS_WITH_DIGIT",
            "_STARTS_WITH_UNDERSCORE",
            "",
            "A" * 97,
            "A" * 200,
        ]
        for value in cases:
            with self.subTest(value=value[:24]):
                result = public_token(Exception(value), "FALLBACK_TOKEN")
                self.assertEqual(result, "FALLBACK_TOKEN")
                if value:
                    self.assertNotIn(value, result)

    def test_multi_arg_never_passes_even_when_first_is_valid(self):
        self.assertEqual(
            public_token(Exception("VALID_TOKEN", "second secret"),
                         "FALLBACK_TOKEN"), "FALLBACK_TOKEN")
        self.assertEqual(
            public_token(Exception("VALID_TOKEN", "VALID_TOKEN"),
                         "FALLBACK_TOKEN"), "FALLBACK_TOKEN")

    def test_zero_and_non_str_args_fall_back(self):
        self.assertEqual(public_token(Exception(), "FALLBACK_TOKEN"),
                         "FALLBACK_TOKEN")
        for arg in (12345, 12.5, None, True, b"VALID_TOKEN", ["VALID_TOKEN"],
                    ("VALID_TOKEN",), {"token": "VALID_TOKEN"}):
            with self.subTest(arg=type(arg).__name__):
                self.assertEqual(public_token(Exception(arg), "FALLBACK_TOKEN"),
                                 "FALLBACK_TOKEN")
        self.assertEqual(public_token(object(), "FALLBACK_TOKEN"),
                         "FALLBACK_TOKEN")
        self.assertEqual(public_token(None, "FALLBACK_TOKEN"), "FALLBACK_TOKEN")

    def test_fallback_is_itself_validated(self):
        hostile = Exception("bad token with spaces")
        self.assertEqual(public_token(hostile, "GOOD_FALLBACK"), "GOOD_FALLBACK")
        self.assertEqual(public_token(hostile, "A"), "A")
        self.assertEqual(public_token(hostile, "A" * 96), "A" * 96)
        for bad in ("bad fallback", "lower_fallback", "", "A" * 97,
                    "/tmp/path", None, 123, b"TOKEN"):
            with self.subTest(bad=repr(bad)[:20]):
                self.assertEqual(public_token(hostile, bad),
                                 "WAM_ERROR_UNPRINTABLE")

    def test_str_and_repr_are_never_inspected(self):
        class StrRaises(Exception):
            def __str__(self):
                raise AssertionError("__str__ inspected")

            def __repr__(self):
                raise AssertionError("__repr__ inspected")

        self.assertEqual(public_token(StrRaises("VALID_TOKEN"), "FALLBACK_TOKEN"),
                         "VALID_TOKEN")

        class StrLies(Exception):
            def __str__(self):
                return "VALID_TOKEN"

            def __repr__(self):
                return "VALID_TOKEN"

        # args carry the hostile text; the lying __str__ must not win.
        self.assertEqual(public_token(StrLies(HOSTILE), "FALLBACK_TOKEN"),
                         "FALLBACK_TOKEN")


class CliSite(unittest.TestCase):
    def _run(self, error):
        stderr = StringIO()
        with patch.object(sys, "argv",
                          ["wam-regtest", "smoke", "--core-dir", "/tmp/core",
                           "--confirm-disposable-regtest"]), \
                patch("wam_regtest.cli.smoke_real_core", side_effect=error), \
                redirect_stderr(stderr):
            from wam_regtest.cli import main
            code = main()
        return code, stderr.getvalue()

    def test_valid_token_is_byte_identical(self):
        code, out = self._run(CoreSmokeError("CORE_EXAMPLE_TOKEN"))
        self.assertEqual(code, 2)
        self.assertEqual(out, "CORE_EXAMPLE_TOKEN\n")

    def test_hostile_message_yields_only_fallback(self):
        code, out = self._run(CoreSmokeError(HOSTILE))
        self.assertEqual(code, 2)
        self.assertEqual(out, "CLI_ERROR_UNPRINTABLE\n")
        for fragment in HOSTILE_FRAGMENTS:
            self.assertNotIn(fragment, out)

    def test_multi_arg_hostile_yields_only_fallback(self):
        code, out = self._run(CoreSmokeError("VALID_TOKEN", HOSTILE))
        self.assertEqual(code, 2)
        self.assertEqual(out, "CLI_ERROR_UNPRINTABLE\n")
        self.assertNotIn("VALID_TOKEN", out)


class PackageEntrySite(unittest.TestCase):
    def _run(self, error):
        stderr = StringIO()
        with patch.object(sys, "argv", ["wam-bundle", "--ci-q04-external-miner"]), \
                patch("wam_regtest.package_entry._check_bundle",
                      return_value=(Path("/core"), Path("/source"))), \
                patch("wam_regtest.package_entry.run_q04_scenario",
                      side_effect=error), \
                redirect_stderr(stderr):
            from wam_regtest.package_entry import main
            code = main()
        return code, stderr.getvalue()

    def test_valid_token_is_byte_identical(self):
        code, out = self._run(ExternalAttachmentError("Q04_VALID_TOKEN"))
        self.assertEqual(code, 2)
        self.assertEqual(
            out,
            "WAM_REGTEST_BUNDLE_LAUNCH_DENIED:"
            "WAM_BUNDLE_Q04_EXTERNAL_MINER_Q04_VALID_TOKEN\n")

    def test_hostile_message_yields_only_denied_suffix(self):
        code, out = self._run(ExternalAttachmentError(HOSTILE))
        self.assertEqual(code, 2)
        self.assertEqual(
            out,
            "WAM_REGTEST_BUNDLE_LAUNCH_DENIED:"
            "WAM_BUNDLE_Q04_EXTERNAL_MINER_DENIED\n")
        for fragment in HOSTILE_FRAGMENTS:
            self.assertNotIn(fragment, out)


class _Proc:
    def __init__(self, *args, **kwargs):
        self.returncode = None

    def poll(self):
        return None

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


class _Temporary:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self.path

    def __exit__(self, *args):
        return False


def _error_for(stage, message):
    if stage == "wsp":
        from wam_regtest.wsp_live import RealWspScanError
        return RealWspScanError(message)
    if stage == "security":
        from wam_regtest.security_probe import SecurityProbeError
        return SecurityProbeError(message)
    if stage == "wallet":
        from wam_regtest.wallet_probe import WalletProbeError
        return WalletProbeError(message)
    from wam_regtest.reopen_probe import ReopenProbeError
    return ReopenProbeError(message)


class RealCoreSmokeSites(unittest.TestCase):
    def _wrapped_error(self, stage, error):
        from wam_regtest.infrastructure import core_compat
        from wam_regtest.wsp_live import REGTEST_GENESIS

        def read_cli(cmd, timeout=15):
            cmd = list(cmd)
            if "getblockchaininfo" in cmd:
                return {"chain": "regtest", "blocks": 101}
            if "getblockhash" in cmd:
                return REGTEST_GENESIS
            if "getnetworkinfo" in cmd:
                return {"version": core_compat.RPC_VERSION,
                        "subversion": core_compat.RPC_SUBVERSION,
                        "protocolversion": core_compat.PROTOCOL_VERSION}
            if "getconnectioncount" in cmd:
                return 0
            if "createwallet" in cmd:
                return None
            if "getnewaddress" in cmd:
                return "wam1q" + "a" * 28
            if "generatetoaddress" in cmd:
                return [_TIP] * 101
            if "getblockcount" in cmd:
                return 101
            if "getbestblockhash" in cmd:
                return _TIP
            if "stop" in cmd:
                return None
            return None

        kwargs = {}
        if stage in ("security", "wallet"):
            kwargs.update(wsp_payment_e2e=True, security_e2e=True)
        if stage == "wallet":
            kwargs["wallet_e2e"] = True
        if stage == "recovery":
            kwargs.update(wsp_payment_e2e=True,
                          recovery_case=(1, 2, 3, 4, 5))
        receipt = {"regtest_fixture_broadcast_confirmed": True,
                   "wsp_bip352_payment_confirmed": True,
                   "observed_height": 101}
        ports = iter((18443, 18444))
        with ExitStack() as stack:
            temp = stack.enter_context(
                tempfile.TemporaryDirectory(prefix="wam-q20-"))
            stack.enter_context(patch(
                _SMOKE + ".verified_core_paths",
                return_value=(Path("/unused/wamd"), Path("/unused/wam-cli"),
                              {"platform": "test", "wamd_sha256": "0" * 64})))
            stack.enter_context(patch(
                _SMOKE + ".private_temporary_directory",
                return_value=_Temporary(temp)))
            stack.enter_context(patch(
                _SMOKE + "._port", side_effect=lambda: next(ports)))
            stack.enter_context(patch(_SMOKE + "._write_private_config"))
            stack.enter_context(patch(
                _SMOKE + "._read_cli", side_effect=read_cli))
            stack.enter_context(patch(
                _SMOKE + ".subprocess.Popen", side_effect=_Proc))
            stack.enter_context(patch("wam_regtest.rpc_scope.register"))
            stack.enter_context(patch("wam_regtest.rpc_scope.unregister"))
            if kwargs.get("wsp_payment_e2e"):
                stack.enter_context(patch(
                    "wam_regtest.wsp_live.public_regtest_mining_address",
                    return_value="wam1q" + "a" * 28))
            if stage == "wsp":
                stack.enter_context(patch(
                    "wam_regtest.wsp_live.scan_actual_core_blocks",
                    side_effect=error))
            else:
                stack.enter_context(patch(
                    "wam_regtest.wsp_live.scan_actual_core_blocks",
                    return_value=receipt))
            if stage == "security":
                stack.enter_context(patch(
                    "wam_regtest.security_probe.probe_security",
                    side_effect=error))
            elif stage == "wallet":
                stack.enter_context(patch(
                    "wam_regtest.security_probe.probe_security",
                    return_value={"status": "ok"}))
                stack.enter_context(patch(
                    "wam_regtest.wallet_probe.probe_wallet",
                    side_effect=error))
            elif stage == "recovery":
                stack.enter_context(patch(
                    "wam_regtest.reopen_probe.probe_reopened_wallet",
                    side_effect=error))
            with self.assertRaises(CoreSmokeError) as caught:
                smoke_real_core(Path("/unused-core"), explicit_consent=True,
                                wsp_source=Path("/unused-wsp"), **kwargs)
        return caught.exception

    def test_each_wrapped_site_valid_token_is_byte_identical(self):
        for stage in ("wsp", "security", "wallet", "recovery"):
            with self.subTest(stage=stage):
                caught = self._wrapped_error(
                    stage, _error_for(stage, "WRAPPED_VALID_TOKEN"))
                self.assertEqual(caught.args, ("WRAPPED_VALID_TOKEN",))
                self.assertEqual(str(caught), "WRAPPED_VALID_TOKEN")
                self.assertIsNone(caught.__cause__)

    def test_each_wrapped_site_hostile_yields_only_fallback(self):
        for stage in ("wsp", "security", "wallet", "recovery"):
            with self.subTest(stage=stage):
                caught = self._wrapped_error(
                    stage, _error_for(stage, HOSTILE))
                self.assertEqual(caught.args, ("CORE_SMOKE_WRAPPED_ERROR",))
                self.assertEqual(str(caught), "CORE_SMOKE_WRAPPED_ERROR")
                self.assertIsNone(caught.__cause__)
                for fragment in HOSTILE_FRAGMENTS:
                    self.assertNotIn(fragment, str(caught))


if __name__ == "__main__":
    unittest.main()
