"""PM-095: startup poll records each public token and names a scope fault.

No real Core. A swallowed CoreSmokeError during the 120 second getblockchaininfo
poll must leave only a validated public token in foundation.diagnostics. A
timeout after a non-bootstrap token raises CORE_STARTUP_SCOPE_FAULTED_DENIED
and keeps that first token. A timeout with no such token raises
CORE_STARTUP_NO_ANSWER_DENIED. A real non-regtest answer stays
CORE_WRONG_CHAIN_DENIED. The deadline stays 120 seconds. Fakes advance the
clock, so the test does not wait.
"""
import inspect
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from wam_regtest.core import CoreSmokeError
from wam_regtest.foundation import diagnostics
from wam_regtest.qualification.real_core_smoke import smoke_real_core

_SMOKE = 'wam_regtest.qualification.real_core_smoke'
_SECRET = '/Users/secret/wallet.dat'


class _Proc:
    def __init__(self, *args, **kwargs):
        self.args = args
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


class StartupPollDiagnostics(unittest.TestCase):
    def test_timeout_parameter_stays_120_seconds(self):
        self.assertEqual(
            inspect.signature(smoke_real_core).parameters['timeout'].default, 120)

    def test_each_attempt_records_a_public_token_and_scope_fault_keeps_the_first(self):
        calls = {'n': 0}

        def read_cli(cmd, timeout=15):
            if cmd[-1] != 'getblockchaininfo':
                return None
            calls['n'] += 1
            if calls['n'] == 1:
                raise CoreSmokeError('CORE_RPC_UNAVAILABLE')
            if calls['n'] == 2:
                raise CoreSmokeError('CORE_RPC_PROCESS_IDENTITY_DENIED')
            raise CoreSmokeError('CORE_RPC_SCOPE_FAULTED')

        self._run(read_cli, 'CORE_STARTUP_SCOPE_FAULTED_DENIED')
        rows = [(item.stage, item.category) for item in diagnostics.records()]
        # The diagnostic ring is 64 records. Two hundred attempts evict the
        # opening rows; the closing summary restates the first faulting token.
        self.assertIn(('CORE_SMOKE_STARTUP_ATTEMPT', 'CORE_RPC_SCOPE_FAULTED'), rows)
        self.assertNotIn(('CORE_SMOKE_STARTUP_ATTEMPT', 'CORE_RPC_UNAVAILABLE'), rows)
        self.assertEqual(rows[-1], ('CORE_SMOKE_STARTUP', 'CORE_RPC_PROCESS_IDENTITY_DENIED'))

    def test_credential_token_then_scope_fault_keeps_the_credential_token(self):
        calls = {'n': 0}

        def read_cli(cmd, timeout=15):
            if cmd[-1] != 'getblockchaininfo':
                return None
            calls['n'] += 1
            if calls['n'] == 1:
                raise CoreSmokeError('CORE_RPC_CREDENTIAL_CHANGED_OR_UNSAFE')
            raise CoreSmokeError('CORE_RPC_SCOPE_FAULTED')

        self._run(read_cli, 'CORE_STARTUP_SCOPE_FAULTED_DENIED')
        rows = [(item.stage, item.category) for item in diagnostics.records()]
        self.assertEqual(
            rows[-1], ('CORE_SMOKE_STARTUP', 'CORE_RPC_CREDENTIAL_CHANGED_OR_UNSAFE'))

    def test_credential_rewrite_without_scope_fault_is_no_answer(self):
        def read_cli(cmd, timeout=15):
            if cmd[-1] == 'getblockchaininfo':
                raise CoreSmokeError('CORE_RPC_CREDENTIAL_CHANGED_OR_UNSAFE')
            return None

        self._run(read_cli, 'CORE_STARTUP_NO_ANSWER_DENIED')
        rows = [(item.stage, item.category) for item in diagnostics.records()]
        self.assertIn(
            ('CORE_SMOKE_STARTUP_ATTEMPT', 'CORE_RPC_CREDENTIAL_CHANGED_OR_UNSAFE'), rows)
        self.assertEqual(rows[-1], ('CORE_SMOKE_STARTUP', 'CORE_RPC_NO_ANSWER'))

    def test_bootstrap_only_timeout_is_no_answer(self):
        def read_cli(cmd, timeout=15):
            if cmd[-1] == 'getblockchaininfo':
                raise CoreSmokeError('CORE_RPC_UNAVAILABLE')
            return None

        self._run(read_cli, 'CORE_STARTUP_NO_ANSWER_DENIED')
        rows = [(item.stage, item.category) for item in diagnostics.records()]
        self.assertTrue(all(category == 'CORE_RPC_UNAVAILABLE'
                            for stage, category in rows
                            if stage == 'CORE_SMOKE_STARTUP_ATTEMPT'))
        self.assertEqual(rows[-1], ('CORE_SMOKE_STARTUP', 'CORE_RPC_NO_ANSWER'))

    def test_non_regtest_answer_stays_wrong_chain(self):
        def read_cli(cmd, timeout=15):
            if cmd[-1] == 'getblockchaininfo':
                return {'chain': 'main', 'blocks': 0}
            return None

        seen = self._run(read_cli, 'CORE_WRONG_CHAIN_DENIED')
        self.assertEqual(
            [(cmd[-1], timeout) for cmd, timeout in seen if cmd[-1] == 'getblockchaininfo'],
            [('getblockchaininfo', 5)])
        self.assertEqual(
            [(item.stage, item.category) for item in diagnostics.records()],
            [('CORE_SMOKE_STARTUP', 'CORE_WRONG_CHAIN')])

    def test_hostile_attempt_text_is_not_recorded(self):
        def read_cli(cmd, timeout=15):
            if cmd[-1] == 'getblockchaininfo':
                raise CoreSmokeError(_SECRET)
            return None

        self._run(read_cli, 'CORE_STARTUP_SCOPE_FAULTED_DENIED')
        blob = repr(diagnostics.records())
        self.assertNotIn(_SECRET, blob)
        self.assertNotIn('secret', blob)
        self.assertNotIn('wallet', blob)
        rows = [(item.stage, item.category) for item in diagnostics.records()]
        self.assertIn(('CORE_SMOKE_STARTUP_ATTEMPT', 'CORE_SMOKE_ATTEMPT_UNPRINTABLE'), rows)
        self.assertEqual(rows[-1], ('CORE_SMOKE_STARTUP', 'CORE_SMOKE_ATTEMPT_UNPRINTABLE'))

    def _run(self, read_cli, code):
        diagnostics.clear()
        seen = []
        clock = {'now': 0.0}

        def wrapped(cmd, timeout=15):
            seen.append((list(cmd), timeout))
            return read_cli(cmd, timeout)

        def monotonic():
            return clock['now']

        def sleep(seconds):
            clock['now'] += seconds

        ports = iter((18443, 18444))
        with tempfile.TemporaryDirectory(prefix='wam-pm095-') as temp, \
                patch(_SMOKE + '.verified_core_paths',
                      return_value=(Path('/unused/wamd'), Path('/unused/wam-cli'), {})), \
                patch(_SMOKE + '.private_temporary_directory',
                      return_value=_Temporary(temp)), \
                patch(_SMOKE + '._port', side_effect=lambda: next(ports)), \
                patch(_SMOKE + '._write_private_config'), \
                patch(_SMOKE + '._read_cli', side_effect=wrapped), \
                patch(_SMOKE + '.subprocess.Popen', side_effect=_Proc), \
                patch(_SMOKE + '.time.monotonic', side_effect=monotonic), \
                patch(_SMOKE + '.time.sleep', side_effect=sleep), \
                patch('wam_regtest.rpc_scope.register'), \
                patch('wam_regtest.rpc_scope.unregister'):
            with self.assertRaises(CoreSmokeError) as caught:
                smoke_real_core(Path('/unused-core'), explicit_consent=True)
        self.assertEqual(caught.exception.args, (code,))
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(str(caught.exception), code)
        self.assertNotIn(_SECRET, str(caught.exception))
        self.assertEqual(clock['now'], 120.0 if code != 'CORE_WRONG_CHAIN_DENIED' else 0.0)
        return seen


class _Temporary:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self.path

    def __exit__(self, *args):
        return False


if __name__ == '__main__':
    unittest.main()
