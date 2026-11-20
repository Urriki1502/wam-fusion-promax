"""Public real-Core startup denial, plus the internal F-06 category.

No real Core. A startup that never returns a dict raises
CORE_STARTUP_NO_ANSWER_DENIED. A dict whose chain is not regtest raises
CORE_WRONG_CHAIN_DENIED. The startup deadline parameter stays 120 seconds.
The foundation diagnostic records which of the two happened. Fakes advance
the clock, so the test does not wait.
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


class WrongChainDenial(unittest.TestCase):
    def test_startup_timeout_parameter_stays_120_seconds(self):
        self.assertEqual(inspect.signature(smoke_real_core).parameters['timeout'].default, 120)

    def test_no_dict_answer_before_timeout_raises_no_answer_denied(self):
        seen, clock = self._deny(None, 'CORE_RPC_NO_ANSWER', 'CORE_STARTUP_NO_ANSWER_DENIED')
        probes = [(cmd[-1], timeout) for cmd, timeout in seen if cmd[-1] == 'getblockchaininfo']
        self.assertTrue(probes)
        self.assertTrue(all(timeout == 5 for _, timeout in probes))
        self.assertEqual(clock['now'], 120.0)
        self.assertEqual(seen[-1][0][-1], 'stop')
        self.assertEqual(seen[-1][1], 8)

    def test_non_regtest_chain_answer_raises_wrong_chain_denied(self):
        seen, clock = self._deny(
            {'chain': 'main', 'blocks': 0}, 'CORE_WRONG_CHAIN', 'CORE_WRONG_CHAIN_DENIED')
        self.assertEqual(
            [(cmd[-1], timeout) for cmd, timeout in seen if cmd[-1] == 'getblockchaininfo'],
            [('getblockchaininfo', 5)])
        self.assertEqual(clock['now'], 0.0)
        self.assertEqual(seen[-1][0][-1], 'stop')
        self.assertEqual(seen[-1][1], 8)

    def _deny(self, answer, category, code):
        diagnostics.clear()
        seen = []
        clock = {'now': 0.0}

        def read_cli(cmd, timeout=15):
            seen.append((list(cmd), timeout))
            if cmd[-1] == 'getblockchaininfo':
                return answer
            return None

        def monotonic():
            return clock['now']

        def sleep(seconds):
            clock['now'] += seconds

        ports = iter((18443, 18444))
        with tempfile.TemporaryDirectory(prefix='wam-pm008-') as temp, \
                patch(_SMOKE + '.verified_core_paths',
                      return_value=(Path('/unused/wamd'), Path('/unused/wam-cli'), {})), \
                patch(_SMOKE + '.private_temporary_directory',
                      return_value=_Temporary(temp)), \
                patch(_SMOKE + '._port', side_effect=lambda: next(ports)), \
                patch(_SMOKE + '._write_private_config'), \
                patch(_SMOKE + '._read_cli', side_effect=read_cli), \
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
        self.assertEqual(
            [(item.stage, item.category, item.open_stage) for item in diagnostics.records()],
            [('CORE_SMOKE_STARTUP', category, None)])
        return seen, clock


class _Temporary:
    """Stand-in for private_temporary_directory's context manager."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self.path

    def __exit__(self, *args):
        return False


if __name__ == '__main__':
    unittest.main()
