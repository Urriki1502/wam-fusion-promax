"""CORE-SET-01: -nosettings managed argv and post-start policy check."""
from contextlib import ExitStack
from decimal import Decimal
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_q05_core_supervisor as lifecycle_fixture
from wam_regtest import core_process, core_supervisor as module
from wam_regtest.core_process import CoreBindingError, OwnedCoreBinding, managed_core_argv
from wam_regtest.supervisor_store import read_exact

POLICY = {'minrelaytxfee': Decimal('0.00001000'),
          'incrementalrelayfee': Decimal('0.00001000'), 'fullrbf': True}


class HelperContracts(unittest.TestCase):
    def test_helper_darwin_exact_without_defer(self):
        with patch.object(sys, 'platform', 'darwin'):
            self.assertEqual(
                managed_core_argv(Path('/node/wamd'), Path('/data')),
                ['/node/wamd', '-datadir=/data', '-daemon=0', '-nosettings'])

    def test_helper_darwin_exact_with_defer(self):
        with patch.object(sys, 'platform', 'darwin'):
            self.assertEqual(
                managed_core_argv(Path('/node/wamd'), Path('/data'), defer_network=True),
                ['/node/wamd', '-datadir=/data', '-daemon=0', '-nosettings', '-networkactive=0'])

    def test_helper_non_darwin_has_no_nosettings(self):
        for platform in ('linux', 'win32'):
            with self.subTest(platform=platform):
                with patch.object(sys, 'platform', platform):
                    self.assertEqual(
                        managed_core_argv(Path('/node/wamd'), Path('/data')),
                        ['/node/wamd', '-datadir=/data', '-daemon=0'])
                    self.assertEqual(
                        managed_core_argv(Path('/node/wamd'), Path('/data'), defer_network=True),
                        ['/node/wamd', '-datadir=/data', '-daemon=0', '-networkactive=0'])


class BindingContracts(unittest.TestCase):
    def test_binding_refuses_popen_without_nosettings_on_darwin(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            core = root / 'core'
            core.mkdir(mode=0o700)
            node, cli = core / 'wamd', core / 'wam-cli'
            node.write_bytes(b'unit fixture only')
            cli.write_bytes(b'unit fixture only')
            datadir = root / 'chain'
            datadir.mkdir(mode=0o700)

            class Process:
                def __init__(self, args):
                    self.args = args

                def poll(self):
                    return None

            missing = [str(node), f'-datadir={datadir}', '-daemon=0']
            missing_deferred = missing + ['-networkactive=0']
            with patch.object(sys, 'platform', 'darwin'), \
                    patch.object(core_process.subprocess, 'Popen', Process), \
                    patch.object(core_process, 'verified_core_paths', return_value=(node, cli, {})), \
                    patch.object(core_process, '_metadata', return_value=('unit fixture',)):
                for args in (missing, missing_deferred):
                    with self.subTest(args=args):
                        with self.assertRaisesRegex(CoreBindingError, 'RPC_OWNED_PROCESS_REQUIRED'):
                            OwnedCoreBinding(Process(args), core, datadir)


class PolicyContracts(unittest.TestCase):
    setUp = lifecycle_fixture.SupervisorLifecycleUnit.setUp
    owner = lifecycle_fixture.SupervisorLifecycleUnit.owner

    def _setup_start(self, owner, policy):
        stack = ExitStack()
        process = Mock(spec=subprocess.Popen)
        process.pid = 12345
        process.poll.return_value = None
        binding = Mock(spec=OwnedCoreBinding)
        probe = Mock()
        probe.__enter__ = Mock(return_value=probe)
        probe.__exit__ = Mock(return_value=False)
        spawn = stack.enter_context(patch.object(module.subprocess, 'Popen', return_value=process))
        stack.enter_context(patch.object(module, 'OwnedCoreBinding', return_value=binding))
        stack.enter_context(patch.object(module, 'register'))

        def reply(cmd, timeout=None):
            if cmd[-1] == 'getmempoolinfo':
                return policy
            return {'chain': 'regtest'}

        stack.enter_context(patch.object(module, '_read_cli', side_effect=reply))
        stack.enter_context(patch.object(module.socket, 'create_connection', return_value=probe))
        read = Mock()
        read.call.return_value = {'blocks': 101, 'chain': 'regtest'}
        rpc = stack.enter_context(patch.object(module, 'ManagedReadRpc', return_value=read))
        self.addCleanup(lambda p=process: setattr(p, 'poll', Mock(return_value=0)))
        return stack, process, binding, rpc, spawn, read

    def test_policy_accepts_exact_decimal_dict(self):
        owner = self.owner()
        stack, process, binding, rpc, spawn, read = self._setup_start(owner, dict(POLICY))
        with stack:
            owner.start(timeout=1)
        self.assertEqual(owner.state, 'ready')
        self.assertIs(owner.process, process)
        rpc.assert_called_once_with(owner.core, owner.directory,
                                    authorized_readonly=True, binding=binding)

    def test_policy_refuses_each_bad_value(self):
        cases = [
            ('minrelay_0.00005', {'minrelaytxfee': Decimal('0.00005000'),
                                  'incrementalrelayfee': Decimal('0.00001000'), 'fullrbf': True}),
            ('incremental_0.00007', {'minrelaytxfee': Decimal('0.00001000'),
                                     'incrementalrelayfee': Decimal('0.00007000'), 'fullrbf': True}),
            ('fullrbf_false', {'minrelaytxfee': Decimal('0.00001000'),
                               'incrementalrelayfee': Decimal('0.00001000'), 'fullrbf': False}),
            ('float_fee', {'minrelaytxfee': 0.00001,
                           'incrementalrelayfee': Decimal('0.00001000'), 'fullrbf': True}),
            ('string_fee', {'minrelaytxfee': '0.00001000',
                            'incrementalrelayfee': Decimal('0.00001000'), 'fullrbf': True}),
            ('missing_key', {'minrelaytxfee': Decimal('0.00001000'), 'fullrbf': True}),
            ('non_dict', ['minrelaytxfee']),
        ]
        for index, (name, policy) in enumerate(cases):
            with self.subTest(case=name):
                self.root = self.root.parent / f'wam-fusion-core-{index + 300:016x}'
                self.create_private_directory(self.root)
                owner = self.owner()
                stack, process, binding, rpc, spawn, read = self._setup_start(owner, policy)
                with stack:
                    with self.assertRaisesRegex(module.ManagedCoreError, 'MANAGED_CORE_POLICY_DENIED'):
                        owner.start(timeout=1)
                    rpc.assert_not_called()
                self.assertEqual(owner.state, 'recovery-needed')
                self.assertIs(owner.process, process)

    def test_policy_denial_records_failure_and_retains_process_unkilled(self):
        owner = self.owner()
        bad = {'minrelaytxfee': Decimal('0.00005000'),
               'incrementalrelayfee': Decimal('0.00001000'), 'fullrbf': True}
        stack, process, binding, rpc, spawn, read = self._setup_start(owner, bad)
        with stack:
            with self.assertRaisesRegex(module.ManagedCoreError, 'MANAGED_CORE_POLICY_DENIED'):
                owner.start(timeout=1)
        self.assertEqual(owner.state, 'recovery-needed')
        self.assertTrue(owner._faulted)
        self.assertIs(owner.process, process)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        self.assertEqual(json.loads(read_exact(owner.root, 'supervisor.failure')),
                         {'stage': 'start', 'code': 'MANAGED_CORE_POLICY_DENIED'})
        with self.assertRaises(module.ManagedCoreError):
            owner.start(timeout=1)
        self.assertEqual(spawn.call_count, 1)


class StaticContracts(unittest.TestCase):
    def test_no_settings_json_string_in_managed_modules(self):
        root = Path(__file__).resolve().parent.parent
        for rel in ('src/wam_regtest/core_supervisor.py', 'src/wam_regtest/core_process.py'):
            with self.subTest(path=rel):
                self.assertNotIn('settings.json', (root / rel).read_text())


if __name__ == '__main__':
    unittest.main()
