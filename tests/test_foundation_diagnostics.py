"""PM-003 / R1: internal diagnostic context (audit F-05, invariant I-13).

The public refusal codes are unchanged (see test_characterization_r0). These
tests prove the new internal record keeps only fixed tokens and classifies the
underlying failure that fail-closed wrappers drop.
"""
import ast
import io
import os
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from wam_regtest.foundation import diagnostics

SECRETS = (
    'abandon ability able about above absent absorb abstract absurd abuse access accident',
    'correct-horse-battery-staple', '/Users/someone/wallet/profile', 'rpcpassword=hunter2',
    'b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d',
)


class StorageError(Exception):
    pass


class TokenRules(unittest.TestCase):
    def setUp(self):
        diagnostics.clear()

    def test_category_is_a_code_token_or_class_name_never_text(self):
        self.assertEqual(diagnostics.category_of(ValueError('Q06_PENDING_BROADCAST_UNVERIFIED')),
                         'Q06_PENDING_BROADCAST_UNVERIFIED')
        self.assertEqual(diagnostics.category_of(StorageError('DATABASE_BUSY_OR_CORRUPT')),
                         'DATABASE_BUSY_OR_CORRUPT')
        self.assertEqual(diagnostics.category_of(TimeoutError()), 'TimeoutError')
        self.assertEqual(diagnostics.category_of(None), 'NONE')
        for secret in SECRETS:
            with self.subTest(secret=secret):
                self.assertEqual(diagnostics.category_of(ValueError(secret)), 'ValueError')
                self.assertEqual(diagnostics.category_of(OSError(5, secret)), 'OSError')
        # Two args (even if the first is a code) never pass text through.
        self.assertEqual(diagnostics.category_of(ValueError('CODE', SECRETS[0])), 'ValueError')
        # PEER-039 hardening: all-caps password-shaped words, upper-case hex and
        # hex-bearing class names never pass as categories.
        for raw in ('HUNTER2', 'PASSWORD', 'B88F3D262F285E38E184F50BF3EEA1C8E615486AE67D3D9EAF0976FBD6D3D30D',
                    'TX_B88F3D262F285E38E184', '12345678', 'A_0123456789ABCDEF0'):
            with self.subTest(raw=raw):
                self.assertEqual(diagnostics.category_of(ValueError(raw)), 'ValueError')
        hexname = type('b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d', (Exception,), {})
        self.assertEqual(diagnostics.category_of(hexname()), 'INTERNAL')
        lower = type('custom_error', (Exception,), {})
        self.assertEqual(diagnostics.category_of(lower()), 'INTERNAL')
        self.assertEqual(diagnostics.record('STAGE_0123456789ABCDEF').stage, 'INVALID_STAGE')

    def test_stage_must_be_a_literal_token(self):
        self.assertEqual(diagnostics.record('UNLOCK_ACTIVATION').stage, 'UNLOCK_ACTIVATION')
        for bad in ('unlock', SECRETS[2], 'A' * 65, 42, None, 'BAD STAGE'):
            with self.subTest(bad=bad):
                self.assertEqual(diagnostics.record(bad).stage, 'INVALID_STAGE')
        self.assertIsNone(diagnostics.record('S', open_stage=SECRETS[1]).open_stage)
        self.assertEqual(diagnostics.record('S', open_stage='PENDING_BROADCAST_RECOVERY').open_stage,
                         'PENDING_BROADCAST_RECOVERY')

    def test_innermost_cause_and_open_stage_survive_wrappers(self):
        try:
            try:
                raise StorageError('DATABASE_BUSY_OR_CORRUPT')
            except StorageError as inner:
                outer = ValueError('Q06_SPEND_OPEN_DENIED')
                outer.open_stage = 'PENDING_BROADCAST_RECOVERY'
                raise outer from inner
        except ValueError as error:
            item = diagnostics.record('UNLOCK_ACTIVATION', error)
        self.assertEqual(item.category, 'DATABASE_BUSY_OR_CORRUPT')
        self.assertEqual(item.open_stage, 'PENDING_BROADCAST_RECOVERY')
        # `from None` suppression is respected: the wrapper is what is visible.
        try:
            try:
                raise StorageError(SECRETS[1])
            except StorageError:
                raise ValueError('Q06_GUI_SPEND_ACTIVATION_DENIED') from None
        except ValueError as error:
            self.assertEqual(diagnostics.record('X', error).category, 'Q06_GUI_SPEND_ACTIVATION_DENIED')

    def test_records_are_bounded_immutable_and_never_raise(self):
        for _ in range(200):
            diagnostics.record('STAGE')
        items = diagnostics.records()
        self.assertEqual(len(items), 64)
        self.assertIsInstance(items, tuple)
        with self.assertRaises(AttributeError):
            items[0].stage = 'OTHER'

        class Hostile(Exception):
            @property
            def args(self):
                raise RuntimeError('boom')
        self.assertIsNone(diagnostics.record('STAGE', Hostile()))

    def test_concurrent_records_are_all_kept(self):
        diagnostics.clear()
        threads = [threading.Thread(target=lambda: [diagnostics.record('T') for _ in range(5)])
                   for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(diagnostics.records()), 40)

    def test_stderr_only_with_explicit_opt_in_and_only_tokens(self):
        for value, expect in ((None, False), ('0', False), ('true', False), ('1', True)):
            with self.subTest(value=value), patch.dict(os.environ):
                os.environ.pop('WAM_INTERNAL_DIAGNOSTICS', None)
                if value is not None:
                    os.environ['WAM_INTERNAL_DIAGNOSTICS'] = value
                err, out = io.StringIO(), io.StringIO()
                with redirect_stderr(err), redirect_stdout(out):
                    diagnostics.record('UNLOCK_ACTIVATION', ValueError(SECRETS[0]), open_stage='SEED_AUTH')
                self.assertEqual(out.getvalue(), '')
                self.assertEqual(bool(err.getvalue()), expect)
                if expect:
                    self.assertEqual(err.getvalue(),
                                     'WAM_DIAG stage=UNLOCK_ACTIVATION category=ValueError open_stage=SEED_AUTH\n')
                for secret in SECRETS:
                    self.assertNotIn(secret, err.getvalue())


class FoundationLayerRule(unittest.TestCase):
    def test_foundation_imports_nothing_from_wam_regtest_and_no_qt(self):
        import ast
        root = Path(__file__).resolve().parents[1] / 'src/wam_regtest/foundation'
        for path in sorted(root.rglob('*.py')):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse(node.level > 0 or (node.module or '').startswith(('wam_regtest', 'PySide6')),
                                     '%s: %s' % (path.name, node.module))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(alias.name.startswith(('wam_regtest', 'PySide6')), path.name)


# Explicit wam_regtest import allowlist. Anything else, including
# PySide6, presentation, qualification, bip39_owner_backend and
# wallet_executor, fails. Stdlib imports are not layer edges.
_DOMAIN_EXACT = frozenset({
    'private_directory',
    'linux_private_storage',
    'windows_private_storage',
    'bip39_seed_vault',
    # payment_evidence seals through the existing custody module.
    'custody',
})


def _layer_modules(node, package):
    """wam_regtest module names (and any PySide6 import) from one statement."""
    found = []
    if isinstance(node, ast.Import):
        names = [alias.name for alias in node.names]
        relative = False
        modules = names
    elif isinstance(node, ast.ImportFrom):
        relative = node.level > 0
        module = node.module or ''
        if node.level == 0 and module == 'wam_regtest':
            modules = [alias.name.split('.')[0] for alias in node.names]
        elif node.level == 1:
            modules = [package + ('.' + module if module else '')]
        elif node.level > 1:
            modules = [module or '__init__']
        else:
            modules = [module]
    else:
        return found
    for name in modules:
        if not name:
            continue
        if name == 'PySide6' or name.startswith('PySide6.'):
            found.append(name)
        elif name.startswith('wam_regtest.'):
            found.append(name.split('.', 1)[1])
        elif relative or name.startswith(('domain.', 'application.', 'foundation.')) or name in (
                'domain', 'application', 'foundation'):
            found.append(name)
    return found


def _prefix_allowed(name, root):
    return name == root or name.startswith(root + '.')


def _domain_import_allowed(name):
    if _prefix_allowed(name, 'foundation') or _prefix_allowed(name, 'domain'):
        return True
    return name in _DOMAIN_EXACT


def _application_import_allowed(name):
    return (_prefix_allowed(name, 'foundation') or _prefix_allowed(name, 'domain')
            or _prefix_allowed(name, 'application'))


class DomainApplicationLayerRule(unittest.TestCase):
    """domain/ and application/ may import only their allowlisted layers."""

    def _modules(self, package):
        root = Path(__file__).resolve().parents[1] / 'src/wam_regtest' / package
        found = []
        for path in sorted(root.rglob('*.py')):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                for name in _layer_modules(node, package):
                    found.append((path.name, name))
        return found

    def test_domain_imports_only_the_allowlist(self):
        for filename, name in self._modules('domain'):
            self.assertTrue(_domain_import_allowed(name),
                            'domain/%s imports %s' % (filename, name))

    def test_application_imports_only_the_allowlist(self):
        for filename, name in self._modules('application'):
            self.assertTrue(_application_import_allowed(name),
                            'application/%s imports %s' % (filename, name))

    def test_owner_backend_reexports_the_domain_error(self):
        from wam_regtest.bip39_owner_backend import Q06ReadOnlyError as exported
        from wam_regtest.domain.errors import Q06ReadOnlyError as defined
        self.assertIs(exported, defined)
        self.assertTrue(issubclass(defined, ValueError))

    def test_payment_state_imports_only_stdlib_or_foundation(self):
        path = Path(__file__).resolve().parents[1] / 'src/wam_regtest/domain/payment_state.py'
        tree = ast.parse(path.read_text())
        found = [name for node in ast.walk(tree) for name in _layer_modules(node, 'domain')]
        for name in found:
            self.assertTrue(_domain_import_allowed(name), name)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ''
                self.assertFalse(module.startswith('wam_sp'), module)
                self.assertFalse(module.startswith('PySide6'), module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertFalse(alias.name.startswith(('wam_sp', 'PySide6', 'wam_regtest')))
        self.assertIn('payment_state.py', path.name)

    def test_payment_evidence_imports_only_custody_and_wsp_keystore(self):
        """PM-012. Exact modules: stdlib json/os/re, wam_regtest.custody, wam_sp.keystore, wam_sp.psbt."""
        path = Path(__file__).resolve().parents[1] / 'src/wam_regtest/domain/payment_evidence.py'
        tree = ast.parse(path.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, path.name)
                module = node.module or ''
                if module == 'wam_regtest':
                    imported.update('wam_regtest.' + alias.name for alias in node.names)
                else:
                    imported.add(module)
        self.assertEqual(imported, {
            'json', 'os', 're',
            'wam_regtest.custody',
            'wam_sp.keystore',
            'wam_sp.psbt',
        })
        for filename, name in self._modules('domain'):
            if filename == 'payment_evidence.py':
                self.assertTrue(_domain_import_allowed(name), name)


class ExistingMarkersUnchanged(unittest.TestCase):
    """The pre-existing env-gated markers keep their exact gates and text."""

    def _run(self, fn, env, *args):
        out = io.StringIO()
        with patch.dict(os.environ, env, clear=False), redirect_stdout(out):
            for key in ('GITHUB_ACTIONS', 'WAM_Q06_CI_SPEND_QUALIFY', 'CI', 'WAM_RECONCILIATION_DIAGNOSTICS'):
                if key not in env:
                    os.environ.pop(key, None)
            fn(*args)
        return out.getvalue()

    def test_q06_spend_marker_gate(self):
        both = {'GITHUB_ACTIONS': 'true', 'WAM_Q06_CI_SPEND_QUALIFY': '1'}
        with patch.object(diagnostics.sys, 'platform', 'darwin'):
            self.assertEqual(self._run(diagnostics.q06_spend_marker, both, 'M'), 'M\n')
            self.assertEqual(self._run(diagnostics.q06_spend_marker, {'GITHUB_ACTIONS': 'true'}, 'M'), '')
            self.assertEqual(self._run(diagnostics.q06_spend_marker, {'WAM_Q06_CI_SPEND_QUALIFY': '1'}, 'M'), '')
        with patch.object(diagnostics.sys, 'platform', 'linux'):
            self.assertEqual(self._run(diagnostics.q06_spend_marker, both, 'M'), '')

    def test_ci_and_reconciliation_markers(self):
        self.assertEqual(self._run(diagnostics.ci_marker, {'CI': 'true'}, 'X'), 'X\n')
        self.assertEqual(self._run(diagnostics.ci_marker, {}, 'X'), '')
        env = {'WAM_RECONCILIATION_DIAGNOSTICS': '1'}
        self.assertEqual(self._run(diagnostics.reconciliation_marker, env, 'P', ValueError('CODE_1')),
                         'Q06_RECONCILIATION_DENIED_STAGE=P;CATEGORY=CODE_1\n')
        self.assertEqual(self._run(diagnostics.reconciliation_marker, env, 'P', ValueError(SECRETS[1])),
                         'Q06_RECONCILIATION_DENIED_STAGE=P;CATEGORY=INTERNAL_DENIED\n')
        self.assertEqual(self._run(diagnostics.reconciliation_marker, {}, 'P', ValueError('CODE_1')), '')


class WiredSites(unittest.TestCase):
    """Each fail-closed wrapper records the underlying category before raising."""

    def setUp(self):
        diagnostics.clear()

    def test_backend_unlock_activation_failure_is_classified(self):
        from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend, Q06ReadOnlyError
        backend = object.__new__(Bip39ReadOnlyBackend)
        backend.shared_profile = None
        backend._spend_session = None
        backend._public = backend._seed_folder = backend._backup_challenge = None
        backend._backup_epoch = 0
        backend._secret = None
        backend._resume_spend = True
        secret = bytearray(b'password-marker')

        def reopen(password):
            backend._secret = secret
            return {'backup_status': 'verified'}

        def activate():
            error = ValueError('Q06_SPEND_OPEN_DENIED')
            error.open_stage = 'PENDING_BROADCAST_RECOVERY'
            try:
                raise ValueError('Q06_PENDING_BROADCAST_UNVERIFIED')
            except ValueError as inner:
                raise error from inner

        backend._reopen_q06 = reopen
        backend._activate_q06 = activate
        with self.assertRaises(Q06ReadOnlyError) as caught:
            backend.execute('unlock', (b'wallet-password', False), {})
        self.assertEqual(caught.exception.args, ('Q06_GUI_UNLOCK_RECONCILIATION_DENIED',))
        self.assertEqual([(r.stage, r.category, r.open_stage) for r in diagnostics.records()],
                         [('UNLOCK_ACTIVATION', 'Q06_PENDING_BROADCAST_UNVERIFIED',
                           'PENDING_BROADCAST_RECOVERY')])

    def test_open_owned_spend_session_records_phase_and_underlying_category(self):
        from wam_regtest.bip39_spend_session import Q06SpendSessionError, open_owned_spend_session
        target = 'wam_regtest.bip39_spend_session'
        with patch(target + '._owned_password', return_value='unused'), \
                patch(target + '._owned'), \
                patch(target + '.open_owned_seed_container',
                      side_effect=StorageError('DATABASE_BUSY_OR_CORRUPT')):
            owner = type('O', (), {'directory': Path('/nonexistent'), 'cli': 'x', 'core': 'x', 'receipt': {}})()
            with self.assertRaises(Q06SpendSessionError) as caught:
                open_owned_spend_session(owner, Path('/unused'), Path('/unused').resolve(),
                                         b'x' * 16, authorized=True)
        self.assertEqual(caught.exception.args, ('Q06_SPEND_OPEN_DENIED',))
        items = diagnostics.records()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].stage, 'SPEND_OPEN')
        self.assertEqual(caught.exception.open_stage, 'SEED_AUTH')
        self.assertEqual(items[0].open_stage, 'SEED_AUTH')
        self.assertEqual(items[0].category, 'DATABASE_BUSY_OR_CORRUPT')

    def test_production_allowlist_ships_the_diagnostics_module(self):
        import importlib.util
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('pm003_policy', root / 'scripts/production_packaging.py')
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        names = policy.wallet_module_names(root)
        self.assertIn('foundation', names)
        self.assertIn('foundation.diagnostics', names)
        for platform in ('macos', 'windows', 'linux-desktop'):
            self.assertIn('foundation.diagnostics', policy.runtime_modules(platform))
        self.assertEqual(policy.module_path(root, 'foundation.diagnostics'),
                         root / 'src/wam_regtest/foundation/diagnostics.py')
        self.assertEqual(policy.module_path(root, 'foundation'),
                         root / 'src/wam_regtest/foundation/__init__.py')
        args = policy.arguments(root)
        self.assertIn('wam_regtest.foundation.diagnostics', args)
        self.assertNotIn('PySide6', (root / 'src/wam_regtest/foundation/diagnostics.py').read_text())


if __name__ == '__main__':
    unittest.main()
