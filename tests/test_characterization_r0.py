"""R0 characterization of behaviour at f8926405. Tests only; no product change.

Pins the audit contracts that later refactors must keep: unlock/open error
projection (F-05, I-13), action availability (F-08) including the current
W-TX-03 warning (F-02), reduced-motion predicates (F-05), the production
allowlist (I-12, F-10), runtime import edges (F-10), and import origin (F-18).
English catalog text lives in test_characterization_r0_english.py (F-14).
"""
import ast
import fnmatch
import importlib.util
import itertools
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_OPEN = 'PRIVATE_OPEN_MARKER'
PRIVATE_ACTIVATION = 'PRIVATE_ACTIVATION_MARKER'
TIP = 'ab' * 32
TXID_A = '11' * 32
TXID_B = '22' * 32
COMMITMENT = '33' * 32

# phase = '<token>' assignments inside open_owned_spend_session at this revision,
# including PENDING_BROADCAST_RECOVERY. F-05.
OPEN_STAGES = frozenset({
    'SEED_AUTH',
    'RUNTIME_PREFLIGHT',
    'SCANNER_CREATE',
    'SCANNER_GUARD',
    'RPC_ATTEST',
    'CHECKPOINT_DIRECTORY',
    'CHECKPOINT_RESTORE',
    'INITIAL_SCANNER_SYNC',
    'INITIAL_NATIVE_PUBLISH',
    'NATIVE_VAULT_OPEN',
    'SESSION_CONSTRUCTION',
    'OWNED_SESSION_RPC',
    'PENDING_BROADCAST_RECOVERY',
})

# Exact macOS production module set at this revision (I-12).
RUNTIME_SNAPSHOT = frozenset({
    '__init__', 'amounts', 'bip39_12', 'bip39_backup_page', 'bip39_fusion_gui',
    'bip39_locale', 'bip39_native_checkpoint', 'bip39_owner_backend',
    'bip39_owner_gui', 'bip39_reconciliation', 'bip39_recovery_proof',
    'bip39_scanner_checkpoint', 'bip39_seed_vault', 'bip39_spend_session',
    'branding', 'build_provenance', 'cli_rpc', 'core', 'core_process',
    'core_supervisor', 'custody', 'desktop', 'disclosure', 'encrypted_storage',
    'external_core', 'external_core_gui', 'external_recovery', 'fusion_motion',
    'fusion_pages', 'fusion_status', 'fusion_ui', 'gui_errors', 'history_pages',
    'json_rpc', 'linux_anchor_witness', 'linux_developer_core',
    'linux_official_core', 'linux_private_storage', 'linux_runtime',
    'managed_gui', 'managed_onboarding', 'managed_wallet_checkpoint',
    'managed_wallet_session', 'network_policy', 'official_core_v013',
    'operational_gui', 'payjoin_safety', 'private_directory', 'production_entry',
    'q05_platforms', 'regtest_funding', 'release', 'rpc_contention',
    'rpc_credentials', 'rpc_scope', 'shared_regtest', 'shared_regtest_gui',
    'supervisor_client', 'supervisor_identity', 'supervisor_journal',
    'supervisor_protocol', 'supervisor_store', 'telemetry', 'vault',
    'wallet_executor', 'wallet_read', 'wallet_recovery', 'wallet_session',
    # PM-003: first layered subpackage module (dotted names).
    'foundation', 'foundation.diagnostics',
    # PM-004: backup acknowledgement domain and owned-spend snapshot projection.
    'application', 'application.snapshot_projection',
    'domain', 'domain.backup_ack',
    'windows_checkpoint_anchor', 'windows_core_files', 'windows_core_transport',
    'windows_private_storage', 'windows_release_preflight', 'wsp_import',
    'wsp_live',
})
WINDOWS_EXTRA_SNAPSHOT = frozenset({
    'windows_core_regtest_smoke', 'windows_core_stage', 'windows_production_entry',
})
LINUX_EXTRA_SNAPSHOT = frozenset({'linux_production_entry'})

# Function-level imports of a non-runtime wam_regtest module from a macOS
# RUNTIME module. The whole set at this revision (F-10). A new edge fails.
#   * core.smoke_real_core's probe imports, plus that function's win32 helper
#   * managed_onboarding.assert_unified_welcome_qt -> onboarding_probe
#   * win32 windows_core_regtest_smoke helpers reached from core /
#     core_process / core_supervisor / rpc_scope / windows_core_transport
RUNTIME_FUNCTION_IMPORTS = frozenset({
    ('core', 'smoke_real_core', 'desktop_probe'),
    ('core', 'smoke_real_core', 'q02_probe'),
    ('core', 'smoke_real_core', 'reopen_probe'),
    ('core', 'smoke_real_core', 'security_probe'),
    ('core', 'smoke_real_core', 'wallet_probe'),
    ('core', 'smoke_real_core', 'windows_core_regtest_smoke'),
    ('core', 'smoke_real_core', 'windows_vault_probe'),
    ('core', '_write_private_config', 'windows_core_regtest_smoke'),
    ('core_process', '_windows_socket', 'windows_core_regtest_smoke'),
    ('core_supervisor', 'CoreSupervisor.start', 'windows_core_regtest_smoke'),
    ('managed_onboarding', 'assert_unified_welcome_qt', 'onboarding_probe'),
    ('rpc_scope', 'route', 'windows_core_regtest_smoke'),
    ('windows_core_transport', 'read_cli', 'windows_core_regtest_smoke'),
})

LEGACY_WORKSPACE = 'WAM-Q06-Audit-20261102'
ACTION_FLAGS = (
    'ready', 'spend', 'signed', 'pending', 'commitment', 'recovered',
    'resumable', 'unlock_allowed', 'last_review', 'locked', 'faulted',
    'busy', 'reauth',
)
ACTION_CONTROLS = ('send', 'broadcast', 'confirm', 'activate', 'lock', 'unlock', 'cancel')


def _packaging():
    spec = importlib.util.spec_from_file_location(
        'characterization_r0_packaging', ROOT / 'scripts' / 'production_packaging.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _assigned_open_stages():
    tree = ast.parse((ROOT / 'src/wam_regtest/bip39_spend_session.py').read_text())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'open_owned_spend_session':
            found = set()
            for child in ast.walk(node):
                if not isinstance(child, ast.Assign) or len(child.targets) != 1:
                    continue
                target = child.targets[0]
                if (isinstance(target, ast.Name) and target.id == 'phase'
                        and isinstance(child.value, ast.Constant)
                        and type(child.value.value) is str):
                    found.add(child.value.value)
            return found
    raise AssertionError('open_owned_spend_session is missing')


def _parents(tree):
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def _function_scope(node, parents):
    """Qualified function scope, or None when the node is not inside a function."""
    parts = []
    saw_function = False
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parts.append(current.name)
            saw_function = True
        elif isinstance(current, ast.ClassDef):
            parts.append(current.name)
    if not saw_function:
        return None
    return '.'.join(reversed(parts))


def _wam_regtest_modules(node):
    """Module stems imported from wam_regtest by one import statement."""
    if isinstance(node, ast.Import):
        found = []
        for alias in node.names:
            name = alias.name
            if name == 'wam_regtest' or name.startswith('wam_regtest.'):
                parts = name.split('.')
                found.append(parts[1] if len(parts) > 1 else '__init__')
        return found
    if isinstance(node, ast.ImportFrom):
        if node.level not in (0, 1):
            return ['<relative-level-%s>' % node.level]
        if node.level == 1 and node.module:
            return [node.module.split('.')[0]]
        if node.level == 1 and node.module is None:
            return [alias.name.split('.')[0] for alias in node.names]
        if node.module == 'wam_regtest':
            return [alias.name.split('.')[0] for alias in node.names]
        if node.module and node.module.startswith('wam_regtest.'):
            return [node.module.split('.')[1]]
    return []


def _dynamic_wam_regtest_modules(node):
    """Constant wam_regtest targets of import_module/__import__, or a marker."""
    if not isinstance(node, ast.Call):
        return []
    func = node.func
    name = func.id if isinstance(func, ast.Name) else (
        func.attr if isinstance(func, ast.Attribute) else None)
    if name not in ('import_module', '__import__') or not node.args:
        return []
    argument = node.args[0]
    if not isinstance(argument, ast.Constant) or type(argument.value) is not str:
        return ['<dynamic>'] if name == 'import_module' else []
    value = argument.value
    if value == 'wam_regtest' or value.startswith('wam_regtest.'):
        parts = value.split('.')
        return [parts[1] if len(parts) > 1 else '__init__']
    return []


def _runtime_import_edges():
    """(module, function-or-empty, imported) for non-runtime wam_regtest imports."""
    policy = _packaging()
    runtime = set(policy.RUNTIME)
    module_level = set()
    function_level = set()
    for module in sorted(policy.wallet_module_names(ROOT)):
        if module not in runtime:
            continue
        tree = ast.parse(policy.module_path(ROOT, module).read_text())
        parents = _parents(tree)
        for node in ast.walk(tree):
            imported = _wam_regtest_modules(node) if isinstance(
                node, (ast.Import, ast.ImportFrom)) else _dynamic_wam_regtest_modules(node)
            if not imported:
                continue
            scope = _function_scope(node, parents)
            for name in imported:
                if name in runtime:
                    continue
                edge = (module, scope or '<module>', name)
                if scope is None:
                    module_level.add(edge)
                else:
                    function_level.add((module, scope, name))
    return module_level, function_level


def _ci_flags(path):
    tree = ast.parse(path.read_text())
    return {node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and type(node.value) is str
            and node.value.startswith('--ci-')}


def _expected_actions(flags):
    """Current Bip39TrialWindow._set_actions predicates (bip39_owner_gui.py:361-394).

    _resumable_intent and _last_review are applied by the caller and do not
    appear here: at this revision they do not change these seven controls.
    """
    busy = flags['busy']
    safe = not flags['faulted']
    spend_safe = (safe and not flags['locked'] and not flags['reauth']
                  and flags['core_alive'] is True)
    return {
        'send': (spend_safe and flags['spend'] and not flags['commitment']
                 and not flags['recovered'] and not busy),
        'broadcast': spend_safe and flags['spend'] and flags['signed'] and not busy,
        'confirm': spend_safe and flags['spend'] and flags['pending'] and not busy,
        'activate': flags['ready'] and safe and not flags['spend'] and not busy,
        'lock': flags['ready'] and not busy,
        'unlock': flags['unlock_allowed'] and not flags['ready'] and not busy,
        'cancel': (spend_safe and flags['spend']
                   and (flags['commitment'] or flags['recovered'])
                   and not flags['signed'] and not busy),
    }


def _apply_actions(window, flags):
    window._ready = flags['ready']
    window._spend_enabled = flags['spend']
    window._signed_ready = flags['signed']
    window._pending_confirm_txid = TXID_A if flags['pending'] else None
    window._approved_commitment = COMMITMENT if flags['commitment'] else None
    window._recovered_unsigned_cancel = flags['recovered']
    window._resumable_intent = {'status': 'review'} if flags['resumable'] else None
    window._unlock_allowed = flags['unlock_allowed']
    window._last_review = SimpleNamespace(commitment=COMMITMENT) if flags['last_review'] else None
    window._worker = None
    window._delivering_result = False
    window._quit_requested = False
    window._test_funded = False
    window.executor.busy = flags['busy']
    window.executor.closed = False
    window.executor.state = window.executor.state.__class__(
        locked=flags['locked'],
        faulted=flags['faulted'],
        reauthentication_required=flags['reauth'],
        core_alive=flags['core_alive'],
    )


def _enabled(window):
    return {name: getattr(window, name).isEnabled() for name in ACTION_CONTROLS}


def _qt_app():
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


class _Closable:
    def close(self):
        return None


class _Keys(_Closable):
    def accounts(self):
        return ('acct',)

    def public_metadata(self):
        return {'account_id': 'id'}


class _Scanner(_Closable):
    def __init__(self, phase):
        self.phase = phase
        self.store = SimpleNamespace(tip=lambda: (3, TIP))

    def sync(self, rpc):
        if self.phase == 'INITIAL_SCANNER_SYNC':
            raise RuntimeError(PRIVATE_OPEN)

    def assert_current(self):
        return None


class _Guard(_Closable):
    def check(self):
        return None


class _BadDirectory:
    def iterdir(self):
        raise RuntimeError(PRIVATE_OPEN)


def _snapshot_result(**overrides):
    result = {
        'signer_allowed': True,
        'payment_review': None,
        'pending_confirm_txid': None,
        'receive_code': 'wamrtsp1example',
        'confirmed_atoms': 0,
        'available_atoms': 0,
        'height': 101,
        'tip': 'cd' * 32,
        'history': (),
        'reservation_count': 0,
    }
    result.update(overrides)
    return result


class UnlockOpenProjection(unittest.TestCase):
    """F-05 / I-13. Public unlock text is a fixed code, never the failure text."""

    def test_unlock_codes_project_through_operation_error(self):
        """gui_errors.py:52-82. The GUI calls operation_error on the
        WalletExecutorError the owner thread built from the original code
        (wallet_executor.py:114-121, managed_gui.py:37)."""
        from wam_regtest.bip39_owner_backend import Q06ReadOnlyError
        from wam_regtest.bip39_seed_vault import Bip39SeedCustodyError
        from wam_regtest.gui_errors import error_text, operation_error
        from wam_regtest.vault import VaultError
        from wam_regtest.wallet_executor import WalletExecutorError
        from wam_regtest.wallet_session import WalletSessionError

        code = 'Q06_GUI_UNLOCK_RECONCILIATION_DENIED'
        # The equality the GUI observes: the wrapped reconciliation code.
        self.assertEqual(
            operation_error('unlock', WalletExecutorError(code)),
            'WALLET_UNLOCK_REFUSED')
        self.assertEqual(
            operation_error('open', WalletExecutorError(code)),
            'WALLET_UNLOCK_REFUSED')
        # Exact-type gate at this revision: the raw backend error is a
        # Q06ReadOnlyError, not a WalletExecutorError, so lines 65-68 do not
        # see it. The owner thread wraps args[0] before the GUI projects it.
        self.assertEqual(
            operation_error('unlock', Q06ReadOnlyError(code)),
            'WALLET_OPERATION_DENIED_STATE_RETAINED')
        for action in ('unlock', 'open'):
            for seed_code in ('Q06_SEED_REOPEN_DENIED', 'Q06_SEED_PASSWORD_DENIED'):
                with self.subTest(action=action, seed_code=seed_code):
                    self.assertEqual(
                        operation_error(action, WalletExecutorError(seed_code)),
                        'WALLET_UNLOCK_REFUSED')
        # Same codes on a different action stay off the unlock row.
        self.assertNotEqual(
            operation_error('broadcast', WalletExecutorError(code)),
            'WALLET_UNLOCK_REFUSED')
        # The seed classes themselves are not WalletExecutorError.
        self.assertEqual(
            operation_error('unlock', Bip39SeedCustodyError('Q06_SEED_REOPEN_DENIED')),
            'WALLET_OPERATION_DENIED_STATE_RETAINED')
        marker = 'rpcpassword=private-test-marker'
        self.assertEqual(operation_error('unlock', VaultError(marker)), 'WALLET_UNLOCK_REFUSED')
        self.assertEqual(operation_error('recover', VaultError(marker)), 'WALLET_RECOVERY_REFUSED')
        self.assertNotIn('private-test-marker', error_text('WALLET_UNLOCK_REFUSED'))
        self.assertNotIn('private-test-marker', error_text('WALLET_RECOVERY_REFUSED'))
        # A registered session code is returned as itself. An unregistered
        # one, including an input code, falls through to the unlock/recover row.
        self.assertEqual(
            operation_error('unlock', WalletSessionError('WALLET_STALE_SESSION_DENIED')),
            'WALLET_STALE_SESSION_DENIED')
        self.assertEqual(
            operation_error('unlock', WalletSessionError('NOT_A_PUBLIC_CODE')),
            'WALLET_UNLOCK_REFUSED')
        self.assertEqual(
            operation_error('recover', WalletSessionError('NOT_A_PUBLIC_CODE')),
            'WALLET_RECOVERY_REFUSED')
        self.assertEqual(
            operation_error('unlock', WalletSessionError('WALLET_INPUT_AMOUNT_INVALID')),
            'WALLET_UNLOCK_REFUSED')
        self.assertEqual(
            operation_error('unlock', WalletSessionError(marker, 'second')),
            'WALLET_UNLOCK_REFUSED')
        self.assertNotIn('private-test-marker', 'WALLET_UNLOCK_REFUSED')

    def test_open_stage_vocabulary_includes_pending_broadcast_recovery(self):
        """F-05. The phase tokens assigned in open_owned_spend_session."""
        self.assertEqual(_assigned_open_stages(), set(OPEN_STAGES))
        self.assertIn('PENDING_BROADCAST_RECOVERY', OPEN_STAGES)

    def test_open_failure_keeps_open_stage_and_drops_exception_text(self):
        """F-05. Each failing phase raises Q06_SPEND_OPEN_DENIED with that
        fixed open_stage and no exception text. No real Core."""
        from wam_regtest.bip39_spend_session import Q06SpendSessionError
        for phase in sorted(OPEN_STAGES):
            with self.subTest(phase=phase):
                error, printed = self._fail_phase(phase)
                self.assertIsInstance(error, Q06SpendSessionError)
                self.assertEqual(error.args, ('Q06_SPEND_OPEN_DENIED',))
                self.assertEqual(error.open_stage, phase)
                self.assertIn(error.open_stage, OPEN_STAGES)
                self.assertEqual(str(error), 'Q06_SPEND_OPEN_DENIED')
                self.assertIsNone(error.__cause__)
                self.assertTrue(error.__suppress_context__)
                self.assertNotIn(PRIVATE_OPEN, str(error))
                self.assertNotIn(PRIVATE_OPEN, error.open_stage)
                self.assertNotIn(PRIVATE_OPEN, printed)
                if phase == 'PENDING_BROADCAST_RECOVERY' and sys.platform == 'darwin':
                    self.assertEqual(
                        printed,
                        'MACOS_Q06_SPEND_OPEN_DENIED_STAGE=PENDING_BROADCAST_RECOVERY\n')

    def _fail_phase(self, phase):
        from wam_regtest.bip39_spend_session import (
            Q06SpendSessionError, open_owned_spend_session)
        target = 'wam_regtest.bip39_spend_session'

        class FakeCli:
            def __init__(self, *args, **kwargs):
                self._transport = None

            def attest(self):
                if phase == 'RPC_ATTEST':
                    raise RuntimeError(PRIVATE_OPEN)

            def call(self, method):
                if method == 'getblockcount':
                    return 3
                if method == 'getbestblockhash':
                    return TIP
                raise AssertionError(method)

        def open_keys(*args, **kwargs):
            if phase == 'SEED_AUTH':
                raise RuntimeError(PRIVATE_OPEN)
            return _Keys()

        def make_scanner(*args, **kwargs):
            if phase == 'SCANNER_CREATE':
                raise RuntimeError(PRIVATE_OPEN)
            return _Scanner(phase)

        def make_guard(*args, **kwargs):
            if phase == 'SCANNER_GUARD':
                raise RuntimeError(PRIVATE_OPEN)
            return _Guard()

        def make_vault(*args, **kwargs):
            if phase == 'NATIVE_VAULT_OPEN':
                raise RuntimeError(PRIVATE_OPEN)
            return object()

        def make_session(*args, **kwargs):
            if phase == 'SESSION_CONSTRUCTION':
                raise RuntimeError(PRIVATE_OPEN)
            return session

        class _Session:
            def _rpc(self):
                if phase == 'OWNED_SESSION_RPC':
                    raise RuntimeError(PRIVATE_OPEN)
                return object()

            def _recover_pending_broadcast(self):
                if phase == 'PENDING_BROADCAST_RECOVERY':
                    raise RuntimeError(PRIVATE_OPEN)
                return None

        session = _Session()

        def publish(*args, **kwargs):
            if phase == 'INITIAL_NATIVE_PUBLISH':
                raise RuntimeError(PRIVATE_OPEN)

        def read_candidate(*args, **kwargs):
            raise RuntimeError(PRIVATE_OPEN)

        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            existing = directory / 'checkpoint-folder'
            existing.mkdir()
            missing = directory / 'missing-checkpoint'
            owner_directory = _BadDirectory() if phase == 'RUNTIME_PREFLIGHT' else directory

            def resolve_directory(owner, seed_folder):
                if phase == 'CHECKPOINT_DIRECTORY':
                    raise RuntimeError(PRIVATE_OPEN)
                if phase == 'CHECKPOINT_RESTORE':
                    return ('ab' * 16, existing)
                return ('ab' * 16, missing)

            owner = SimpleNamespace(
                directory=owner_directory, cli='unused-cli', core='unused-core', receipt={})
            printed = StringIO()
            with patch.dict(os.environ), redirect_stdout(printed), \
                    patch(target + '._owned_password', return_value='unused'), \
                    patch(target + '._owned'), \
                    patch(target + '.open_owned_seed_container', side_effect=open_keys), \
                    patch(target + '.Scanner', side_effect=make_scanner), \
                    patch(target + '.RuntimeGuard', side_effect=make_guard), \
                    patch(target + '.WalletCoreCli', FakeCli), \
                    patch(target + '._directory', side_effect=resolve_directory), \
                    patch(target + '.read_owned_candidate', side_effect=read_candidate), \
                    patch(target + '.publish_owned_candidate', side_effect=publish), \
                    patch(target + '._Q06NativeScannerVault', side_effect=make_vault), \
                    patch(target + '.Q06OwnedSpendSession', side_effect=make_session):
                os.environ.pop('GITHUB_ACTIONS', None)
                os.environ.pop('WAM_Q06_CI_SPEND_QUALIFY', None)
                if phase == 'PENDING_BROADCAST_RECOVERY':
                    os.environ['GITHUB_ACTIONS'] = 'true'
                    os.environ['WAM_Q06_CI_SPEND_QUALIFY'] = '1'
                with self.assertRaises(Q06SpendSessionError) as caught:
                    open_owned_spend_session(
                        owner, Path('/unused-seed'), Path('/unused-source').resolve(),
                        b'x' * 16, authorized=True)
        return caught.exception, printed.getvalue()

    def test_unlock_activation_failure_relocks_as_reconciliation_denied(self):
        """F-05. bip39_owner_backend.py unlock: an activation failure becomes
        Q06_GUI_UNLOCK_RECONCILIATION_DENIED and relocks. No real Core."""
        from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend, Q06ReadOnlyError
        from wam_regtest.gui_errors import operation_error
        from wam_regtest.wallet_executor import WalletExecutorError

        backend = object.__new__(Bip39ReadOnlyBackend)
        backend.shared_profile = None
        backend._spend_session = None
        backend._public = None
        backend._seed_folder = None
        backend._backup_challenge = None
        backend._backup_epoch = 0
        secret = bytearray(b'password-marker')
        calls = {'activate': 0}

        def reopen(password):
            backend._secret = secret
            backend._seed_folder = Path('/unused-seed')
            return {'backup_status': backend._backup_status, 'receive_code': 'wamrtsp1example'}

        def activate():
            calls['activate'] += 1
            raise RuntimeError(PRIVATE_ACTIVATION)

        backend._reopen_q06 = reopen
        backend._activate_q06 = activate

        backend._secret = None
        backend._resume_spend = True
        backend._backup_status = 'verified'
        with self.assertRaises(Q06ReadOnlyError) as caught:
            backend.execute('unlock', (b'wallet-password', False), {})
        error = caught.exception
        self.assertEqual(error.args, ('Q06_GUI_UNLOCK_RECONCILIATION_DENIED',))
        self.assertIsNone(error.__cause__)
        self.assertTrue(error.__suppress_context__)
        self.assertNotIn(PRIVATE_ACTIVATION, str(error))
        self.assertIsNone(backend._secret)
        self.assertEqual(bytes(secret), b'\x00' * len(secret))
        self.assertFalse(backend._resume_spend)
        self.assertEqual(calls['activate'], 1)
        self.assertEqual(
            operation_error('unlock', WalletExecutorError(error.args[0])),
            'WALLET_UNLOCK_REFUSED')

        # The relock row runs only after a verified reopen while resume is set.
        secret = bytearray(b'password-marker')
        backend._secret = None
        backend._resume_spend = False
        backend._backup_status = 'verified'
        opened = backend.execute('unlock', (b'wallet-password', False), {})
        self.assertEqual(opened['backup_status'], 'verified')
        self.assertIs(backend._secret, secret)
        self.assertEqual(calls['activate'], 1)

        backend._secret = None
        backend._resume_spend = True
        backend._backup_status = 'deferred'
        opened = backend.execute('unlock', (b'wallet-password', False), {})
        self.assertEqual(opened['backup_status'], 'deferred')
        self.assertIs(backend._secret, secret)
        self.assertTrue(backend._resume_spend)
        self.assertEqual(calls['activate'], 1)


class ActionAvailability(unittest.TestCase):
    """F-08. Button enablement is the current _set_actions truth table."""

    def setUp(self):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.bip39_owner_gui import Bip39TrialWindow
        from wam_regtest.wallet_executor import ExecutorState
        self.app = _qt_app()
        self.owner = SimpleNamespace(
            state=ExecutorState(locked=False, faulted=False, core_alive=True),
            busy=False, closed=False)
        self.trial = Bip39TrialWindow(self.owner)
        self.fusion = Bip39FusionWindow(self.owner)
        self.trial._poll.stop()
        self.fusion._poll.stop()

    def tearDown(self):
        self.trial._poll.stop()
        self.fusion._poll.stop()
        self.trial.hide()
        self.fusion.hide()
        self.trial.deleteLater()
        self.fusion.deleteLater()
        self.app.processEvents()

    def test_set_actions_truth_table_for_trial_and_fusion(self):
        """F-08. send/broadcast/confirm/activate/lock/unlock/cancel over the
        GUI flags and executor locked/faulted/busy (plus reauthentication and
        core_alive, which spend_safe also reads). _resumable_intent and
        _last_review are varied and do not change these controls. Fusion's
        non-shared _set_actions keeps the same seven results."""
        for bits in itertools.product((False, True), repeat=len(ACTION_FLAGS)):
            flags = dict(zip(ACTION_FLAGS, bits))
            for core_alive in (True, False, None):
                flags['core_alive'] = core_alive
                want = _expected_actions(flags)
                for window in (self.trial, self.fusion):
                    _apply_actions(window, flags)
                    window._set_actions()
                    got = _enabled(window)
                    if got != want:
                        self.fail('%s %s\n got %s\nwant %s' % (
                            type(window).__name__, flags, got, want))

    def test_worker_delivery_and_quit_disable_enabled_controls(self):
        """F-08. busy is also _worker, _delivering_result, or _quit_requested."""
        baselines = {
            'send': dict(ready=True, spend=True, signed=False, pending=False,
                         commitment=False, recovered=False, unlock_allowed=False),
            'broadcast': dict(ready=True, spend=True, signed=True, pending=False,
                              commitment=True, recovered=False, unlock_allowed=False),
            'confirm': dict(ready=True, spend=True, signed=False, pending=True,
                            commitment=False, recovered=False, unlock_allowed=False),
            'activate': dict(ready=True, spend=False, signed=False, pending=False,
                             commitment=False, recovered=False, unlock_allowed=False),
            'lock': dict(ready=True, spend=False, signed=False, pending=False,
                         commitment=False, recovered=False, unlock_allowed=False),
            'unlock': dict(ready=False, spend=False, signed=False, pending=False,
                           commitment=False, recovered=False, unlock_allowed=True),
            'cancel': dict(ready=True, spend=True, signed=False, pending=False,
                           commitment=True, recovered=False, unlock_allowed=False),
        }
        blockers = ('busy', 'worker', 'delivering', 'quit')
        for control, base in baselines.items():
            flags = dict(base)
            flags.update(resumable=False, last_review=False, locked=False,
                         faulted=False, busy=False, reauth=False, core_alive=True)
            for window in (self.trial, self.fusion):
                _apply_actions(window, flags)
                window._set_actions()
                self.assertTrue(getattr(window, control).isEnabled(),
                                '%s %s' % (type(window).__name__, control))
                for blocker in blockers:
                    self._set_blocker(window, blocker, True)
                    window._set_actions()
                    self.assertFalse(
                        getattr(window, control).isEnabled(),
                        '%s %s blocked by %s' % (type(window).__name__, control, blocker))
                    self._set_blocker(window, blocker, False)
                    window._set_actions()
                    self.assertTrue(getattr(window, control).isEnabled())

    @staticmethod
    def _set_blocker(window, blocker, enabled):
        if blocker == 'busy':
            window.executor.busy = enabled
        elif blocker == 'worker':
            window._worker = object() if enabled else None
        elif blocker == 'delivering':
            window._delivering_result = enabled
        elif blocker == 'quit':
            window._quit_requested = enabled
        else:
            raise AssertionError(blocker)

    def test_snapshot_keeps_pending_confirm_txid_when_report_is_none(self):
        """F-08. bip39_owner_gui.py:638-643 keeps the GUI TXID when a snapshot
        reports pending_confirm_txid=None. A reported TXID replaces it."""
        window = self.trial
        window._spend_enabled = True
        window._pending_confirm_txid = TXID_A
        window.last_txid.setText(TXID_A)
        window._on_ready('snapshot', _snapshot_result(
            pending_confirm_txid=None, reservation_count=2))
        self.assertEqual(window._pending_confirm_txid, TXID_A)
        self.assertEqual(window.last_txid.text(), TXID_A)
        self.assertEqual(
            window.status.text(),
            'Broadcast TXID %s is awaiting its first REGTEST confirmation. '
            'Use Confirm 1 REGTEST block; do not send this payment again.' % TXID_A)
        self.assertNotIn('Anchored transaction reservations exist', window.status.text())

        window.last_txid.clear()
        window._on_ready('snapshot', _snapshot_result(pending_confirm_txid=TXID_B))
        self.assertEqual(window._pending_confirm_txid, TXID_B)
        self.assertEqual(window.last_txid.text(), TXID_B)

    def test_reservation_warning_on_positive_count_without_pending_txid_pins_w_tx_03_as_current_behaviour(self):
        """F-02 / W-TX-03 current behaviour. bip39_owner_gui.py:661-665 warns
        whenever spend is enabled, reservation_count>0, and there is no pending
        TXID. The count is not filtered by reservation state."""
        window = self.trial
        window._pending_confirm_txid = None
        window._spend_enabled = False
        window._recovered_unsigned_cancel = False
        window.last_txid.clear()
        warning = (
            'Anchored transaction reservations exist; check previous TXID '
            'against verified history. Never auto-rebroadcast or release locks.')
        window._on_ready('snapshot', _snapshot_result(reservation_count=1))
        self.assertIsNone(window._pending_confirm_txid)
        self.assertEqual(window.status.text(), warning)

        window._on_ready('snapshot', _snapshot_result(reservation_count=0))
        self.assertEqual(
            window.status.text(),
            'Verified BIP39 REGTEST Send session; review every transaction')

        window._spend_enabled = False
        window._on_ready('snapshot', _snapshot_result(
            signer_allowed=False, reservation_count=4))
        self.assertFalse(window._spend_enabled)
        self.assertEqual(
            window.status.text(),
            'Verified WAM Core and WSP scan; Send remains disabled')
        self.assertNotIn('Anchored transaction reservations exist', window.status.text())


class MotionReduced(unittest.TestCase):
    """F-05. fusion_motion.motion_reduced predicates, including GITHUB_ACTIONS."""

    def test_motion_reduced_matrix(self):
        from PySide6.QtWidgets import QWidget
        from wam_regtest.fusion_motion import motion_reduced
        app = _qt_app()
        parent = QWidget()
        child = QWidget(parent)
        try:
            with patch.dict(os.environ):
                os.environ.pop('QT_REDUCE_MOTION', None)
                os.environ.pop('GITHUB_ACTIONS', None)
                parent.setProperty('fusion_reduce_motion', None)
                child.setProperty('fusion_reduce_motion', None)
                self.assertFalse(motion_reduced())
                self.assertFalse(motion_reduced(child))

                os.environ['QT_REDUCE_MOTION'] = '1'
                self.assertTrue(motion_reduced())
                self.assertTrue(motion_reduced(child))
                os.environ['QT_REDUCE_MOTION'] = '0'
                self.assertFalse(motion_reduced())
                del os.environ['QT_REDUCE_MOTION']

                os.environ['GITHUB_ACTIONS'] = 'true'
                self.assertTrue(motion_reduced())
                self.assertTrue(motion_reduced(child))
                os.environ['GITHUB_ACTIONS'] = 'false'
                self.assertFalse(motion_reduced(child))
                del os.environ['GITHUB_ACTIONS']

                child.setProperty('fusion_reduce_motion', True)
                self.assertTrue(motion_reduced(child))
                self.assertFalse(motion_reduced())
                child.setProperty('fusion_reduce_motion', False)
                parent.setProperty('fusion_reduce_motion', True)
                self.assertTrue(motion_reduced(child))
                parent.setProperty('fusion_reduce_motion', 1)
                self.assertFalse(motion_reduced(child))
        finally:
            child.deleteLater()
            parent.deleteLater()
            app.processEvents()


class ProductionAllowlist(unittest.TestCase):
    """I-12 / F-10. Shipped module sets and developer argv at this revision."""

    def test_runtime_windows_and_linux_sets_match_the_snapshot(self):
        policy = _packaging()
        self.assertEqual(policy.RUNTIME, RUNTIME_SNAPSHOT)
        self.assertEqual(policy.WINDOWS_EXTRA, WINDOWS_EXTRA_SNAPSHOT)
        self.assertEqual(policy.LINUX_EXTRA, LINUX_EXTRA_SNAPSHOT)
        self.assertEqual(policy.runtime_modules('macos'), policy.RUNTIME)
        self.assertEqual(
            policy.runtime_modules('windows'),
            (policy.RUNTIME - {'production_entry'}) | policy.WINDOWS_EXTRA)
        self.assertEqual(
            policy.runtime_modules('linux-desktop'),
            (policy.RUNTIME - {'production_entry'}) | policy.LINUX_EXTRA)

    def test_probes_scenarios_and_package_entry_are_excluded_from_every_runtime(self):
        policy = _packaging()
        watched = set()
        for path in (ROOT / 'src' / 'wam_regtest').glob('*.py'):
            stem = path.stem
            if (fnmatch.fnmatch(stem, 'q0*_probe') or fnmatch.fnmatch(stem, '*_scenario')
                    or stem in {'wallet_probe', 'security_probe', 'reopen_probe', 'package_entry'}):
                watched.add(stem)
        for required in ('package_entry', 'wallet_probe', 'security_probe', 'reopen_probe',
                         'q02_probe', 'q06_spend_probe'):
            self.assertIn(required, watched)
        self.assertTrue(any(fnmatch.fnmatch(name, '*_scenario') for name in watched))
        for platform in ('macos', 'windows', 'linux-desktop'):
            overlap = watched & policy.runtime_modules(platform)
            self.assertEqual(overlap, set(), '%s still ships %s' % (platform, sorted(overlap)))

    def test_developer_argv_contains_every_package_entry_ci_flag(self):
        policy = _packaging()
        accepted = _ci_flags(ROOT / 'src/wam_regtest/package_entry.py')
        present = {item for group in policy.DEVELOPER_ARGV for item in group
                   if type(item) is str and item.startswith('--ci-')}
        self.assertTrue(accepted)
        self.assertTrue(accepted <= present, sorted(accepted - present))


class RuntimeLayering(unittest.TestCase):
    """F-10. macOS RUNTIME must not grow edges into non-runtime modules."""

    def test_no_new_runtime_import_of_a_non_runtime_module(self):
        module_level, function_level = _runtime_import_edges()
        self.assertEqual(module_level, set())
        self.assertEqual(function_level, set(RUNTIME_FUNCTION_IMPORTS))


class ImportOrigin(unittest.TestCase):
    """F-18. The suite must not import the legacy audit workspace.

    wam_regtest comes from this clone. wam_sp is not tracked here; the
    interpreter supplies the pinned wsp-upstream tree. Both must stay off
    any sys.path entry containing WAM-Q06-Audit-20261102.
    """

    def test_packages_do_not_resolve_through_the_legacy_audit_workspace(self):
        import wam_regtest
        import wam_sp
        regtest_file = Path(wam_regtest.__file__).resolve()
        wsp_file = Path(wam_sp.__file__).resolve()
        regtest_entry = _supplying_entry(regtest_file, 'wam_regtest')
        wsp_entry = _supplying_entry(wsp_file, 'wam_sp')
        self.assertEqual(regtest_entry, (ROOT / 'src').resolve())
        self.assertEqual(regtest_file, regtest_entry / 'wam_regtest' / '__init__.py')
        self.assertEqual(wsp_entry.name, 'src')
        self.assertEqual(wsp_entry.parent.name, 'wsp-upstream')
        self.assertEqual(wsp_file, wsp_entry / 'wam_sp' / '__init__.py')
        for label, path in (
                ('wam_regtest', regtest_file),
                ('wam_sp', wsp_file),
                ('wam_regtest sys.path entry', regtest_entry),
                ('wam_sp sys.path entry', wsp_entry)):
            self.assertNotIn(LEGACY_WORKSPACE, str(path), label)
        for entry in sys.path:
            self.assertNotIn(LEGACY_WORKSPACE, entry)


def _supplying_entry(filename, package):
    """First sys.path entry whose package/__init__.py is the loaded file."""
    filename = Path(filename).resolve()
    for entry in sys.path:
        if not entry:
            continue
        root = Path(entry).resolve()
        if (root / package / '__init__.py') == filename:
            return root
    raise AssertionError('no sys.path entry supplied %s' % filename)


if __name__ == '__main__':
    unittest.main()
