"""PM-007: one Core compatibility descriptor (audit F-11; invariants I-2, I-7, I-16)."""
import ast
import importlib.util
import unittest
from pathlib import Path

from wam_regtest.infrastructure import core_compat

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src' / 'wam_regtest'
# Intake pins: signed-archive names/sizes/hashes are version-specific records by nature.
INTAKE_PIN_MODULES = {'official_core_v013', 'release', 'windows_release_preflight', 'q05_platforms',
                      'infrastructure.core_compat'}


def _policy():
    spec = importlib.util.spec_from_file_location('pm007_policy', ROOT / 'scripts/production_packaging.py')
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    return policy


class Descriptor(unittest.TestCase):
    def test_values_are_the_persisted_and_wire_contracts(self):
        # Persisted in supervisor.profile 'version' and the getnetworkinfo identity: never change silently.
        self.assertEqual(core_compat.CORE_RELEASE, 'v0.1.13')
        self.assertEqual(core_compat.SUPPORTED_RPC, (113, '/WAM:0.1.13/', 70016))
        self.assertEqual(core_compat.DISPLAY_NAME, 'WAM Core v0.1.13')

    def test_intake_pins_agree_with_the_descriptor(self):
        from wam_regtest import official_core_v013, release, q05_platforms, windows_release_preflight
        self.assertEqual(official_core_v013.VERSION, core_compat.CORE_RELEASE)
        self.assertEqual(release.VERSION, core_compat.CORE_RELEASE)
        self.assertEqual(windows_release_preflight.ROOT, 'wam-coin-' + core_compat.CORE_RELEASE)
        self.assertEqual(q05_platforms.DarwinArm64Adapter.core_version, core_compat.CORE_RELEASE)

    def test_consumers_use_the_descriptor(self):
        from wam_regtest import json_rpc
        self.assertIs(json_rpc.SUPPORTED_RPC, core_compat.SUPPORTED_RPC)

    def test_descriptor_imports_nothing(self):
        tree = ast.parse((SRC / 'infrastructure/core_compat.py').read_text())
        self.assertFalse([n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))])


class NoScatteredCoreVersion(unittest.TestCase):
    def test_runtime_code_names_the_core_version_only_in_the_descriptor_and_intake_pins(self):
        policy = _policy()
        offenders = []
        for platform in ('macos', 'windows', 'linux-desktop'):
            for name in sorted(policy.runtime_modules(platform)):
                if name in INTAKE_PIN_MODULES:
                    continue
                tree = ast.parse(policy.module_path(ROOT, name).read_text())
                docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                              if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef))
                              and node.body and isinstance(node.body[0], ast.Expr)
                              and isinstance(node.body[0].value, ast.Constant)}
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Constant) or id(node) in docstrings:
                        continue
                    value = node.value
                    if (isinstance(value, str) and '0.1.13' in value) or value in (70016,):
                        offenders.append((platform, name, node.lineno, value))
        self.assertEqual(offenders, [])


if __name__ == '__main__':
    unittest.main()
