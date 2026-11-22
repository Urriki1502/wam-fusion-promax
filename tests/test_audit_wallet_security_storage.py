"""PM-093: AST storage_contract tests for scripts/audit_wallet_security.py.

Verifies that storage_contract(root) accepts the real source tree (which uses
DUR-01a fullflush.full_flush) and legacy os.fsync storage, while rejecting
mutants of encrypted_storage.py and fullflush.py. Synthetic temp dirs only.
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_audit():
    spec = importlib.util.spec_from_file_location(
        "independent_wallet_audit", REPO_ROOT / "scripts/audit_wallet_security.py"
    )
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    return audit


VALID_ENCRYPTED_STORAGE = """\
import os
from .fullflush import flush_directory, full_flush

def publish(directory, name, ciphertext):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT, 0o600)
    os.fchmod(fd, 0o600)
    full_flush(fd)
    os.close(fd)
    os.link(name, "final")
    flush_directory(fd)
"""

VALID_FULLFLUSH = """\
import os
import sys

_F_FULLFSYNC_DARWIN = 51

def full_flush(fd: int) -> None:
    if sys.platform == "darwin":
        import fcntl
        code = getattr(fcntl, "F_FULLFSYNC", _F_FULLFSYNC_DARWIN)
        fcntl.fcntl(fd, code)
        return
    os.fsync(fd)

def flush_directory(fd: int) -> None:
    os.fsync(fd)
    if sys.platform == "darwin":
        full_flush(fd)
"""


class StorageContractTests(unittest.TestCase):
    def _make_tree(self, encrypted_storage_src, fullflush_src=None, extra_files=None):
        tmp = tempfile.TemporaryDirectory(prefix="pm093-storage-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        pkg = root / "src/wam_regtest"
        pkg.mkdir(parents=True)
        (pkg / "encrypted_storage.py").write_text(encrypted_storage_src)
        if fullflush_src is not None:
            (pkg / "fullflush.py").write_text(fullflush_src)
        for rel, content in (extra_files or {}).items():
            target = pkg / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        return root

    def test_real_source_tree_passes(self):
        audit = _load_audit()
        self.assertIs(audit.storage_contract(REPO_ROOT), True)

    def test_legacy_os_fsync_storage_without_fullflush_passes(self):
        audit = _load_audit()
        src = """\
import os

def publish():
    os.fchmod(1, 0o600)
    os.fsync(1)
    os.link("a", "b")
"""
        root = self._make_tree(src)
        self.assertIs(audit.storage_contract(root), True)

    def test_valid_fullflush_import_and_constant_variants_pass(self):
        audit = _load_audit()
        variants = [
            (
                "from wam_regtest.fullflush import full_flush\n"
                "import os\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, fcntl.F_FULLFSYNC)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "from wam_regtest.fullflush import full_flush, flush_directory\n"
                "import os\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n"
                "    flush_directory(1)\n",
                "from __future__ import annotations\n"
                "import os\n"
                "from pathlib import Path\n"
                "import sys\n"
                "FULL_FLUSH_FAILED = 'FULL_FLUSH_FAILED'\n"
                "_F_FULLFSYNC_DARWIN = 51\n"
                "def full_flush(fd: int) -> None:\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 51)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd: int) -> None:\n"
                "    os.fsync(fd)\n"
                "def _helper(path: Path, flag: int = 0) -> None:\n"
                "    os.close(os.open(path, flag))\n",
            ),
        ]
        for storage_src, ff_src in variants:
            with self.subTest(storage=storage_src.splitlines()[0]):
                root = self._make_tree(storage_src, ff_src)
                self.assertIs(audit.storage_contract(root), True)

    def test_mutant_encrypted_storage_without_os_link_fails(self):
        audit = _load_audit()
        mutated = VALID_ENCRYPTED_STORAGE.replace('os.link(name, "final")', 'pass')
        root = self._make_tree(mutated, VALID_FULLFLUSH)
        self.assertIs(audit.storage_contract(root), False)

    def test_mutant_encrypted_storage_without_os_fchmod_fails(self):
        audit = _load_audit()
        mutated = VALID_ENCRYPTED_STORAGE.replace('os.fchmod(fd, 0o600)', 'pass')
        root = self._make_tree(mutated, VALID_FULLFLUSH)
        self.assertIs(audit.storage_contract(root), False)

    def test_mutant_encrypted_storage_without_any_flush_fails(self):
        audit = _load_audit()
        mutated = """\
import os
from .fullflush import flush_directory, full_flush

def publish():
    os.fchmod(1, 0o600)
    os.link("a", "b")
"""
        root = self._make_tree(mutated, VALID_FULLFLUSH)
        self.assertIs(audit.storage_contract(root), False)

    def test_mutant_fake_local_full_flush_not_imported_from_fullflush_fails(self):
        audit = _load_audit()
        mutants = [
            (
                "local_def",
                "import os\n"
                "def full_flush(fd):\n"
                "    pass\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
                None,
            ),
            (
                "wrong_module_import",
                "import os\n"
                "from .other_flush import full_flush\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
                {"other_flush.py": VALID_FULLFLUSH},
            ),
            (
                "imported_then_shadowed_locally",
                "import os\n"
                "from .fullflush import full_flush\n"
                "def full_flush(fd):\n"
                "    pass\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
                None,
            ),
            (
                "imported_then_reassigned",
                "import os\n"
                "from .fullflush import full_flush\n"
                "full_flush = lambda fd: None\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
                None,
            ),
        ]
        for label, storage_src, extra in mutants:
            with self.subTest(mutant=label):
                root = self._make_tree(storage_src, VALID_FULLFLUSH, extra)
                self.assertIs(audit.storage_contract(root), False)

    def test_mutant_full_flush_darwin_falls_back_to_os_fsync_fails(self):
        audit = _load_audit()
        mutants = [
            (
                "explicit_os_fsync_in_darwin_branch",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 51)\n"
                "        os.fsync(fd)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "missing_return_falls_through_to_os_fsync",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 51)\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "os_fsync_before_darwin_branch",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    os.fsync(fd)\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 51)\n"
                "        return\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
        ]
        for label, ff_src in mutants:
            with self.subTest(mutant=label):
                root = self._make_tree(VALID_ENCRYPTED_STORAGE, ff_src)
                self.assertIs(audit.storage_contract(root), False)

    def test_mutant_full_flush_wrapped_in_try_except_oserror_pass_fails(self):
        audit = _load_audit()
        mutants = [
            (
                "try_except_oserror_pass_inside_darwin",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        try:\n"
                "            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)\n"
                "        except OSError:\n"
                "            pass\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "try_except_exception_pass_inside_darwin",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        try:\n"
                "            fcntl.fcntl(fd, 51)\n"
                "        except Exception:\n"
                "            pass\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "try_except_oserror_pass_enclosing_darwin_branch",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    try:\n"
                "        if sys.platform == 'darwin':\n"
                "            import fcntl\n"
                "            fcntl.fcntl(fd, 51)\n"
                "            return\n"
                "    except OSError:\n"
                "        pass\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
        ]
        for label, ff_src in mutants:
            with self.subTest(mutant=label):
                root = self._make_tree(VALID_ENCRYPTED_STORAGE, ff_src)
                self.assertIs(audit.storage_contract(root), False)

    def test_mutant_fullflush_other_contract_violations_fail(self):
        audit = _load_audit()
        mutants = [
            (
                "wrong_fcntl_constant",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 0)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "wrong_getattr_fallback_constant",
                "import os, sys\n"
                "_F_FULLFSYNC_DARWIN = 99\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        code = getattr(fcntl, 'F_FULLFSYNC', _F_FULLFSYNC_DARWIN)\n"
                "        fcntl.fcntl(fd, code)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "missing_non_darwin_os_fsync",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 51)\n"
                "        return\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "missing_flush_directory",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 51)\n"
                "        return\n"
                "    os.fsync(fd)\n",
            ),
            (
                "flush_directory_without_os_fsync",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 51)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    full_flush(fd)\n",
            ),
            (
                "fcntl_shadowed_by_fake_class",
                "import os, sys\n"
                "class fcntl:\n"
                "    F_FULLFSYNC = 51\n"
                "    @staticmethod\n"
                "    def fcntl(fd, code): pass\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        fcntl.fcntl(fd, fcntl.F_FULLFSYNC)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "uncalled_lambda_fcntl_in_darwin_branch",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        _ = lambda: fcntl.fcntl(fd, 51)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "return_before_fcntl",
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        return\n"
                "        fcntl.fcntl(fd, 51)\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
        ]
        for label, ff_src in mutants:
            with self.subTest(mutant=label):
                root = self._make_tree(VALID_ENCRYPTED_STORAGE, ff_src)
                self.assertIs(audit.storage_contract(root), False)

    def test_evaluate_uses_storage_contract_and_preserves_schema(self):
        audit = _load_audit()
        import hashlib
        import shutil
        tmp = tempfile.TemporaryDirectory(prefix="pm093-eval-")
        self.addCleanup(tmp.cleanup)
        tmp_path = Path(tmp.name)
        core = tmp_path / "core"
        core.mkdir()
        pins = {}
        for bin_name in ("wamd", "wam-cli"):
            p = core / bin_name
            p.write_bytes(bin_name.encode())
            pins[bin_name] = hashlib.sha256(p.read_bytes()).hexdigest()

        root = tmp_path / "repo"
        src_pkg = root / "src/wam_regtest"
        src_pkg.mkdir(parents=True)
        for rel in (
            "src/wam_regtest/wallet_session.py",
            "src/wam_regtest/vault.py",
            "src/wam_regtest/encrypted_storage.py",
            "src/wam_regtest/fullflush.py",
        ):
            dst = root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / rel, dst)

        with patch.object(audit, "PINS", pins):
            result = audit.evaluate(root, core)
            self.assertEqual(result["schema"], "wam-regtest-independent-contracts/v1")
            self.assertEqual(
                set(result.keys()),
                {
                    "schema",
                    "status",
                    "contracts",
                    "core_sha256",
                    "wsp_source_commit",
                    "model_crash_boundaries",
                    "mutation_classes_detected",
                    "runtime_pass_flags_trusted",
                    "external_reviewer_approval",
                    "second_builder_witness",
                    "formal_verification_complete",
                    "production_qualified",
                },
            )
            self.assertEqual(
                set(result["contracts"].keys()),
                {
                    "sign_broadcast_lease",
                    "exact_sign_review_before_crypto",
                    "exact_broadcast_review_before_submission",
                    "live_inputs_before_sensitive_operations",
                    "sign_anchor_precedes_crypto",
                    "broadcast_anchor_precedes_submission",
                    "uncertain_before_submission",
                    "faults_on_crypto_or_submission_failure",
                    "crash_model_invariants",
                    "model_mutation_sensitivity",
                    "source_mutation_sensitivity",
                    "lock_closes_keys_and_plaintext_runtime",
                    "stale_writer_anchor_comparison",
                    "backup_create_only_publication_and_fsync",
                    "both_core_hashes_independently_pinned",
                },
            )
            self.assertEqual(result["status"], "INDEPENDENT_WALLET_CONTRACTS_PASS")
            self.assertIs(result["contracts"]["backup_create_only_publication_and_fsync"], True)

            # Mutating fullflush.py in the copied root must fail evaluate()
            (src_pkg / "fullflush.py").write_text(
                "import os, sys\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 51)\n"
                "        os.fsync(fd)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n"
            )
            with self.assertRaisesRegex(ValueError, "INDEPENDENT_WALLET_CONTRACT_DENIED"):
                audit.evaluate(root, core)

    def test_mutant_fullflush_rebinding_forms_fail(self):
        audit = _load_audit()
        mutants = [
            ("P1_trailing_assign_full_flush", VALID_FULLFLUSH + "full_flush = lambda fd: None\n"),
            ("P2_trailing_assign_flush_directory", VALID_FULLFLUSH + "flush_directory = lambda fd: None\n"),
            (
                "second_function_def_full_flush",
                VALID_FULLFLUSH + "def full_flush(fd):\n    pass\n",
            ),
            (
                "second_function_def_flush_directory_conditional",
                VALID_FULLFLUSH + "if True:\n    def flush_directory(fd):\n        pass\n",
            ),
            (
                "second_async_def_full_flush",
                VALID_FULLFLUSH + "async def full_flush(fd):\n    pass\n",
            ),
            (
                "second_async_def_flush_directory",
                VALID_FULLFLUSH + "async def flush_directory(fd):\n    pass\n",
            ),
            (
                "class_def_full_flush",
                VALID_FULLFLUSH + "class full_flush:\n    pass\n",
            ),
            (
                "for_target_flush_directory",
                VALID_FULLFLUSH + "for flush_directory in (lambda fd: None,):\n    pass\n",
            ),
            (
                "augassign_full_flush",
                VALID_FULLFLUSH + "full_flush += (lambda fd: None)\n",
            ),
            (
                "annassign_full_flush_with_value",
                VALID_FULLFLUSH + "full_flush: object = lambda fd: None\n",
            ),
            (
                "annassign_flush_directory_bare",
                VALID_FULLFLUSH + "flush_directory: object\n",
            ),
            (
                "namedexpr_full_flush",
                VALID_FULLFLUSH + "_ = (full_flush := (lambda fd: None))\n",
            ),
            (
                "namedexpr_in_module_comprehension",
                VALID_FULLFLUSH + "_ = [(flush_directory := (lambda fd: None)) for _ in (1,)]\n",
            ),
            (
                "global_rebinding_inside_function_full_flush",
                VALID_FULLFLUSH
                + "def _tamper():\n    global full_flush\n    full_flush = lambda fd: None\n",
            ),
            (
                "global_rebinding_inside_function_flush_directory",
                VALID_FULLFLUSH
                + "def _tamper():\n    global flush_directory\n    flush_directory = lambda fd: None\n",
            ),
            (
                "import_as_full_flush",
                VALID_FULLFLUSH + "import os as full_flush\n",
            ),
            (
                "from_import_flush_directory",
                VALID_FULLFLUSH + "from os import fsync as flush_directory\n",
            ),
            (
                "from_import_direct_full_flush",
                VALID_FULLFLUSH + "from other_mod import full_flush\n",
            ),
            (
                "del_full_flush",
                VALID_FULLFLUSH + "del full_flush\n",
            ),
            (
                "del_flush_directory",
                VALID_FULLFLUSH + "del flush_directory\n",
            ),
            (
                "setattr_module_full_flush",
                VALID_FULLFLUSH + "setattr(sys.modules[__name__], 'full_flush', lambda fd: None)\n",
            ),
            (
                "setattr_inside_function_flush_directory",
                VALID_FULLFLUSH
                + "def _tamper():\n    setattr(sys.modules[__name__], 'flush_directory', lambda fd: None)\n",
            ),
            (
                "globals_subscript_full_flush",
                VALID_FULLFLUSH + "globals()['full_flush'] = lambda fd: None\n",
            ),
            (
                "globals_update_dict_flush_directory",
                VALID_FULLFLUSH + "globals().update({'flush_directory': lambda fd: None})\n",
            ),
            (
                "globals_update_kwarg_full_flush",
                VALID_FULLFLUSH + "globals().update(full_flush=lambda fd: None)\n",
            ),
            (
                "dunder_dict_subscript_full_flush",
                VALID_FULLFLUSH
                + "sys.modules[__name__].__dict__['full_flush'] = lambda fd: None\n",
            ),
            (
                "dunder_dict_update_flush_directory",
                VALID_FULLFLUSH
                + "sys.modules[__name__].__dict__.update({'flush_directory': lambda fd: None})\n",
            ),
            (
                "bare_dunder_dict_full_flush",
                VALID_FULLFLUSH + "__dict__['full_flush'] = lambda fd: None\n",
            ),
        ]
        for label, ff_src in mutants:
            with self.subTest(mutant=label):
                root = self._make_tree(VALID_ENCRYPTED_STORAGE, ff_src)
                self.assertIs(audit.storage_contract(root), False)

    def test_mutant_encrypted_storage_rebinds_imported_fullflush_fails(self):
        audit = _load_audit()
        mutants = [
            (
                "rebind_even_with_os_fsync_present",
                "import os\n"
                "from .fullflush import full_flush\n"
                "full_flush = lambda fd: None\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    os.fsync(1)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "rebind_alias",
                "import os\n"
                "from .fullflush import full_flush as ff\n"
                "ff = lambda fd: None\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    ff(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "rebind_imported_flush_directory",
                "import os\n"
                "from .fullflush import flush_directory, full_flush\n"
                "flush_directory = lambda fd: None\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n"
                "    flush_directory(1)\n",
            ),
            (
                "rebind_namedexpr",
                "import os\n"
                "from .fullflush import full_flush\n"
                "_ = (full_flush := (lambda fd: None))\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "rebind_del",
                "import os\n"
                "from .fullflush import full_flush\n"
                "del full_flush\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    os.fsync(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "rebind_global_in_function",
                "import os\n"
                "from .fullflush import full_flush\n"
                "def _tamper():\n"
                "    global full_flush\n"
                "    full_flush = lambda fd: None\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "rebind_via_second_import_from_same_module",
                "import os\n"
                "from .fullflush import full_flush\n"
                "from .fullflush import FULL_FLUSH_FAILED as full_flush\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "rebind_via_setattr",
                "import os, sys\n"
                "from .fullflush import full_flush\n"
                "setattr(sys.modules[__name__], 'full_flush', lambda fd: None)\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "rebind_via_globals",
                "import os\n"
                "from .fullflush import full_flush\n"
                "globals()['full_flush'] = lambda fd: None\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "rebind_via_dunder_dict",
                "import os, sys\n"
                "from .fullflush import full_flush\n"
                "sys.modules[__name__].__dict__['full_flush'] = lambda fd: None\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "rebind_imported_module_attribute",
                "import os\n"
                "from . import fullflush\n"
                "fullflush.full_flush = lambda fd: None\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    fullflush.full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "rebind_imported_module_via_setattr",
                "import os\n"
                "from . import fullflush\n"
                "setattr(fullflush, 'full_flush', lambda fd: None)\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    fullflush.full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "rebind_dotted_import_module_attr",
                "import os\n"
                "import wam_regtest.fullflush\n"
                "wam_regtest.fullflush = None\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    wam_regtest.fullflush.full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
        ]
        for label, storage_src in mutants:
            with self.subTest(mutant=label):
                root = self._make_tree(storage_src, VALID_FULLFLUSH)
                self.assertIs(audit.storage_contract(root), False)

    def test_known_accepted_ast_reachability_limits_documented(self):
        """Document pre-existing, accepted AST-reachability limits (M1, M2, M3).

        Identical to the pre-existing oracle ({os.link, os.fsync, os.fchmod} <=
        ast-call-set), storage_contract() verifies AST presence and primitive
        implementation rather than control-flow reachability or fd dataflow:
          - M1: full_flush called only in dead/unrelated code while publish()
            never flushes.
          - M2: os.fsync placed behind a dead ``if False:`` branch.
          - M3: full_flush called with a wrong fd / only one of the two fds.
        """
        audit = _load_audit()
        cases = [
            (
                "M1_dead_code_call",
                "import os\n"
                "from .fullflush import full_flush\n"
                "def _dead_helper():\n"
                "    full_flush(1)\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "M2_if_false_os_fsync",
                "import os\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    if False:\n"
                "        os.fsync(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "M3_wrong_fd_or_single_fd_only",
                "import os\n"
                "from .fullflush import full_flush\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(-1)\n"
                "    os.link('a', 'b')\n",
            ),
        ]
        for label, storage_src in cases:
            with self.subTest(limitation=label):
                root = self._make_tree(storage_src, VALID_FULLFLUSH)
                self.assertIs(audit.storage_contract(root), True)

    def test_storage_oracle_bypass_cases_fail(self):
        """PEER-459 bypass scenarios (a), (b), (c), (e), (f) and all decorators must FAIL."""
        audit = _load_audit()
        source_mutants = [
            (
                "a_decorator_on_full_flush",
                "import os, sys\n"
                "def _noop(fn):\n"
                "    return os.fsync\n"
                "@_noop\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 51)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "a_decorator_on_flush_directory",
                "import os, sys\n"
                "def _noop(fn):\n"
                "    return os.fsync\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 51)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "@_noop\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "a_identity_lambda_decorator",
                "import os, sys\n"
                "@(lambda fn: fn)\n"
                "def full_flush(fd):\n"
                "    if sys.platform == 'darwin':\n"
                "        import fcntl\n"
                "        fcntl.fcntl(fd, 51)\n"
                "        return\n"
                "    os.fsync(fd)\n"
                "def flush_directory(fd):\n"
                "    os.fsync(fd)\n",
            ),
            (
                "a_decorator_on_helper_function",
                VALID_FULLFLUSH
                + "def _id(fn):\n    return fn\n@_id\ndef _helper():\n    pass\n",
            ),
            (
                "b_module_level_exec_rebind",
                VALID_FULLFLUSH + "exec('full_flush = lambda fd: None')\n",
            ),
            (
                "b_in_function_exec",
                VALID_FULLFLUSH + "def _tamper():\n    exec('full_flush = lambda fd: None')\n",
            ),
            (
                "c_module_level_eval_globals_update",
                VALID_FULLFLUSH + "eval(\"globals().update({'full_flush': lambda fd: None})\")\n",
            ),
            (
                "c_in_function_eval",
                VALID_FULLFLUSH + "def _tamper():\n    eval('1')\n",
            ),
            (
                "f_module_level_sys_modules_patch",
                VALID_FULLFLUSH + "sys.modules[__name__].full_flush = lambda fd: None\n",
            ),
            (
                "f_in_function_sys_modules_patch",
                VALID_FULLFLUSH
                + "def _tamper():\n    sys.modules[__name__].full_flush = lambda fd: None\n",
            ),
            (
                "f_in_function_sys_modules_update",
                VALID_FULLFLUSH
                + "def _tamper():\n    sys.modules.update({'wam_regtest.fullflush': None})\n",
            ),
            (
                "f_in_function_sys_modules_alias",
                VALID_FULLFLUSH + "def _tamper():\n    m = sys.modules\n",
            ),
        ]
        for label, ff_src in source_mutants:
            with self.subTest(bypass=label):
                root = self._make_tree(VALID_ENCRYPTED_STORAGE, ff_src)
                self.assertIs(audit.storage_contract(root), False)

        # (e) Shadowing on disk under src/wam_regtest/
        shadow_cases = [
            ("e_package_dir_with_init_and_py", VALID_FULLFLUSH, {"fullflush/__init__.py": "def full_flush(fd): pass\n"}, False),
            ("e_empty_namespace_dir_with_py", VALID_FULLFLUSH, {}, True),
            ("e_pyc_alongside_py", VALID_FULLFLUSH, {"fullflush.pyc": ""}, False),
            ("e_so_alongside_py", VALID_FULLFLUSH, {"fullflush.cpython-312-darwin.so": ""}, False),
            ("e_pyc_only_no_py", None, {"fullflush.pyc": ""}, False),
            ("e_so_only_no_py", None, {"fullflush.so": ""}, False),
        ]
        for label, ff_src, extra_files, make_empty_dir in shadow_cases:
            with self.subTest(bypass=label):
                root = self._make_tree(VALID_ENCRYPTED_STORAGE, ff_src, extra_files)
                if make_empty_dir:
                    (root / "src/wam_regtest/fullflush").mkdir(parents=True, exist_ok=True)
                self.assertIs(audit.storage_contract(root), False)

    def test_fullflush_disallowed_module_level_constructs_fail(self):
        audit = _load_audit()
        mutants = [
            ("expr_call_at_module_level", VALID_FULLFLUSH + "print('x')\n"),
            ("trailing_string_expr_not_docstring", VALID_FULLFLUSH + "'not a docstring'\n"),
            ("if_at_module_level", VALID_FULLFLUSH + "if True:\n    pass\n"),
            ("try_at_module_level", VALID_FULLFLUSH + "try:\n    pass\nexcept Exception:\n    pass\n"),
            ("for_at_module_level", VALID_FULLFLUSH + "for _ in (1,):\n    pass\n"),
            ("with_at_module_level", VALID_FULLFLUSH + "with open('/dev/null'):\n    pass\n"),
            ("while_at_module_level", VALID_FULLFLUSH + "while False:\n    pass\n"),
            ("class_def_at_module_level", VALID_FULLFLUSH + "class Helper:\n    pass\n"),
            ("async_def_at_module_level", VALID_FULLFLUSH + "async def helper():\n    pass\n"),
            ("star_import", "from os import *\n" + VALID_FULLFLUSH),
            ("other_import_ctypes", "import ctypes\n" + VALID_FULLFLUSH),
            ("top_level_import_fcntl", "import fcntl\n" + VALID_FULLFLUSH),
            ("from_os_import_fsync", "from os import fsync\n" + VALID_FULLFLUSH),
            ("assign_non_constant", VALID_FULLFLUSH + "MY_CONST = os.fsync\n"),
            ("assign_bool_constant", VALID_FULLFLUSH + "MY_FLAG = True\n"),
            ("assign_float_constant", VALID_FULLFLUSH + "MY_FLOAT = 1.5\n"),
            ("assign_lowercase_name", VALID_FULLFLUSH + "my_const = 1\n"),
            ("assign_dunder_name", VALID_FULLFLUSH + "__ALL__ = 'x'\n"),
            ("assign_tuple_target", VALID_FULLFLUSH + "A = B = 1\n"),
            ("duplicate_constant_assign", VALID_FULLFLUSH + "_F_FULLFSYNC_DARWIN = 0\n"),
            ("annassign_at_module_level", VALID_FULLFLUSH + "MY_CONST: int = 1\n"),
            ("non_constant_default_arg", VALID_FULLFLUSH + "def _h(fn=os.fsync):\n    pass\n"),
            ("non_constant_kw_default_arg", VALID_FULLFLUSH + "def _h(*, fn=os.fsync):\n    pass\n"),
            ("nested_function_def", VALID_FULLFLUSH + "def _h():\n    def inner():\n        pass\n"),
            ("nested_class_def", VALID_FULLFLUSH + "def _h():\n    class Inner:\n        pass\n"),
            ("nested_lambda", VALID_FULLFLUSH + "def _h():\n    fn = lambda x: x\n"),
            ("call_in_annotation", VALID_FULLFLUSH + "def _h(x: eval('1')) -> None:\n    pass\n"),
            ("import_fcntl_outside_darwin_branch", VALID_FULLFLUSH + "def _h():\n    import fcntl\n"),
            (
                "import_fcntl_in_darwin_orelse",
                VALID_FULLFLUSH
                + "def _h():\n    if sys.platform == 'darwin':\n        pass\n    else:\n        import fcntl\n",
            ),
            (
                "from_fcntl_import_inside_function",
                VALID_FULLFLUSH
                + "def _h():\n    if sys.platform == 'darwin':\n        from fcntl import F_FULLFSYNC\n",
            ),
        ]
        for label, ff_src in mutants:
            with self.subTest(construct=label):
                root = self._make_tree(VALID_ENCRYPTED_STORAGE, ff_src)
                self.assertIs(audit.storage_contract(root), False)

    def test_fullflush_disallowed_in_function_calls_and_attrs_fail(self):
        audit = _load_audit()
        mutants = [
            ("call_compile", VALID_FULLFLUSH + "def _h():\n    compile('1', 'x', 'eval')\n"),
            ("call_globals", VALID_FULLFLUSH + "def _h():\n    globals()\n"),
            ("call_locals", VALID_FULLFLUSH + "def _h():\n    locals()\n"),
            ("call_vars", VALID_FULLFLUSH + "def _h():\n    vars()\n"),
            ("call_setattr", VALID_FULLFLUSH + "def _h():\n    setattr(os, 'fsync', None)\n"),
            ("call_delattr", VALID_FULLFLUSH + "def _h():\n    delattr(os, 'fsync')\n"),
            ("call_dunder_import", VALID_FULLFLUSH + "def _h():\n    __import__('ctypes')\n"),
            ("call_builtins_eval", VALID_FULLFLUSH + "def _h():\n    builtins.eval('1')\n"),
            (
                "call_getattr_non_constant_name",
                VALID_FULLFLUSH + "def _h(attr_name):\n    getattr(os, attr_name, 0)\n",
            ),
            (
                "call_getattr_keyword_arg",
                VALID_FULLFLUSH + "def _h():\n    getattr(os, 'O_DIRECTORY', default=0)\n",
            ),
            ("call_importlib", VALID_FULLFLUSH + "def _h():\n    importlib.import_module('os')\n"),
            ("attr_dunder_dict", VALID_FULLFLUSH + "def _h():\n    return os.__dict__\n"),
            ("attr_dunder_globals", VALID_FULLFLUSH + "def _h():\n    return full_flush.__globals__\n"),
            ("attr_dunder_code", VALID_FULLFLUSH + "def _h():\n    return full_flush.__code__\n"),
            ("attr_dunder_builtins", VALID_FULLFLUSH + "def _h():\n    return os.__builtins__\n"),
            ("name_dunder_builtins", VALID_FULLFLUSH + "def _h():\n    return __builtins__\n"),
            ("attr_write_inside_function", VALID_FULLFLUSH + "def _h():\n    os.fsync = None\n"),
        ]
        for label, ff_src in mutants:
            with self.subTest(call_or_attr=label):
                root = self._make_tree(VALID_ENCRYPTED_STORAGE, ff_src)
                self.assertIs(audit.storage_contract(root), False)

    def test_disallowed_encrypted_storage_import_forms_fail(self):
        audit = _load_audit()
        mutants = [
            (
                "relative_module_import",
                "from . import fullflush\n"
                "import os\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    fullflush.full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "absolute_module_import",
                "from wam_regtest import fullflush\n"
                "import os\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    fullflush.full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "dotted_import",
                "import os\n"
                "import wam_regtest.fullflush\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    wam_regtest.fullflush.full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "relative_aliased_import",
                "from .fullflush import full_flush as ff\n"
                "import os\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    ff(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "absolute_aliased_import",
                "from wam_regtest.fullflush import full_flush as ff\n"
                "import os\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    ff(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "star_import_from_fullflush",
                "from .fullflush import *\n"
                "import os\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "non_primitive_import_from_fullflush",
                "from .fullflush import FULL_FLUSH_FAILED, full_flush\n"
                "import os\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "import_inside_function",
                "import os\n"
                "def publish():\n"
                "    from .fullflush import full_flush\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "import_inside_if_block",
                "import os\n"
                "if True:\n"
                "    from .fullflush import full_flush\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "exec_rebind_in_encrypted_storage",
                "import os\n"
                "from .fullflush import full_flush\n"
                "exec('full_flush = lambda fd: None')\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
            (
                "eval_rebind_in_encrypted_storage",
                "import os\n"
                "from .fullflush import full_flush\n"
                "eval(\"globals().update({'full_flush': lambda fd: None})\")\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    full_flush(1)\n"
                "    os.link('a', 'b')\n",
            ),
        ]
        for label, storage_src in mutants:
            with self.subTest(import_form=label):
                root = self._make_tree(storage_src, VALID_FULLFLUSH)
                self.assertIs(audit.storage_contract(root), False)

    def test_forbidden_import_aliasing_forms_fail_in_storage_and_fullflush(self):
        """PM-096: Reject Import/ImportFrom of importlib, builtins/__builtin__, sys.modules helpers."""
        import ast

        audit = _load_audit()
        forbidden_imports = [
            ("import_importlib", "import importlib"),
            ("import_importlib_alias", "import importlib as x"),
            ("import_importlib_submodule", "import importlib.util"),
            ("import_importlib_submodule_alias", "import importlib.util as iu"),
            ("import_importlib_machinery", "import importlib.machinery"),
            ("from_importlib_import_module", "from importlib import import_module"),
            ("from_importlib_import_module_alias", "from importlib import import_module as _imp"),
            ("from_importlib_star", "from importlib import *"),
            ("from_importlib_util", "from importlib.util import spec_from_file_location as s"),
            ("from_rel_import_importlib", "from . import importlib"),
            ("import_builtins", "import builtins"),
            ("import_builtins_alias", "import builtins as b"),
            ("import_builtins_submodule", "import builtins.something"),
            ("from_builtins_getattr", "from builtins import getattr as _g"),
            ("from_builtins_eval_alias", "from builtins import eval as _e"),
            ("from_builtins_star", "from builtins import *"),
            ("from_rel_import_builtins", "from . import builtins"),
            ("import_dunder_builtin", "import __builtin__"),
            ("import_dunder_builtin_alias", "import __builtin__ as b"),
            ("import_dunder_builtin_submodule", "import __builtin__.something"),
            ("from_dunder_builtin_eval_alias", "from __builtin__ import eval as _e"),
            ("from_dunder_builtin_star", "from __builtin__ import *"),
            ("from_rel_import_dunder_builtin", "from . import __builtin__"),
            ("from_sys_import_modules", "from sys import modules"),
            ("from_sys_import_modules_alias", "from sys import modules as _m"),
            ("from_sys_import_star", "from sys import *"),
            ("import_sys_modules", "import sys.modules"),
            ("import_sys_modules_alias", "import sys.modules as _sm"),
            ("from_sys_modules_import", "from sys.modules import anything"),
            ("import_sys_alias", "import sys as _s"),
            ("from_sys_meta_path_alias", "from sys import meta_path as _mp"),
            ("from_sys_path_hooks_alias", "from sys import path_hooks as _ph"),
            ("from_sys_path_importer_cache_alias", "from sys import path_importer_cache as _pic"),
            ("from_sys_getframe_alias", "from sys import _getframe as _gf"),
        ]

        legacy_fsync_storage = (
            "import os\n"
            "def publish():\n"
            "    os.fchmod(1, 0o600)\n"
            "    os.fsync(1)\n"
            "    os.link('a', 'b')\n"
        )

        # Valid fixtures remain accepted by _has_forbidden_runtime_ops.
        self.assertIs(audit._has_forbidden_runtime_ops(ast.parse(VALID_FULLFLUSH)), False)
        self.assertIs(
            audit._has_forbidden_runtime_ops(
                ast.parse(VALID_ENCRYPTED_STORAGE), allow_dynamic_getattr=True
            ),
            False,
        )

        for label, stmt in forbidden_imports:
            with self.subTest(target="direct_op", form=label):
                self.assertIs(audit._has_forbidden_runtime_ops(ast.parse(stmt)), True)

            with self.subTest(target="encrypted_storage_fullflush", form=label):
                storage_src = f"{stmt}\n{VALID_ENCRYPTED_STORAGE}"
                root = self._make_tree(storage_src, VALID_FULLFLUSH)
                self.assertIs(audit.storage_contract(root), False)

            with self.subTest(target="encrypted_storage_legacy_fsync", form=label):
                storage_src = f"{stmt}\n{legacy_fsync_storage}"
                root = self._make_tree(storage_src)
                self.assertIs(audit.storage_contract(root), False)

            with self.subTest(target="fullflush_module_level", form=label):
                ff_src = f"{stmt}\n{VALID_FULLFLUSH}"
                root = self._make_tree(VALID_ENCRYPTED_STORAGE, ff_src)
                self.assertIs(audit.storage_contract(root), False)

            with self.subTest(target="fullflush_inside_function", form=label):
                ff_src = f"{VALID_FULLFLUSH}\ndef _helper():\n    {stmt}\n"
                root = self._make_tree(VALID_ENCRYPTED_STORAGE, ff_src)
                self.assertIs(audit.storage_contract(root), False)

        # Also reject indirect sys.modules attribute access / constant getattr in encrypted_storage.py
        indirect_storage_mutants = [
            (
                "local_sys_alias_modules_attr",
                "import sys\n" + VALID_ENCRYPTED_STORAGE + "def _tamper():\n    s = sys\n    return s.modules\n",
            ),
            (
                "getattr_sys_modules_constant",
                "import sys\n" + VALID_ENCRYPTED_STORAGE + "def _tamper():\n    return getattr(sys, 'modules')\n",
            ),
            (
                "dunder_builtin_call",
                VALID_ENCRYPTED_STORAGE + "def _tamper():\n    return __builtin__.eval('1')\n",
            ),
        ]
        for label, storage_src in indirect_storage_mutants:
            with self.subTest(target="encrypted_storage_indirect", form=label):
                root = self._make_tree(storage_src, VALID_FULLFLUSH)
                self.assertIs(audit.storage_contract(root), False)


if __name__ == "__main__":
    unittest.main()
