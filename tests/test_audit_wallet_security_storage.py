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
                "from . import fullflush\n"
                "import os\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    fullflush.full_flush(1)\n"
                "    os.link('a', 'b')\n",
                "import os, sys\n"
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
                "from .fullflush import full_flush as ff\n"
                "import os\n"
                "def publish():\n"
                "    os.fchmod(1, 0o600)\n"
                "    ff(1)\n"
                "    os.link('a', 'b')\n",
                VALID_FULLFLUSH,
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


if __name__ == "__main__":
    unittest.main()
