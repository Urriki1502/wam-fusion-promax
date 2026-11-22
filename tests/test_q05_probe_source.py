"""Literal runtime bytes cannot be waived by CI artifact/index status."""
from hashlib import sha1
from pathlib import Path
import tempfile
import unittest
import os
import subprocess
from unittest.mock import patch

from wam_regtest.probe_source import verify_python_tree,ProbeSourceError,local_audit_documents


class CiProbeSourceContracts(unittest.TestCase):
    """Use real Git objects, including a two-parent PR checkout."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Source contract fixture')
        self.git('config', 'user.email', 'source-contract@example.invalid')
        self.file = self.root / 'src/wam_regtest/__init__.py'
        self.file.parent.mkdir(parents=True)
        self.file.write_text('value = 1\n')
        self.commit('base')
        base = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-qb', 'candidate')
        self.file.write_text('value = 2\n')
        self.candidate = self.commit('candidate')
        self.git('checkout', '-qb', 'base-docs', base)
        (self.root / 'README.md').write_text('Non-runtime base update\n')
        self.commit('docs')
        self.git('checkout', '-q', 'candidate')
        self.git('merge', '-q', '--no-ff', 'base-docs', '-m', 'PR merge fixture')
        self.head = self.git('rev-parse', 'HEAD')
        self.env = {'GITHUB_ACTIONS': 'true',
                    'GITHUB_REPOSITORY': 'Urriki1502/wam-fusion-promax',
                    'GITHUB_SHA': self.head, 'WAM_SOURCE_HEAD': self.candidate}

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root,
                                       stderr=subprocess.PIPE, text=True).strip()

    def commit(self, message):
        self.git('add', '.')
        self.git('commit', '-qm', message)
        return self.git('rev-parse', 'HEAD')

    def verify(self):
        import wam_regtest
        from wam_regtest.probe_source import verify_source
        # The fixture substitutes only the imported-package location. All Git
        # objects, file enumeration, byte hashes and status checks remain real.
        env = dict(os.environ)
        for key in ('GITHUB_ACTIONS', 'GITHUB_REPOSITORY', 'GITHUB_SHA', 'WAM_SOURCE_HEAD'):
            env.pop(key, None)
        env.update(self.env)
        with patch.dict(os.environ, env, clear=True), \
                patch.object(wam_regtest, '__file__', str(self.file)):
            return verify_source(self.root)

    def test_authorized_repositories_accept_runtime_identical_pr_merge(self):
        for repo in ('Urriki1502/wam-fusion-promax',
                     'Urriki1502/wam-privacy-wallet-regtest'):
            with self.subTest(repository=repo):
                self.env['GITHUB_REPOSITORY'] = repo
                try:
                    proof = self.verify()
                except ProbeSourceError as error:
                    self.fail('Authorized exact runtime refused: ' + str(error))
                self.assertEqual(proof['checkout_sha'], self.head)
                self.assertEqual(proof['candidate_source_sha'], self.candidate)
                self.assertNotEqual(self.head, self.candidate)
                self.assertEqual(proof['literal_python_files_verified'], 1)

    def test_unknown_repository_and_missing_or_mismatched_context_refuse(self):
        self.env['GITHUB_REPOSITORY'] = 'Urriki1502/wam-privacy-wallet-regtest'
        for key, value in (('GITHUB_REPOSITORY', 'attacker/wam-fusion-promax'),
                           ('GITHUB_REPOSITORY', 'Urriki1502/wam-fusion-promax-extra'),
                           ('GITHUB_REPOSITORY', 'https://github.com/Urriki1502/wam-fusion-promax'),
                           ('GITHUB_SHA', None), ('GITHUB_SHA', self.candidate),
                           ('WAM_SOURCE_HEAD', ''), ('WAM_SOURCE_HEAD', 'not-a-sha')):
            with self.subTest(key=key, value=value):
                before = dict(self.env)
                if value is None:
                    self.env.pop(key, None)
                else:
                    self.env[key] = value
                try:
                    with self.assertRaisesRegex(ProbeSourceError, 'CI_SOURCE_CONTEXT_DENIED'):
                        self.verify()
                finally:
                    self.env = before

    def test_runtime_merge_drift_dirty_and_untracked_python_refuse(self):
        self.env['GITHUB_REPOSITORY'] = 'Urriki1502/wam-privacy-wallet-regtest'
        self.file.write_text('value = 3\n')
        with self.assertRaisesRegex(ProbeSourceError, 'CLEAN_SOURCE_REQUIRED'):
            self.verify()
        self.head = self.commit('runtime drift in checkout')
        self.env['GITHUB_SHA'] = self.head
        with self.assertRaisesRegex(ProbeSourceError, 'CANDIDATE_CHECKOUT_PYTHON_DIFFERS'):
            self.verify()
        self.env['WAM_SOURCE_HEAD'] = self.head
        (self.file.parent / 'shadow.py').write_text('value = 4\n')
        with self.assertRaisesRegex(ProbeSourceError, 'UNTRACKED_PYTHON_INPUT_DENIED'):
            self.verify()


class NativeProbeSourceContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.file=self.root/'src/wam_regtest/test.py'
        self.file.parent.mkdir(parents=True);self.file.write_bytes(b'value = 1\n')
        raw=self.file.read_bytes()
        self.tree={'src/wam_regtest/test.py':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

    def test_exact_source_and_non_code_artifacts_are_distinct(self):
        (self.root/'public-receipt.json').write_text('{}')
        digests,normalized=verify_python_tree(self.root,self.tree,self.tree)
        self.assertEqual(len(digests),1);self.assertFalse(normalized)

    def test_tracked_byte_change_cannot_hide_behind_clean_index_status(self):
        self.file.write_bytes(b'value = 2\n')
        with self.assertRaisesRegex(ProbeSourceError,'LITERAL_SOURCE_BYTES_DENIED'):
            verify_python_tree(self.root,self.tree,self.tree)

    def test_untracked_python_and_different_candidate_checkout_are_denied(self):
        extra=self.file.with_name('untracked.py');extra.write_bytes(b'value = 1\n')
        with self.assertRaises(ProbeSourceError):verify_python_tree(self.root,self.tree,self.tree)
        extra.unlink()
        with self.assertRaisesRegex(ProbeSourceError,'CANDIDATE_CHECKOUT_PYTHON_DIFFERS'):
            verify_python_tree(self.root,self.tree,{**self.tree,'scripts/other.py':'a'*40})

    def test_python_crlf_records_raw_digest_but_other_byte_changes_refuse(self):
        self.file.write_bytes(b'value = 1\r\n')
        _,normalized=verify_python_tree(self.root,self.tree,self.tree)
        self.assertTrue(normalized)
        self.file.write_bytes(b'value = 9\r\n')
        with self.assertRaises(ProbeSourceError):verify_python_tree(self.root,self.tree,self.tree)

    def test_retained_owner_audit_is_hashed_without_staging_or_changing_it(self):
        name='docs/INDEPENDENT_RC_AUDIT_56ea3618.md'
        path=self.root/name;path.parent.mkdir();path.write_bytes(b'public retained audit\n')
        before=path.stat()
        from hashlib import sha256
        self.assertEqual(local_audit_documents(self.root,b'?? '+name.encode()+b'\n'),
                         {name:sha256(path.read_bytes()).hexdigest()})
        self.assertEqual(path.stat(),before)

    def test_untracked_code_unknown_docs_and_tracked_edits_still_refuse(self):
        for status in (b'?? src/extra.py\n',b'?? docs/unknown.md\n',
                       b' M src/wam_regtest/test.py\n',b'A  scripts/other.py\n'):
            with self.assertRaisesRegex(ProbeSourceError,'CLEAN_SOURCE_REQUIRED'):
                local_audit_documents(self.root,status)

    def test_named_owner_security_instructions_are_hashed_as_non_runtime(self):
        from hashlib import sha256
        names = (
            'docs/security-audit/WAM_Fusion_PreMainnet_Security_Audit_Charter_2026-11-06.md',
            'docs/security-audit/WAM_Fusion_Security_Remediation_Design_Review_2026-11-06.md')
        expected = {}
        for name in names:
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'public owner instructions\n')
            expected[name] = sha256(path.read_bytes()).hexdigest()
        status = b''.join(b'?? '+name.encode()+b'\n' for name in names)
        self.assertEqual(local_audit_documents(self.root, status), expected)
        for name in names:
            self.assertEqual((self.root/name).read_bytes(), b'public owner instructions\n')

    def test_exact_owner_adr_package_is_recorded_but_no_folder_wide_exclusion(self):
        from hashlib import sha256
        parent='WAM_Fusion_ADR_Gap_Audit_Codex_2026-11-06/'
        names=[parent+'WAM_Fusion_'+name+'_2026-11-06.md'
               for name in ('ADR','Q10_Q20_Gap_Audit','Codex_Handoff')]
        expected={}
        for name in names:
            path=self.root/name;path.parent.mkdir(exist_ok=True)
            path.write_bytes(b'retained public ADR\n')
            expected[name]=sha256(path.read_bytes()).hexdigest()
        status=b''.join(b'?? '+name.encode()+b'\n' for name in names)
        self.assertEqual(local_audit_documents(self.root,status),expected)
        for unknown in ('extra.md','shadow.py'):
            with self.assertRaisesRegex(ProbeSourceError,'CLEAN_SOURCE_REQUIRED'):
                local_audit_documents(self.root,status+b'?? '+(parent+unknown).encode()+b'\n')

    @unittest.skipIf(os.name=='nt','POSIX metadata; native Windows reparse/custody has separate contracts')
    def test_retained_audit_cannot_be_executable_symlink_or_hardlink(self):
        name='docs/INDEPENDENT_RC_AUDIT_56ea3618.md'
        path=self.root/name;path.parent.mkdir();path.write_bytes(b'audit\n')
        status=b'?? '+name.encode()+b'\n'
        path.chmod(0o700)
        with self.assertRaises(ProbeSourceError):local_audit_documents(self.root,status)
        path.chmod(0o600)
        link=path.with_name('second');os.link(path,link)
        with self.assertRaises(ProbeSourceError):local_audit_documents(self.root,status)
        link.unlink();path.unlink();path.symlink_to(self.file)
        with self.assertRaises(ProbeSourceError):local_audit_documents(self.root,status)
