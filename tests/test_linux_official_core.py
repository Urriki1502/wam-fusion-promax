"""Official Linux policy refuses mutable/foreign authority before execution."""
from hashlib import sha256
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from wam_regtest import linux_official_core as official
from wam_regtest.linux_developer_core import LinuxCoreError

class OfficialLinuxPolicy(unittest.TestCase):
    def test_foreign_manifest_is_refused_without_filesystem_or_exec(self):
        with patch.object(official,'native'),patch('wam_regtest.linux_private_storage._walk') as walk:
            for pin,authorized in [('0'*64,True),(official.MANIFEST_SHA256,False),('1e8d6cbd3039fb7f80d26118c6e7c10c8defa654460072b6a3471d7f41cece4d',True)]:
                with self.assertRaisesRegex(LinuxCoreError,'LINUX_OFFICIAL_MANIFEST_APPROVAL_REQUIRED'):
                    official.verify(Path('/nonexistent'),pin,authorized=authorized)
            walk.assert_not_called()

    def test_changed_source_manifest_cannot_repin_itself(self):
        self.assertEqual(sha256(official.manifest_bytes()).hexdigest(),official.MANIFEST_SHA256)
        self.assertEqual(sha256(official.manifest_bytes(official.LEGACY_MANIFEST_SHA256)).hexdigest(),
                         official.LEGACY_MANIFEST_SHA256)
        self.assertEqual(set(official.APPROVED_MANIFESTS),
                         {official.LEGACY_MANIFEST_SHA256, official.MANIFEST_SHA256})
        with self.assertRaisesRegex(LinuxCoreError,'LINUX_OFFICIAL_MANIFEST_APPROVAL_REQUIRED'):
            official.manifest_bytes('0'*64)
        with patch.dict(official.EXPECTED,{'official_signed_release':False}):
            with self.assertRaisesRegex(LinuxCoreError,'MANIFEST_SOURCE_DENIED'):official.manifest_bytes()

    @unittest.skipUnless(os.name=='posix','Native no-follow metadata primitive')
    def test_tampered_library_identity_raises_loader_identity_denied(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / official.MANIFEST_NAME).write_bytes(official.manifest_bytes())
            (root / 'SHA256SUMS').write_bytes(b's')
            (root / 'SHA256SUMS.asc').write_bytes(b'a')
            (root / 'SIGNING-KEY.asc').write_bytes(b'k')
            (root / 'wamd').write_bytes(b'w')
            (root / 'wam-cli').write_bytes(b'c')
            for p in root.iterdir():
                p.chmod(0o600)
            bad_libs = dict(official.EXPECTED['files']['wamd']['libraries'])
            bad_libs['libc.so.6'] = {'path': '/usr/lib/x86_64-linux-gnu/libc.so.6', 'sha256': '0' * 64}
            with patch.object(official, 'native'), \
                 patch('wam_regtest.linux_private_storage._walk', return_value=os.open(root, os.O_RDONLY)), \
                 patch.object(official, 'SUMS_SHA256', sha256(b's').hexdigest()), \
                 patch.object(official, 'SIGNATURE_SHA256', sha256(b'a').hexdigest()), \
                 patch.object(official, 'SIGNING_KEY_SHA256', sha256(b'k').hexdigest()), \
                 patch.object(official, '_public', side_effect=lambda p, lim: p.read_bytes()), \
                 patch.dict(official.MEMBERS, {'linux-x86_64': {'wamd': sha256(b'w').hexdigest(),
                                                                'wam-cli': sha256(b'c').hexdigest()}}), \
                 patch.object(official, '_read_binary', side_effect=lambda p: p.read_bytes()), \
                 patch.object(official, 'inspect_elf', return_value=official.EXPECTED['files']['wamd']['elf']), \
                 patch.object(official, '_system_file', return_value=official.EXPECTED['files']['wamd']['loader']), \
                 patch.object(official, 'library_identity', return_value=bad_libs):
                with self.assertRaisesRegex(LinuxCoreError, 'LINUX_LOADER_LIBRARY_IDENTITY_DENIED'):
                    official.verify(root, official.MANIFEST_SHA256, authorized=True)

    @unittest.skipUnless(os.name=='posix','Native no-follow metadata primitive')
    def test_symlink_hardlink_or_writable_public_metadata_denies(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);p=root/'manifest';p.write_bytes(b'public')
            p.chmod(0o600);self.assertEqual(official._public(p,64),b'public')
            (root/'link').symlink_to(p)
            with self.assertRaises(OSError):official._public(root/'link',64)
            os.link(p,root/'hard')
            with self.assertRaises(LinuxCoreError):official._public(p,64)
            (root/'hard').unlink();p.chmod(0o666)
            with self.assertRaises(LinuxCoreError):official._public(p,64)
