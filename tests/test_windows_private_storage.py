"""Actual Win32 ACL/owner/reparse/atomic publication; not real-Core E2E."""
from pathlib import Path
import os,secrets,subprocess,sys,tempfile,unittest
from wam_regtest import windows_private_storage as store

@unittest.skipUnless(sys.platform=='win32','Native Win64 custody only')
class NativeWindowsCustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='wam-win-custody-');self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.private=self.base/'private'
        store.create_private_directory(self.private)
        self.blob=b'WAMSP02\x00'+secrets.token_bytes(80)
    def test_owner_only_directory_and_create_only_ciphertext(self):
        store.validate_directory(self.private);store.publish(self.private,'test.enc',self.blob)
        self.assertEqual(store.read(self.private,'test.enc'),self.blob)
        with self.assertRaises(store.WindowsCustodyError):store.publish(self.private,'test.enc',self.blob)
        self.assertEqual(store.read(self.private,'test.enc'),self.blob)
        self.assertFalse(list(self.private.glob('.stage-*')))
    def test_default_public_inherited_directory_rejected_without_repair(self):
        with self.assertRaises(store.WindowsCustodyError):store.validate_directory(self.base)
    def test_junction_and_hardlink_denied(self):
        target=self.private/'real';store.create_private_directory(target)
        link=self.private/'junction'
        p=subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],capture_output=True)
        self.assertEqual(p.returncode,0)
        self.addCleanup(lambda:os.rmdir(link) if link.exists() else None)
        with self.assertRaises(store.WindowsCustodyError):store.validate_directory(link)
        with self.assertRaises(store.WindowsCustodyError):store.create_private_directory(link/'child')
        store.publish(self.private,'test.enc',self.blob)
        os.link(self.private/'test.enc',self.private/'alias.enc')
        with self.assertRaises(store.WindowsCustodyError):store.read(self.private,'test.enc')
    def test_world_acl_and_wrong_owner_denied(self):
        import ctypes
        for suffix,descriptor in (('world','O:'+store.owner_sid()+'D:P(A;OICI;FA;;;WD)'),
                                  ('wrong-owner','O:BAD:P(A;OICI;FA;;;'+store.owner_sid()+')')):
            path=self.base/suffix
            with store.security_attributes(directory=True,descriptor=descriptor) as sa:
                self.assertTrue(store.mkdir(str(path),sa))
            with self.assertRaises(store.WindowsCustodyError):store.validate_directory(path)
    def test_ancestor_and_private_directory_cannot_be_renamed_while_pinned(self):
        moved=self.base/'moved'
        with store.directory_guard(self.private):
            with self.assertRaises(OSError):os.rename(self.private,moved)
            with self.assertRaises(OSError):os.rename(self.base,self.base.with_name(self.base.name+'-moved'))
        os.rename(self.private,moved);os.rename(moved,self.private)
        store.validate_directory(self.private)
    def test_bad_names_and_envelopes_never_publish(self):
        for name in ('../escape.enc','con.enc','test.enc:stream','UPPER.enc','a.enc '):
            with self.assertRaises(store.WindowsCustodyError):store.publish(self.private,name,self.blob)
        for blob in (b'',b'not-a-ciphertext'*5):
            with self.assertRaises(store.WindowsCustodyError):store.publish(self.private,'bad.enc',blob)
    def test_spawned_reader_reopens_same_bytes(self):
        store.publish(self.private,'test.enc',self.blob)
        code='from pathlib import Path;import sys,hashlib;from wam_regtest.windows_private_storage import read;print(hashlib.sha256(read(Path(sys.argv[1]),"test.enc")).hexdigest())'
        p=subprocess.run([sys.executable,'-c',code,str(self.private)],capture_output=True,text=True,timeout=15)
        import hashlib
        self.assertEqual(p.returncode,0);self.assertEqual(p.stdout.strip(),hashlib.sha256(self.blob).hexdigest())

    def test_terminated_writer_leaves_only_unpublished_ciphertext(self):
        import time
        store.publish(self.private,'test.enc',self.blob)
        code = """
from pathlib import Path
import ctypes,time,sys
from wam_regtest import windows_private_storage as s
root=Path(sys.argv[1])
with s.directory_guard(root),s.security_attributes() as sa:
    h=s.create(str(root/'.stage-interrupted'),0xc0030000,1,sa,1,0x80200080,None)
    assert h not in (None,s.INVALID)
    blob=b'WAMSP02\\x00'+b'c'*80
    buf=ctypes.create_string_buffer(blob);count=s.w.DWORD()
    assert s.write(h,buf,len(blob),ctypes.byref(count),None) and count.value==len(blob)
    assert s.flush(h)
    s.publish(root,'ready.enc',blob)
    time.sleep(60)
"""
        p=subprocess.Popen([sys.executable,'-c',code,str(self.private)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline=time.monotonic()+10
            while not (self.private/'ready.enc').exists() and p.poll() is None and time.monotonic()<deadline:
                time.sleep(.05)
            self.assertTrue((self.private/'ready.enc').exists(),'native writer did not reach flushed pre-publication phase')
            p.kill();p.wait(timeout=5)
            self.assertFalse((self.private/'snapshot-000000002.enc').exists())
            self.assertEqual(store.read(self.private,'test.enc'),self.blob)
            self.assertTrue((self.private/'.stage-interrupted').exists())
            with self.assertRaises(store.WindowsCustodyError):store.publish(self.private,'test.enc',self.blob)
            self.assertEqual(store.read(self.private,'test.enc'),self.blob)
        finally:
            if p.poll() is None:p.kill()
            p.wait(timeout=5)

    def test_plain_mkdir_root_is_refused_by_exclusive_lease(self):
        from wam_regtest.supervisor_store import exclusive_lease
        bare = self.base / 'wam-fusion-core-abcdef0123456789'
        bare.mkdir()
        with self.assertRaises(store.WindowsCustodyError):
            with exclusive_lease(bare):
                pass

    def test_native_win32_quit_notice_lease_publish_read_ack_and_orphan(self):
        from wam_regtest.quit_notice import (
            QuitNoticeError,
            acknowledge_unresolved,
            publish_notice,
            read_store,
            unacknowledged,
        )
        from wam_regtest.supervisor_store import exclusive_lease
        root = self.base / 'wam-fusion-core-0123456789abcdef'
        store.create_private_directory(root)
        profile_id = 'a' * 32
        # Missing lease must refuse publish.
        with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
            publish_notice(
                root, profile_id=profile_id, session_kind='Q05',
                wallet_outcome='RUNTIME_PRESERVED', core_stop='CLEAN',
                codes=('MANAGED_LIVE_OWNER_CLOSE_DENIED',), journal_seq=1,
            )
        # Empty store reads cleanly with or without lease.
        self.assertEqual(unacknowledged(root, expected_profile_id=profile_id), ())
        with exclusive_lease(root):
            pub = publish_notice(
                root, profile_id=profile_id, session_kind='Q05',
                wallet_outcome='RUNTIME_PRESERVED', core_stop='UNCERTAIN',
                codes=('MANAGED_LIVE_OWNER_CLOSE_DENIED',), journal_seq=2,
            )
            self.assertEqual(pub['seq'], 1)
            unresolved = unacknowledged(root, expected_profile_id=profile_id)
            self.assertEqual(len(unresolved), 1)
            self.assertEqual(unresolved[0]['kind'], 'notice')
            self.assertEqual(unresolved[0]['body_sha256'], pub['body_sha256'])
            # Wrong profile surfaces as unreadable, never silently ignored.
            wrong = read_store(root, expected_profile_id='b' * 32)
            self.assertEqual(len(wrong['notices']), 0)
            self.assertEqual(len(wrong['unreadable']), 1)
            self.assertEqual(wrong['unreadable'][0]['reason'], 'QUIT_NOTICE_PROFILE_MISMATCH')
            # Orphan stage file surfaces as unreadable NOTICE_STAGE_ORPHAN.
            orphan = root / 'supervisor.notice.stage-0123456789abcdef'
            with store.directory_guard(root), store.security_attributes() as sa:
                h = store.create(str(orphan), 0xc0000000, 0, sa, 1, 0x200080, None)
                self.assertNotIn(h, (None, store.INVALID))
                store.close(h)
            with_orphan = unacknowledged(root, expected_profile_id=profile_id)
            self.assertEqual({x['kind'] for x in with_orphan}, {'notice', 'unreadable'})
            self.assertTrue(any(x.get('reason') == 'NOTICE_STAGE_ORPHAN' for x in with_orphan))
            # Acknowledge both notice and orphan stage.
            acks = acknowledge_unresolved(root, expected_profile_id=profile_id)
            self.assertEqual(len(acks), 2)
            self.assertEqual(unacknowledged(root, expected_profile_id=profile_id), ())
        # Persists cleanly across reopen without lease.
        self.assertEqual(unacknowledged(root, expected_profile_id=profile_id), ())


class WindowsCustodyHostScope(unittest.TestCase):
    def test_native_scope_not_simulated_on_other_hosts(self):
        if sys.platform!='win32':
            with self.assertRaisesRegex(store.WindowsCustodyError,'WIN_CUSTODY_NATIVE_X64_REQUIRED'):
                store.create_private_directory(Path('/not-a-windows-datadir'))
        else:store.require_native()
