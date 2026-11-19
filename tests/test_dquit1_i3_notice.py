"""D-QUIT-1 I3: durable quit-notice store, publish-before-release, and reader hooks.

Crash points (R-n1, R-n2) and write denials (N-d, double fault) are simulated
with monkeypatches between steps; mocked Core/owners here are never genuine-Core
proof.
"""
from contextlib import ExitStack, nullcontext
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from mnemonic import Mnemonic

import test_q05_core_supervisor as fixture
from wam_regtest import managed_wallet_session as q05_session
from wam_regtest import quit_notice as module
from wam_regtest.bip39_12 import Bip39Regtest12Keys
from wam_regtest.bip39_owner_backend import Bip39ReadOnlyBackend, Q06ReadOnlyError
from wam_regtest.core_supervisor import CoreSupervisor, DIAGNOSTIC_CODES
from wam_regtest.foundation import diagnostics
from wam_regtest.quit_notice import (
    MAX_NOTICES,
    NOTICE_CODE_ALLOWLIST,
    NOTICE_SCHEMA,
    QuitNoticeError,
    acknowledge_unresolved,
    build_notice,
    parse_notice_bytes,
    publish_ack,
    publish_notice,
    read_store,
    unacknowledged,
    validate_notice_record,
)
from wam_regtest.supervisor_client import control
from wam_regtest.supervisor_store import SupervisorStorageError, create_once, exclusive_lease, read_exact
from wam_regtest.wallet_executor import (
    FrozenDict,
    ManagedWalletBackend,
    WalletExecutor,
    WalletExecutorError,
)
from wam_regtest.wallet_session import WalletSession, WalletSessionError

PASSWORD = b'public-test-password'
PHRASE = Mnemonic('english').to_mnemonic(bytes(16))
PROFILE_ID = 'a' * 32
SOURCE = Path(importlib.util.find_spec('wam_sp').origin).resolve().parents[2]


def _private_core_root(parent):
    root = parent / 'wam-fusion-core-0123456789abcdef'
    root.mkdir(mode=0o700)
    return root


def _canonical_bytes(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True
    ).encode('ascii')


def _live_mock_owner(root, *, profile_id=PROFILE_ID):
    owner = Mock()
    owner.root = root
    owner.directory = root / 'chain'
    owner.directory.mkdir(mode=0o700, exist_ok=True)
    owner.profile = {'profile_id': profile_id}
    owner.journal = SimpleNamespace(events=[{'seq': 3, 'state': 'RUNNING'}])
    owner.process = Mock()
    owner.process.poll.return_value = None
    owner._faulted = False

    def stopped(*_a, **_kw):
        owner.process = None

    owner.shutdown.side_effect = stopped
    owner.recover_stop.side_effect = stopped
    return owner


class QuitNoticeStoreContracts(unittest.TestCase):
    def setUp(self):
        if sys.platform == 'darwin':
            from wam_regtest.custody import private_temporary_directory
            self.tmp = private_temporary_directory('wam-i3-notice-')
        else:
            self.tmp = tempfile.TemporaryDirectory(prefix='wam-i3-notice-')
        self.addCleanup(self.tmp.cleanup)
        self.root = _private_core_root(Path(self.tmp.name).resolve())

    def test_schema_and_privacy_validator_rejects_secrets_free_text_and_non_canonical(self):
        valid = build_notice(
            seq=1,
            profile_id=PROFILE_ID,
            session_kind='Q06',
            wallet_outcome='RUNTIME_PRESERVED',
            core_stop='CLEAN',
            codes=('Q06_SPEND_RUNTIME_PRESERVED', 'MANAGED_SHUTDOWN_UNCERTAIN'),
            journal_seq=4,
            created_utc='2026-11-15T08:00:00Z',
        )
        raw = _canonical_bytes(valid)
        self.assertLessEqual(len(raw), 4096)
        self.assertEqual(parse_notice_bytes(raw, expected_seq=1, expected_profile_id=PROFILE_ID), valid)

        # Allowlist is frozen and includes both Core and Q05/Q06 quit/lock codes.
        self.assertIsInstance(NOTICE_CODE_ALLOWLIST, frozenset)
        self.assertTrue(DIAGNOSTIC_CODES <= NOTICE_CODE_ALLOWLIST)
        self.assertIn('Q06_SPEND_RUNTIME_PRESERVED', NOTICE_CODE_ALLOWLIST)
        self.assertIn('WALLET_MANAGED_RUNTIME_PRESERVED', NOTICE_CODE_ALLOWLIST)

        # Reject non-canonical JSON formatting, duplicate keys, non-ASCII, constants.
        pretty = json.dumps(valid, sort_keys=True, indent=2).encode('ascii')
        with self.assertRaises(QuitNoticeError):
            parse_notice_bytes(pretty)
        unsorted = json.dumps(valid, sort_keys=False, separators=(',', ':')).encode('ascii')
        if unsorted != raw:
            with self.assertRaises(QuitNoticeError):
                parse_notice_bytes(unsorted)
        dup = raw[:-1] + b',"seq":1}'
        with self.assertRaises(QuitNoticeError):
            parse_notice_bytes(dup)
        with self.assertRaises(QuitNoticeError):
            parse_notice_bytes(raw + b'\n')
        with self.assertRaises(QuitNoticeError):
            parse_notice_bytes(b'{"schema":"\xc3\xa9"}')

        # Reject extra keys / txid / amount / address / secret / path / PID / free text.
        for bad_field in (
            {'txid': 'f' * 64},
            {'amount': 1000},
            {'address': 'wamrt1public'},
            {'secret': 'abandon ' * 11 + 'about'},
            {'path': '/Users/private/wallet'},
            {'pid': 12345},
            {'message': 'free text'},
        ):
            tampered = dict(valid, **bad_field)
            with self.subTest(bad_field=bad_field), self.assertRaises(QuitNoticeError):
                validate_notice_record(tampered)

        # Reject invalid values for valid keys (free text in codes, bool seq, >8 codes, bad date).
        nine_codes = sorted(NOTICE_CODE_ALLOWLIST)[:9]
        bad_cases = (
            {'schema': 'wam.fusion.quit-notice.v2'},
            {'seq': 0},
            {'seq': 65},
            {'seq': True},
            {'profile_id': 'not-a-profile-id'},
            {'session_kind': 'Q07'},
            {'created_utc': '2026-02-30T00:00:00Z'},
            {'created_utc': '2026-11-15T08:00:00.123456Z'},
            {'wallet_outcome': 'FREE_TEXT'},
            {'core_stop': 'KILLED'},
            {'codes': ['free text /Users/secret']},
            {'codes': nine_codes},
            {'codes': ['Q06_SPEND_RUNTIME_PRESERVED', 'Q06_SPEND_RUNTIME_PRESERVED']},
            {'journal_seq': True},
            {'journal_seq': -1},
            {'body_sha256': '0' * 64},
        )
        for patch_fields in bad_cases:
            candidate = dict(valid, **patch_fields)
            if 'body_sha256' not in patch_fields:
                body = {k: v for k, v in candidate.items() if k != 'body_sha256'}
                candidate['body_sha256'] = sha256(_canonical_bytes(body)).hexdigest()
            with self.subTest(patch_fields=patch_fields), self.assertRaises(QuitNoticeError):
                validate_notice_record(candidate)

    def test_canonical_round_trip_and_fullfsync(self):
        with exclusive_lease(self.root):
            with patch.object(module, 'full_flush', wraps=module.full_flush) as file_spy, \
                    patch.object(module, 'flush_directory', wraps=module.flush_directory) as dir_spy:
                published = publish_notice(
                    self.root,
                    profile_id=PROFILE_ID,
                    session_kind='Q05',
                    wallet_outcome='RUNTIME_PRESERVED',
                    core_stop='CLEAN',
                    codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                    journal_seq=7,
                )
        # 1 file full_flush + 2 dir flush_directory (after link, after unlink).
        self.assertEqual(file_spy.call_count, 1)
        self.assertEqual(dir_spy.call_count, 2)
        path = self.root / 'supervisor.notice.000001'
        self.assertTrue(path.exists())
        st = path.lstat()
        self.assertEqual(st.st_mode & 0o777, 0o600)
        self.assertEqual(st.st_nlink, 1)
        self.assertEqual(
            parse_notice_bytes(path.read_bytes(), expected_seq=1, expected_profile_id=PROFILE_ID),
            published,
        )
        items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['kind'], 'notice')
        self.assertEqual(items[0]['seq'], 1)
        self.assertEqual(items[0]['notice'], published)
        # supervisor_store.read_exact also accepts the new name allowlist.
        self.assertEqual(read_exact(self.root, 'supervisor.notice.000001'), _canonical_bytes(published))

    def test_publish_without_lease_refused_and_does_not_create_lock(self):
        with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
            publish_notice(
                self.root,
                profile_id=PROFILE_ID,
                session_kind='Q06',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                journal_seq=1,
            )
        self.assertFalse((self.root / 'supervisor.lock').exists())
        self.assertEqual(list(self.root.iterdir()), [])

        # Even after supervisor.lock exists, an unheld lease still refuses.
        with exclusive_lease(self.root):
            pass
        with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
            publish_notice(
                self.root,
                profile_id=PROFILE_ID,
                session_kind='Q06',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                journal_seq=1,
            )
        with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
            publish_ack(self.root, {'kind': 'notice', 'seq': 1, 'body_sha256': '0' * 64})
        with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
            acknowledge_unresolved(self.root)

    def test_child_process_lease_refuses_parent_publish_ack_and_stage_completion(self):
        # Create a staged (st_nlink==2) notice under parent's lease, then release.
        with exclusive_lease(self.root):
            with patch.object(module.os, 'unlink', side_effect=OSError('simulated-crash-after-link')):
                with self.assertRaises(QuitNoticeError):
                    publish_notice(
                        self.root,
                        profile_id=PROFILE_ID,
                        session_kind='Q05',
                        wallet_outcome='RUNTIME_PRESERVED',
                        core_stop='CLEAN',
                        codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                        journal_seq=1,
                    )
        final_path = self.root / 'supervisor.notice.000001'
        stages = [p for p in self.root.iterdir() if p.name.startswith('supervisor.notice.stage-')]
        self.assertTrue(final_path.exists())
        self.assertEqual(len(stages), 1)
        self.assertEqual(final_path.lstat().st_nlink, 2)

        repo_src = str(Path(__file__).resolve().parents[1] / 'src')
        child_code = (
            'import sys\n'
            'from pathlib import Path\n'
            'from wam_regtest.supervisor_store import exclusive_lease\n'
            'with exclusive_lease(Path(sys.argv[1])):\n'
            '    print("LEASE_HELD", flush=True)\n'
            '    sys.stdin.read()\n'
        )
        env = dict(os.environ, PYTHONPATH=repo_src)
        with subprocess.Popen(
            [sys.executable, '-c', child_code, str(self.root)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        ) as child:
            try:
                ready = child.stdout.readline().strip()
                if ready != 'LEASE_HELD':
                    child.stdin.close()
                    child.wait(timeout=10)
                    self.fail(child.stderr.read())
                self.assertEqual(ready, 'LEASE_HELD')
                with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
                    publish_notice(
                        self.root,
                        profile_id=PROFILE_ID,
                        session_kind='Q05',
                        wallet_outcome='RUNTIME_PRESERVED',
                        core_stop='CLEAN',
                        codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                        journal_seq=2,
                    )
                with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
                    publish_ack(self.root, {'kind': 'notice', 'seq': 1, 'body_sha256': '0' * 64})
                with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
                    acknowledge_unresolved(self.root, expected_profile_id=PROFILE_ID)
                with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
                    read_store(self.root, expected_profile_id=PROFILE_ID, complete_staged=True)

                # Default complete_staged=None also refuses stage completion when a child holds the lock.
                store = read_store(self.root, expected_profile_id=PROFILE_ID)
                self.assertEqual(len(store['notices']), 1)
                self.assertTrue(stages[0].exists())
                self.assertEqual(final_path.lstat().st_nlink, 2)
            finally:
                if child.stdin is not None and not child.stdin.closed:
                    child.stdin.close()
                child.wait(timeout=10)
            self.assertEqual(child.returncode, 0, child.stderr.read())

        # Once the parent itself holds exclusive_lease, stage completion succeeds.
        with exclusive_lease(self.root):
            completed = read_store(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(completed['notices']), 1)
        self.assertFalse(stages[0].exists())
        self.assertEqual(final_path.lstat().st_nlink, 1)

    def test_rn1_stage_without_link_is_unreadable_ackable_and_never_collides(self):
        def crash_before_link(*args, **kwargs):
            raise OSError('simulated-crash-before-link')

        with exclusive_lease(self.root):
            with patch.object(module.os, 'link', side_effect=crash_before_link):
                with self.assertRaises(QuitNoticeError):
                    publish_notice(
                        self.root,
                        profile_id=PROFILE_ID,
                        session_kind='Q06',
                        wallet_outcome='RUNTIME_PRESERVED',
                        core_stop='CLEAN',
                        codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                        journal_seq=2,
                    )
        stages = [p for p in self.root.iterdir() if p.name.startswith('supervisor.notice.stage-')]
        self.assertEqual(len(stages), 1)
        self.assertFalse((self.root / 'supervisor.notice.000001').exists())

        # Also add a 0-byte stage simulating an earlier crash right after O_CREAT.
        zero_stage = self.root / ('supervisor.notice.stage-' + '0' * 16)
        zero_stage.write_bytes(b'')
        zero_stage.chmod(0o600)

        unresolved = unacknowledged(self.root)
        self.assertEqual(len(unresolved), 2)
        self.assertTrue(all(item['kind'] == 'unreadable' for item in unresolved))
        self.assertEqual({item['name'] for item in unresolved}, {stages[0].name, zero_stage.name})
        self.assertIn(0, {item['size'] for item in unresolved})

        # Next publish uses a fresh random stage and seq 1 without colliding.
        with exclusive_lease(self.root):
            published = publish_notice(
                self.root,
                profile_id=PROFILE_ID,
                session_kind='Q06',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                journal_seq=3,
            )
            self.assertEqual(published['seq'], 1)
            self.assertTrue(stages[0].exists())
            self.assertTrue(zero_stage.exists())
            acknowledge_unresolved(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(unacknowledged(self.root, expected_profile_id=PROFILE_ID), ())
        # Neither the stage artifacts nor the final notice are ever deleted.
        self.assertTrue(stages[0].exists())
        self.assertTrue(zero_stage.exists())
        self.assertTrue((self.root / 'supervisor.notice.000001').exists())

    def test_rn2_link_done_stage_not_unlinked_accepted_and_completed_under_lease(self):
        with exclusive_lease(self.root):
            with patch.object(module.os, 'unlink', side_effect=OSError('simulated-crash-after-link')):
                with self.assertRaises(QuitNoticeError):
                    publish_notice(
                        self.root,
                        profile_id=PROFILE_ID,
                        session_kind='Q05',
                        wallet_outcome='RUNTIME_PRESERVED',
                        core_stop='CLEAN',
                        codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                        journal_seq=5,
                    )
        final_path = self.root / 'supervisor.notice.000001'
        stages = [p for p in self.root.iterdir() if p.name.startswith('supervisor.notice.stage-')]
        self.assertTrue(final_path.exists())
        self.assertEqual(len(stages), 1)
        self.assertEqual(final_path.lstat().st_nlink, 2)
        self.assertEqual(
            (final_path.lstat().st_dev, final_path.lstat().st_ino),
            (stages[0].lstat().st_dev, stages[0].lstat().st_ino),
        )

        # Without lease (complete_staged=False), accepted without duplicate and stage untouched.
        ro_items = unacknowledged(self.root, expected_profile_id=PROFILE_ID, complete_staged=False)
        self.assertEqual(len(ro_items), 1)
        self.assertEqual(ro_items[0]['kind'], 'notice')
        self.assertTrue(stages[0].exists())

        # Explicitly requesting completion without lease refuses.
        with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_LEASE_REQUIRED'):
            read_store(self.root, expected_profile_id=PROFILE_ID, complete_staged=True)

        # Under lease, reader accepts AND completes publication (unlink stage + flush_directory).
        with exclusive_lease(self.root):
            with patch.object(module, 'flush_directory', wraps=module.flush_directory) as sync_spy:
                items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['kind'], 'notice')
        self.assertEqual(items[0]['seq'], 1)
        self.assertFalse(stages[0].exists())
        self.assertEqual(final_path.lstat().st_nlink, 1)
        self.assertGreaterEqual(sync_spy.call_count, 1)

    def test_rn2_rejects_mismatched_hardlink_count_or_duplicate_stage_to_unreadable(self):
        with exclusive_lease(self.root):
            publish_notice(
                self.root,
                profile_id=PROFILE_ID,
                session_kind='Q05',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                journal_seq=1,
            )
        final_path = self.root / 'supervisor.notice.000001'
        extra_link = self.root / 'supervisor.notice.unexpected'
        os.link(final_path, extra_link)
        self.assertEqual(final_path.lstat().st_nlink, 2)
        with exclusive_lease(self.root):
            items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        # st_nlink==2 without a matching supervisor.notice.stage-* is unreadable!
        self.assertEqual({item['kind'] for item in items}, {'unreadable'})
        self.assertTrue(final_path.exists())
        self.assertTrue(extra_link.exists())

    def test_staged_corrupt_notice_is_one_unreadable_not_an_extra_orphan(self):
        final_path = self.root / 'supervisor.notice.000001'
        final_path.write_bytes(b'{not-valid-json')
        final_path.chmod(0o600)
        stage_path = self.root / ('supervisor.notice.stage-' + '1' * 16)
        os.link(final_path, stage_path)
        items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['kind'], 'unreadable')
        self.assertEqual(items[0]['name'], final_path.name)
        self.assertTrue(stage_path.exists())

    def test_bip39_unresolved_reader_ignores_non_supervisor_root(self):
        from types import SimpleNamespace as _NS

        from wam_regtest.bip39_owner_backend import _read_unresolved_quit_notices
        foreign = self.root.parent / 'not-a-supervisor-root'
        foreign.mkdir(mode=0o700)
        (foreign / 'supervisor.notice.000001').write_bytes(b'preserve')
        owner = _NS(root=foreign, directory=foreign)
        self.assertEqual(_read_unresolved_quit_notices(owner), ())

    def test_corrupt_and_unknown_schema_notices_are_unreadable_and_preserved(self):
        corrupt = self.root / 'supervisor.notice.000001'
        corrupt.write_bytes(b'{not-valid-json')
        corrupt.chmod(0o600)

        bad_schema = self.root / 'supervisor.notice.000002'
        payload = build_notice(
            seq=2,
            profile_id=PROFILE_ID,
            session_kind='Q06',
            wallet_outcome='RUNTIME_PRESERVED',
            core_stop='CLEAN',
            codes=('Q06_SPEND_RUNTIME_PRESERVED',),
            journal_seq=1,
        )
        payload['schema'] = 'wam.fusion.quit-notice.v99'
        bad_schema.write_bytes(_canonical_bytes(payload))
        bad_schema.chmod(0o600)

        items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items), 2)
        self.assertTrue(all(i['kind'] == 'unreadable' for i in items))
        self.assertEqual({i['name'] for i in items}, {corrupt.name, bad_schema.name})

        # Acking unreadable artifacts unblocks without deleting them.
        with exclusive_lease(self.root):
            acks = acknowledge_unresolved(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(acks), 2)
        self.assertEqual(unacknowledged(self.root, expected_profile_id=PROFILE_ID), ())
        self.assertTrue(corrupt.exists())
        self.assertTrue(bad_schema.exists())
        self.assertTrue((self.root / 'supervisor.notice-ack.000001').exists())
        self.assertTrue((self.root / 'supervisor.notice-ack.000002').exists())

    def test_capacity_64_fails_closed_and_ack_cap_exceeds_64(self):
        with exclusive_lease(self.root):
            for seq in range(1, MAX_NOTICES + 1):
                published = publish_notice(
                    self.root,
                    profile_id=PROFILE_ID,
                    session_kind='Q06',
                    wallet_outcome='RUNTIME_PRESERVED',
                    core_stop='CLEAN',
                    codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                    journal_seq=seq,
                )
                self.assertEqual(published['seq'], seq)
            with self.assertRaisesRegex(QuitNoticeError, 'QUIT_NOTICE_CAPACITY_REACHED'):
                publish_notice(
                    self.root,
                    profile_id=PROFILE_ID,
                    session_kind='Q06',
                    wallet_outcome='RUNTIME_PRESERVED',
                    core_stop='CLEAN',
                    codes=('Q06_SPEND_RUNTIME_PRESERVED',),
                    journal_seq=65,
                )
            # Also add an R-n1 orphan stage so ack count > 64.
            orphan = self.root / ('supervisor.notice.stage-' + 'f' * 16)
            orphan.write_bytes(b'partial')
            orphan.chmod(0o600)
            acks = acknowledge_unresolved(self.root, expected_profile_id=PROFILE_ID)
            self.assertEqual(len(acks), 65)
            self.assertTrue((self.root / 'supervisor.notice-ack.000065').exists())
            self.assertEqual(unacknowledged(self.root, expected_profile_id=PROFILE_ID), ())

    def test_rn2_ack_stage_completed_under_lease_and_hyphenated_unreadable_ackable(self):
        with exclusive_lease(self.root):
            published = publish_notice(
                self.root,
                profile_id=PROFILE_ID,
                session_kind='Q05',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                journal_seq=1,
            )
            with patch.object(module.os, 'unlink', side_effect=OSError('simulated-crash-after-ack-link')):
                with self.assertRaises(QuitNoticeError):
                    publish_ack(
                        self.root,
                        {
                            'kind': 'notice',
                            'seq': published['seq'],
                            'body_sha256': published['body_sha256'],
                        },
                    )
        ack_path = self.root / 'supervisor.notice-ack.000001'
        stages = [p for p in self.root.iterdir() if p.name.startswith('supervisor.notice.stage-')]
        self.assertTrue(ack_path.exists())
        self.assertEqual(len(stages), 1)
        self.assertEqual(ack_path.lstat().st_nlink, 2)

        bad_hyphen = self.root / 'supervisor.notice-corrupt'
        bad_hyphen.write_bytes(b'corrupt-artifact')
        bad_hyphen.chmod(0o600)

        with exclusive_lease(self.root):
            unresolved = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
            self.assertEqual([u['name'] for u in unresolved], ['supervisor.notice-corrupt'])
            self.assertFalse(stages[0].exists())
            self.assertEqual(ack_path.lstat().st_nlink, 1)
            acks = acknowledge_unresolved(self.root, expected_profile_id=PROFILE_ID)
            self.assertEqual(len(acks), 1)
            self.assertEqual(acks[0]['name'], 'supervisor.notice-corrupt')
        self.assertEqual(unacknowledged(self.root, expected_profile_id=PROFILE_ID), ())
        self.assertTrue(bad_hyphen.exists())

    def _spawn_publish_and_sigkill_at_boundary(
        self,
        root,
        *,
        boundary,
        profile_id=PROFILE_ID,
        session_kind='Q06',
        code='Q06_SPEND_RUNTIME_PRESERVED',
        journal_seq=1,
        ack_payload=None,
    ):
        """Spawn a child running real quit_notice publication and SIGKILL at a deterministic pipe barrier."""
        repo_root = Path(__file__).resolve().parents[1]
        pythonpath = os.pathsep.join((
            str(repo_root / 'src'),
            str(repo_root / 'wsp-upstream' / 'src'),
        ))
        child_code = (
            'import json, os, sys\n'
            'from pathlib import Path\n'
            'from wam_regtest import quit_notice as qn\n'
            'from wam_regtest.supervisor_store import exclusive_lease\n'
            'root = Path(sys.argv[1])\n'
            'profile_id, session_kind, boundary, code = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]\n'
            'journal_seq = int(sys.argv[6])\n'
            'ack_json = sys.argv[7]\n'
            'orig_link, orig_unlink = os.link, os.unlink\n'
            'def _is_stage(name):\n'
            '    return isinstance(name, str) and name.startswith("supervisor.notice.stage-")\n'
            'def _barrier(stage_name):\n'
            '    print(f"BOUNDARY_READY {stage_name}", flush=True)\n'
            '    while os.read(0, 1):\n'
            '        pass\n'
            '    os._exit(99)\n'
            'def _wrapped_link(src, dst, *args, **kwargs):\n'
            '    if boundary == "before_link" and _is_stage(src):\n'
            '        _barrier(src)\n'
            '    return orig_link(src, dst, *args, **kwargs)\n'
            'def _wrapped_unlink(path, *args, **kwargs):\n'
            '    if boundary == "before_unlink" and _is_stage(path):\n'
            '        _barrier(path)\n'
            '    return orig_unlink(path, *args, **kwargs)\n'
            'qn.os.link = _wrapped_link\n'
            'qn.os.unlink = _wrapped_unlink\n'
            'with exclusive_lease(root):\n'
            '    if ack_json:\n'
            '        qn.publish_ack(root, json.loads(ack_json))\n'
            '    else:\n'
            '        qn.publish_notice(\n'
            '            root,\n'
            '            profile_id=profile_id,\n'
            '            session_kind=session_kind,\n'
            '            wallet_outcome="RUNTIME_PRESERVED",\n'
            '            core_stop="CLEAN",\n'
            '            codes=(code,),\n'
            '            journal_seq=journal_seq,\n'
            '        )\n'
        )
        ack_arg = json.dumps(ack_payload) if ack_payload is not None else ''
        env = dict(os.environ, PYTHONPATH=pythonpath)
        proc = subprocess.Popen(
            [
                sys.executable,
                '-c',
                child_code,
                str(root),
                profile_id,
                session_kind,
                boundary,
                code,
                str(journal_seq),
                ack_arg,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            ready_line = proc.stdout.readline().strip()
            if not ready_line.startswith('BOUNDARY_READY '):
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
                proc.wait(timeout=10)
                self.fail(f'child did not reach {boundary}: stdout={ready_line!r} stderr={proc.stderr.read()!r}')
            stage_name = ready_line.split(' ', 1)[1]
            # Confirm the child still holds exclusive_lease(root) at the barrier.
            with self.assertRaisesRegex(SupervisorStorageError, '^SUPERVISOR_STORAGE_LEASE_BUSY$'):
                with exclusive_lease(root):
                    pass
            os.kill(proc.pid, signal.SIGKILL)
            returncode = proc.wait(timeout=10)
            self.assertEqual(returncode, -signal.SIGKILL)
            return stage_name, returncode
        finally:
            if proc.poll() is None:
                os.kill(proc.pid, signal.SIGKILL)
                proc.wait(timeout=10)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    stream.close()

    def _assert_apfs_if_darwin(self, path):
        if sys.platform == 'darwin':
            res = subprocess.run(
                ['df', '-T', 'apfs', str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr)

    def test_rn1_real_process_sigkill_before_link_on_apfs(self):
        self._assert_apfs_if_darwin(self.root)
        for idx, (session_kind, code) in enumerate((
            ('Q06', 'Q06_SPEND_RUNTIME_PRESERVED'),
            ('Q05', 'WALLET_MANAGED_RUNTIME_PRESERVED'),
        )):
            with self.subTest(session_kind=session_kind):
                parent = self.root.parent / f'rn1_sigkill_{idx}'
                parent.mkdir(mode=0o700, exist_ok=True)
                sub_root = _private_core_root(parent)
                self._assert_apfs_if_darwin(sub_root)

                stage_name, rc = self._spawn_publish_and_sigkill_at_boundary(
                    sub_root,
                    boundary='before_link',
                    session_kind=session_kind,
                    code=code,
                    journal_seq=2,
                )
                self.assertEqual(rc, -signal.SIGKILL)
                stage_path = sub_root / stage_name
                final_path = sub_root / 'supervisor.notice.000001'
                self.assertTrue(stage_path.exists())
                self.assertFalse(final_path.exists())
                stage_bytes = stage_path.read_bytes()
                parsed_stage = parse_notice_bytes(
                    stage_bytes, expected_seq=1, expected_profile_id=PROFILE_ID
                )
                self.assertEqual(parsed_stage['codes'], [code])

                # Reader tolerates leftover stage without lease, reports truthful unreadable state,
                # never deletes stage, and never blocks.
                store_ro = read_store(sub_root, expected_profile_id=PROFILE_ID)
                self.assertEqual(store_ro['notices'], ())
                self.assertEqual(len(store_ro['unreadable']), 1)
                self.assertEqual(store_ro['unreadable'][0]['name'], stage_name)
                self.assertEqual(store_ro['unreadable'][0]['reason'], 'NOTICE_STAGE_ORPHAN')
                self.assertEqual(store_ro['unreadable'][0]['size'], len(stage_bytes))
                self.assertEqual(
                    store_ro['unreadable'][0]['raw_sha256'],
                    sha256(stage_bytes).hexdigest(),
                )
                self.assertTrue(stage_path.exists())

                # Subsequent publication under lease succeeds cleanly at seq=1 without collision.
                with exclusive_lease(sub_root):
                    published = publish_notice(
                        sub_root,
                        profile_id=PROFILE_ID,
                        session_kind=session_kind,
                        wallet_outcome='RUNTIME_PRESERVED',
                        core_stop='CLEAN',
                        codes=(code,),
                        journal_seq=3,
                    )
                    self.assertEqual(published['seq'], 1)
                    unresolved = unacknowledged(sub_root, expected_profile_id=PROFILE_ID)
                    self.assertEqual({item['kind'] for item in unresolved}, {'notice', 'unreadable'})
                    acks = acknowledge_unresolved(sub_root, expected_profile_id=PROFILE_ID)
                    self.assertEqual(len(acks), 2)
                self.assertEqual(unacknowledged(sub_root, expected_profile_id=PROFILE_ID), ())
                self.assertTrue(stage_path.exists())
                self.assertTrue(final_path.exists())
                self.assertEqual(final_path.lstat().st_nlink, 1)

    def test_rn2_real_process_sigkill_after_link_before_unlink_on_apfs(self):
        self._assert_apfs_if_darwin(self.root)
        for idx, (session_kind, code) in enumerate((
            ('Q06', 'Q06_SPEND_RUNTIME_PRESERVED'),
            ('Q05', 'WALLET_MANAGED_RUNTIME_PRESERVED'),
        )):
            with self.subTest(session_kind=session_kind):
                parent = self.root.parent / f'rn2_sigkill_{idx}'
                parent.mkdir(mode=0o700, exist_ok=True)
                sub_root = _private_core_root(parent)
                self._assert_apfs_if_darwin(sub_root)

                stage_name, rc = self._spawn_publish_and_sigkill_at_boundary(
                    sub_root,
                    boundary='before_unlink',
                    session_kind=session_kind,
                    code=code,
                    journal_seq=5,
                )
                self.assertEqual(rc, -signal.SIGKILL)
                stage_path = sub_root / stage_name
                final_path = sub_root / 'supervisor.notice.000001'
                self.assertTrue(stage_path.exists())
                self.assertTrue(final_path.exists())
                self.assertEqual(final_path.lstat().st_nlink, 2)
                self.assertEqual(
                    (final_path.lstat().st_dev, final_path.lstat().st_ino),
                    (stage_path.lstat().st_dev, stage_path.lstat().st_ino),
                )
                final_record = parse_notice_bytes(
                    final_path.read_bytes(), expected_seq=1, expected_profile_id=PROFILE_ID
                )
                self.assertEqual(final_record['codes'], [code])

                # Without lease, reader accepts the complete linked notice without duplicating the stage.
                ro_store = read_store(sub_root, expected_profile_id=PROFILE_ID, complete_staged=False)
                self.assertEqual(len(ro_store['notices']), 1)
                self.assertEqual(ro_store['unreadable'], ())
                self.assertEqual(ro_store['notices'][0]['notice'], final_record)
                self.assertTrue(stage_path.exists())

                # Under lease, reader accepts AND completes publication (unlink stage + F_FULLFSYNC).
                with exclusive_lease(sub_root):
                    completed = read_store(sub_root, expected_profile_id=PROFILE_ID)
                    self.assertEqual(len(completed['notices']), 1)
                    self.assertEqual(completed['unreadable'], ())
                    self.assertFalse(stage_path.exists())
                    self.assertEqual(final_path.lstat().st_nlink, 1)
                    acknowledge_unresolved(sub_root, expected_profile_id=PROFILE_ID)
                self.assertEqual(unacknowledged(sub_root, expected_profile_id=PROFILE_ID), ())
                self.assertTrue(final_path.exists())

    def test_rn2_real_process_sigkill_ack_before_unlink_on_apfs(self):
        self._assert_apfs_if_darwin(self.root)
        with exclusive_lease(self.root):
            published = publish_notice(
                self.root,
                profile_id=PROFILE_ID,
                session_kind='Q05',
                wallet_outcome='RUNTIME_PRESERVED',
                core_stop='CLEAN',
                codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                journal_seq=1,
            )
        stage_name, rc = self._spawn_publish_and_sigkill_at_boundary(
            self.root,
            boundary='before_unlink',
            session_kind='Q05',
            code='WALLET_MANAGED_RUNTIME_PRESERVED',
            journal_seq=1,
            ack_payload={
                'kind': 'notice',
                'seq': published['seq'],
                'body_sha256': published['body_sha256'],
            },
        )
        self.assertEqual(rc, -signal.SIGKILL)
        ack_path = self.root / 'supervisor.notice-ack.000001'
        stage_path = self.root / stage_name
        self.assertTrue(ack_path.exists())
        self.assertTrue(stage_path.exists())
        self.assertEqual(ack_path.lstat().st_nlink, 2)

        # Without lease, ack is honored and stage stays intact.
        self.assertEqual(unacknowledged(self.root, expected_profile_id=PROFILE_ID), ())
        self.assertTrue(stage_path.exists())

        # Under lease, reader unlinks the ack stage and reduces st_nlink to 1.
        with exclusive_lease(self.root):
            self.assertEqual(unacknowledged(self.root, expected_profile_id=PROFILE_ID), ())
        self.assertFalse(stage_path.exists())
        self.assertEqual(ack_path.lstat().st_nlink, 1)


class QuitNoticeExecutorAndHooksContracts(unittest.TestCase):
    setUp = fixture.SupervisorLifecycleUnit.setUp
    owner = fixture.SupervisorLifecycleUnit.owner

    def _executor(self, backend):
        executor = WalletExecutor(lambda: backend)
        executor._backend = backend
        backend.attach_executor(executor)
        self.addCleanup(self._close_executor, executor, backend)
        return executor

    def _close_executor(self, executor, backend):
        try:
            if not executor.closed:
                backend._notice_persist_failed = False
                backend._quit_cleanup_uncertain = False
                backend.session = None
                if hasattr(backend, '_spend_session'):
                    backend._spend_session = None
                owner = getattr(backend, 'owner', None)
                if owner is not None:
                    owner.process = None
                try:
                    executor.request('quit', timeout=5)
                except Exception:
                    pass
        finally:
            executor.join(5)

    def test_nd_publish_denied_refuses_release_and_blocks_later_quit_and_control_release(self):
        for kind, cls, err in (
            ('Q05', ManagedWalletBackend, WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')),
            ('Q06', Bip39ReadOnlyBackend, ValueError('Q06_SPEND_RUNTIME_PRESERVED')),
        ):
            with self.subTest(kind=kind):
                if kind == 'Q05':
                    sub_root = self.root
                else:
                    q06_parent = self.root.parent / 'q06'
                    q06_parent.mkdir(mode=0o700, exist_ok=True)
                    sub_root = _private_core_root(q06_parent)
                backend = cls(sub_root, self.core, self.core)
                owner = _live_mock_owner(sub_root)
                backend.owner = owner
                if kind == 'Q05':
                    session = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
                    session.lock.side_effect = err
                    backend.session = session
                else:
                    spend = Mock(locked=False, faulted=True, _q06_uncertain=True, _core_reauthentication_required=False)
                    spend.lock.side_effect = err
                    backend._spend_session = spend
                    backend._secret = bytearray(PASSWORD)
                executor = self._executor(backend)
                with exclusive_lease(sub_root), \
                        patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                        patch('wam_regtest.quit_notice.publish_notice', side_effect=OSError('ENOSPC')):
                    with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                        executor.request('quit', timeout=5)
                    self.assertTrue(backend._notice_persist_failed)
                    self.assertFalse(executor.closed)
                    self.assertIs(executor.state.core_alive, False)
                    owner.release.assert_not_called()
                    owner.close.assert_not_called()

                    # Subsequent quit refuses even if publish_notice would now work.
                with exclusive_lease(sub_root), \
                        patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)):
                    with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                        executor.request('quit', timeout=5)
                    owner.release.assert_not_called()
                    owner.close.assert_not_called()
                    self.assertFalse(executor.closed)

                    # Subsequent control('release') also refuses with NOTICE_PERSIST_FAILED.
                    with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                        executor.request('control', 'release', timeout=5)
                    owner.control_operation.assert_not_called()
                    self.assertFalse(executor.closed)

    def test_nd_ipc_serve_control_release_refused_while_notice_persist_failed(self):
        # Exercise the real CoreSupervisor socket + _serve_control bridge.
        with patch.object(CoreSupervisor, 'start'), \
                patch.object(CoreSupervisor, 'recover_stop') as rec_stop:
            executor = WalletExecutor(lambda: ManagedWalletBackend(self.root, self.core, self.core))
            self.addCleanup(self._close_executor_real, executor)
            executor.request('core_start', timeout=5)
            backend = executor._backend
            owner = backend.owner
            owner.process = Mock()
            owner.process.poll.return_value = None

            def stop_clears():
                owner.process = None

            rec_stop.side_effect = stop_clears
            session = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
            session.lock.side_effect = WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')
            backend.session = session

            with patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                    patch('wam_regtest.quit_notice.publish_notice', side_effect=OSError('ENOSPC')):
                with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                    executor.request('quit', timeout=5)
            self.assertTrue(backend._notice_persist_failed)
            self.assertFalse(executor.closed)
            self.assertFalse(owner._release_requested)

            # IPC control('release') hits _control_bridge -> execute('control', ('release',)) and fails.
            with self.assertRaises(Exception):
                control(self.root, 'release', authorized=True)
            time.sleep(0.05)
            self.assertFalse(owner._release_requested)
            self.assertFalse(executor.closed)

    def _close_executor_real(self, executor):
        try:
            if not executor.closed and executor._backend is not None:
                executor._backend._notice_persist_failed = False
                executor._backend._quit_cleanup_uncertain = False
                executor._backend.session = None
                if executor._backend.owner is not None:
                    executor._backend.owner.process = None
                try:
                    executor.request('quit', timeout=5)
                except Exception:
                    pass
        finally:
            executor.join(5)

    def test_stop_failure_publishes_notice_and_double_fault_refuses_blocked(self):
        # Single stop failure (Core alive) publishes notice with UNCERTAIN/BLOCKED, keeps owner.
        backend = ManagedWalletBackend(self.root, self.core, self.core)
        owner = _live_mock_owner(self.root)
        owner.recover_stop.side_effect = ValueError('MANAGED_SHUTDOWN_UNCERTAIN')
        backend.owner = owner
        backend._faulted_test = True
        owner._faulted = True
        executor = self._executor(backend)
        with exclusive_lease(self.root), \
                patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)):
            with self.assertRaisesRegex(WalletExecutorError, '^MANAGED_SHUTDOWN_UNCERTAIN$'):
                executor.request('quit', timeout=5)
        self.assertFalse(executor.closed)
        self.assertTrue(executor.state.core_alive)
        owner.release.assert_not_called()
        owner.close.assert_not_called()
        items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['notice']['wallet_outcome'], 'NONE')
        self.assertEqual(items[0]['notice']['core_stop'], 'UNCERTAIN')
        self.assertEqual(items[0]['notice']['codes'], ['MANAGED_SHUTDOWN_UNCERTAIN'])

        # Double fault: Core alive + notice publish failure -> refused, BLOCKED, owner kept,
        # and BOTH the stop failure code and NOTICE_PERSIST_FAILED are preserved in diagnostics.
        backend2 = ManagedWalletBackend(self.root, self.core, self.core)
        owner2 = _live_mock_owner(self.root)
        owner2._faulted = True
        owner2.recover_stop.side_effect = ValueError('CORE_RPC_PROCESS_IDENTITY_DENIED')
        backend2.owner = owner2
        executor2 = self._executor(backend2)
        before_diag = len(diagnostics.records())
        with exclusive_lease(self.root), \
                patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                patch('wam_regtest.quit_notice.publish_notice', side_effect=OSError('EIO')):
            with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                executor2.request('quit', timeout=5)
        self.assertFalse(executor2.closed)
        self.assertTrue(executor2.state.core_alive)
        owner2.release.assert_not_called()
        owner2.close.assert_not_called()
        self.assertEqual(backend2._quit_stop_failure_code, 'CORE_RPC_PROCESS_IDENTITY_DENIED')
        recent = diagnostics.records()[before_diag:]
        self.assertIn(('QUIT_STOP_FAILURE', 'CORE_RPC_PROCESS_IDENTITY_DENIED'),
                      [(r.stage, r.category) for r in recent])
        self.assertIn(('QUIT_NOTICE_PERSIST_FAILED', 'NOTICE_PERSIST_FAILED'),
                      [(r.stage, r.category) for r in recent])

    def test_post_link_unlink_or_dir_flush_failure_fails_closed_while_notice_exists(self):
        # I3-N3: failing stage unlink or post-link/post-unlink dir flush still raises
        # NOTICE_PERSIST_FAILED and retains owner, even though the notice file exists on disk.
        real_flush_dir = module.flush_directory
        for idx, mode in enumerate(('unlink', 'dir_flush_after_unlink')):
            with self.subTest(mode=mode):
                parent = self.root.parent / f'n3_{idx}'
                parent.mkdir(mode=0o700, exist_ok=True)
                sub_root = _private_core_root(parent)
                backend = ManagedWalletBackend(sub_root, self.core, self.core)
                owner = _live_mock_owner(sub_root)
                backend.owner = owner
                session = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
                session.lock.side_effect = WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')
                backend.session = session
                executor = self._executor(backend)

                dir_calls = [0]

                def fail_second_dir_flush(fd):
                    dir_calls[0] += 1
                    if dir_calls[0] == 2:
                        raise OSError('simulated-dir-flush-failure')
                    return real_flush_dir(fd)

                with exclusive_lease(sub_root), \
                        patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)):
                    cm = (
                        patch.object(module.os, 'unlink', side_effect=OSError('simulated-unlink-failure'))
                        if mode == 'unlink'
                        else patch.object(module, 'flush_directory', side_effect=fail_second_dir_flush)
                    )
                    with cm:
                        with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                            executor.request('quit', timeout=5)
                self.assertTrue(backend._notice_persist_failed)
                self.assertFalse(executor.closed)
                owner.release.assert_not_called()
                owner.close.assert_not_called()
                self.assertTrue((sub_root / 'supervisor.notice.000001').exists())
                items = unacknowledged(sub_root, expected_profile_id=PROFILE_ID, complete_staged=False)
                self.assertEqual(len(items), 1)
                self.assertEqual(items[0]['kind'], 'notice')
                self.assertEqual(items[0]['notice']['codes'], ['WALLET_MANAGED_RUNTIME_PRESERVED'])

    def test_quit_publish_uses_zero_journal_seq_for_non_list_journal(self):
        backend = ManagedWalletBackend(self.root, self.core, self.core)
        owner = _live_mock_owner(self.root)
        owner.journal = Mock()
        backend.owner = owner
        session = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
        session.lock.side_effect = WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')
        backend.session = session
        executor = self._executor(backend)
        with exclusive_lease(self.root), \
                patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)):
            result = executor.request('quit', timeout=5)
        self.assertIs(result['runtime_preserved'], True)
        self.assertTrue(executor.closed)
        items = unacknowledged(self.root, expected_profile_id=PROFILE_ID)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['notice']['journal_seq'], 0)

    def test_no_owner_quit_under_foreign_lease_fails_closed_and_clean_no_owner_succeeds(self):
        # Clean no-owner quit needs no lease and closes cleanly.
        clean_backend = ManagedWalletBackend(self.root, self.core, self.core)
        clean_exec = self._executor(clean_backend)
        clean_res = clean_exec.request('quit', timeout=5)
        self.assertEqual(dict(clean_res), {'runtime_preserved': False, 'codes': ()})
        self.assertTrue(clean_exec.closed)

        # Uncertain no-owner quit must fail closed with NOTICE_PERSIST_FAILED even if
        # a different process holds supervisor.lock on this root.
        sub_parent = self.root.parent / 'no_owner_foreign'
        sub_parent.mkdir(mode=0o700, exist_ok=True)
        sub_root = _private_core_root(sub_parent)
        repo_src = str(Path(__file__).resolve().parents[1] / 'src')
        child_code = (
            'import sys\n'
            'from pathlib import Path\n'
            'from wam_regtest.supervisor_store import exclusive_lease\n'
            'with exclusive_lease(Path(sys.argv[1])):\n'
            '    print("LEASE_HELD", flush=True)\n'
            '    sys.stdin.read()\n'
        )
        with subprocess.Popen(
            [sys.executable, '-c', child_code, str(sub_root)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(os.environ, PYTHONPATH=repo_src),
        ) as child:
            try:
                ready = child.stdout.readline().strip()
                if ready != 'LEASE_HELD':
                    child.stdin.close()
                    child.wait(timeout=10)
                    self.fail(child.stderr.read())
                self.assertEqual(ready, 'LEASE_HELD')
                backend = ManagedWalletBackend(sub_root, self.core, self.core)
                backend._quit_cleanup_uncertain = True
                backend._quit_cleanup_codes.add('WALLET_MANAGED_RUNTIME_PRESERVED')
                executor = self._executor(backend)
                with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                    executor.request('quit', timeout=5)
                self.assertTrue(backend._notice_persist_failed)
                self.assertFalse(executor.closed)
                self.assertEqual([p.name for p in sub_root.iterdir()], ['supervisor.lock'])
            finally:
                if child.stdin is not None and not child.stdin.closed:
                    child.stdin.close()
                child.wait(timeout=10)

    def test_q05_open_refused_with_unresolved_notice_and_allowed_after_ack(self):
        owner = self.owner()
        profile_id = owner.profile['profile_id']
        publish_notice(
            self.root,
            profile_id=profile_id,
            session_kind='Q05',
            wallet_outcome='RUNTIME_PRESERVED',
            core_stop='CLEAN',
            codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
            journal_seq=2,
        )
        with patch.object(q05_session, '_inputs'):
            with self.assertRaisesRegex(WalletSessionError, '^QUIT_NOTICE_REVIEW_REQUIRED$'):
                WalletSession.open_owned(owner, self.core, PASSWORD, authorized=True)

        # Acknowledge via backend method under owner's held lease.
        backend = ManagedWalletBackend(self.root, self.core, self.core)
        backend.owner = owner
        ack_result = backend.acknowledge_quit_notices()
        self.assertEqual(ack_result['count'], 1)
        self.assertTrue((self.root / 'supervisor.notice.000001').exists())
        self.assertTrue((self.root / 'supervisor.notice-ack.000001').exists())

        # Now open_owned proceeds past the notice gate.
        with patch.object(q05_session, '_inputs'), \
                patch.object(q05_session, '_read_reference', side_effect=ValueError('TEST_REACHED_AFTER_NOTICE')):
            with self.assertRaises(WalletSessionError) as caught:
                WalletSession.open_owned(owner, self.core, PASSWORD, authorized=True)
        self.assertEqual(caught.exception.args, ('WALLET_MANAGED_OPEN_DENIED',))

    def test_q06_reopen_exposes_notices_and_activate_refused_until_ack(self):
        owner = self.owner()
        profile_id = owner.profile['profile_id']
        seed_folder = owner.directory / ('bip39-12-' + 'a' * 32)
        seed_folder.mkdir()
        published = publish_notice(
            self.root,
            profile_id=profile_id,
            session_kind='Q06',
            wallet_outcome='RUNTIME_PRESERVED',
            core_stop='CLEAN',
            codes=('Q06_SPEND_RUNTIME_PRESERVED',),
            journal_seq=4,
        )
        backend = Bip39ReadOnlyBackend(self.root, self.core, self.core)
        backend.owner = owner
        backend._core = lambda: owner

        keys = Bip39Regtest12Keys(PHRASE, source=SOURCE, authorized_disposable=True)
        keys._q06_generation = 2
        backend._q06_write_ack(seed_folder, True, secret=keys.backup_ack_key())
        with patch('wam_regtest.bip39_seed_vault.open_owned_seed_container') as opened:
            opened.return_value.__enter__ = lambda *a, **kw: keys
            opened.return_value.__exit__ = lambda *a, **kw: None
            reopened = backend.execute('open', (PASSWORD, 'reopen', ''), {})

        self.assertEqual(reopened['status'], 'Q06_REGTEST_READ_ONLY_OWNER_OPENED')
        self.assertEqual(len(reopened['unresolved_notices']), 1)
        self.assertEqual(reopened['unresolved_notices'][0]['notice'], published)

        # Spend activation is refused until acknowledged.
        with patch('wam_regtest.bip39_spend_session.open_owned_spend_session') as spend_open:
            with self.assertRaisesRegex(Q06ReadOnlyError, '^QUIT_NOTICE_REVIEW_REQUIRED$'):
                backend.execute('activate', (), {})
            spend_open.assert_not_called()

        # Acknowledge through backend method under lease.
        ack_result = backend.acknowledge_quit_notices()
        self.assertEqual(ack_result['count'], 1)
        self.assertTrue((self.root / 'supervisor.notice.000001').exists())
        self.assertTrue((self.root / 'supervisor.notice-ack.000001').exists())

        # Reopen now has no unresolved notices and spend activation proceeds past both gates.
        backend.execute('lock', (), {})
        with patch('wam_regtest.bip39_seed_vault.open_owned_seed_container') as opened:
            opened.return_value.__enter__ = lambda *a, **kw: keys
            opened.return_value.__exit__ = lambda *a, **kw: None
            reopened2 = backend.execute('open', (PASSWORD, 'reopen', ''), {})
            self.assertEqual(reopened2['unresolved_notices'], ())
            with patch('wam_regtest.bip39_spend_session.open_owned_spend_session',
                       side_effect=ValueError('TEST_REACHED_SPEND_OPEN')) as spend_open:
                with self.assertRaisesRegex(ValueError, '^TEST_REACHED_SPEND_OPEN$'):
                    backend.execute('activate', (), {})
                spend_open.assert_called_once()

    def test_supervisor_failure_only_is_unresolved_and_ack_preserves_failure_file(self):
        owner = self.owner()
        from wam_regtest.core_supervisor import ManagedCoreError
        owner._record_failure('start', ManagedCoreError('MANAGED_START_TIMEOUT'))
        failure_path = self.root / 'supervisor.failure'
        self.assertTrue(failure_path.exists())
        before_bytes = failure_path.read_bytes()

        unresolved = unacknowledged(self.root, expected_profile_id=owner.profile['profile_id'])
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0]['kind'], 'failure')
        self.assertEqual(unresolved[0]['code'], 'MANAGED_START_TIMEOUT')
        self.assertEqual(unresolved[0]['stage'], 'start')

        # Q05 refuses normal open.
        with patch.object(q05_session, '_inputs'):
            with self.assertRaisesRegex(WalletSessionError, '^QUIT_NOTICE_REVIEW_REQUIRED$'):
                WalletSession.open_owned(owner, self.core, PASSWORD, authorized=True)

        # Q06 read-only reopen exposes it and spend activation refuses.
        seed_folder = owner.directory / ('bip39-12-' + 'b' * 32)
        seed_folder.mkdir()
        q06_backend = Bip39ReadOnlyBackend(self.root, self.core, self.core)
        q06_backend.owner = owner
        q06_backend._core = lambda: owner
        keys = Bip39Regtest12Keys(PHRASE, source=SOURCE, authorized_disposable=True)
        keys._q06_generation = 2
        q06_backend._q06_write_ack(seed_folder, True, secret=keys.backup_ack_key())
        with patch('wam_regtest.bip39_seed_vault.open_owned_seed_container') as opened:
            opened.return_value.__enter__ = lambda *a, **kw: keys
            opened.return_value.__exit__ = lambda *a, **kw: None
            reopened = q06_backend.execute('open', (PASSWORD, 'reopen', ''), {})
            self.assertEqual(len(reopened['unresolved_notices']), 1)
            self.assertEqual(reopened['unresolved_notices'][0]['name'], 'supervisor.failure')
            with self.assertRaisesRegex(Q06ReadOnlyError, '^QUIT_NOTICE_REVIEW_REQUIRED$'):
                q06_backend.execute('activate', (), {})

            # Ack unblocks without deleting supervisor.failure.
            ack_result = q06_backend.acknowledge_quit_notices()
            self.assertEqual(ack_result['count'], 1)
            self.assertEqual(failure_path.read_bytes(), before_bytes)
            self.assertEqual(unacknowledged(self.root, expected_profile_id=owner.profile['profile_id']), ())

            with patch('wam_regtest.bip39_spend_session.open_owned_spend_session',
                       side_effect=ValueError('TEST_REACHED_SPEND_OPEN')):
                with self.assertRaisesRegex(ValueError, '^TEST_REACHED_SPEND_OPEN$'):
                    q06_backend.execute('activate', (), {})
        with patch.object(q05_session, '_inputs'), \
                patch.object(q05_session, '_read_reference', side_effect=ValueError('TEST_REACHED_Q05')):
            with self.assertRaises(WalletSessionError) as caught:
                WalletSession.open_owned(owner, self.core, PASSWORD, authorized=True)
        self.assertEqual(caught.exception.args, ('WALLET_MANAGED_OPEN_DENIED',))

    def test_quit_publishes_notice_before_release_and_close_for_q05_and_q06(self):
        cases = (
            ('Q05', ManagedWalletBackend, WalletSessionError('WALLET_LOCK_CLEANUP_UNCERTAIN'), 'CLEANUP_UNCERTAIN'),
            ('Q05', ManagedWalletBackend, WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED'), 'RUNTIME_PRESERVED'),
            ('Q06', Bip39ReadOnlyBackend, ValueError('Q06_SPEND_RUNTIME_UNCERTAIN'), 'CLEANUP_UNCERTAIN'),
            ('Q06', Bip39ReadOnlyBackend, ValueError('Q06_SPEND_RUNTIME_PRESERVED'), 'RUNTIME_PRESERVED'),
        )
        for idx, (kind, cls, err, expected_outcome) in enumerate(cases):
            with self.subTest(kind=kind, expected_outcome=expected_outcome):
                parent = self.root.parent / f'order_{idx}'
                parent.mkdir(mode=0o700, exist_ok=True)
                sub_root = _private_core_root(parent)
                backend = cls(sub_root, self.core, self.core)
                owner = _live_mock_owner(sub_root)
                events = []

                def on_lock():
                    events.append('lock')
                    raise err

                def on_recover_stop():
                    events.append('recover_stop')
                    owner.process = None

                def on_release():
                    events.append('release')

                def on_close():
                    events.append('close')

                owner.recover_stop.side_effect = on_recover_stop
                owner.release.side_effect = on_release
                owner.close.side_effect = on_close
                backend.owner = owner
                if kind == 'Q05':
                    session = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
                    session.lock.side_effect = on_lock
                    backend.session = session
                else:
                    spend = Mock(locked=False, faulted=True, _q06_uncertain=True, _core_reauthentication_required=False)
                    spend.lock.side_effect = on_lock
                    backend._spend_session = spend
                    backend._secret = bytearray(PASSWORD)

                real_publish = module.publish_notice

                def traced_publish(*a, **kw):
                    events.append('publish_notice')
                    return real_publish(*a, **kw)

                executor = self._executor(backend)
                with exclusive_lease(sub_root), \
                        patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)), \
                        patch('wam_regtest.quit_notice.publish_notice', side_effect=traced_publish):
                    result = executor.request('quit', timeout=5)
                self.assertEqual(
                    events,
                    ['lock', 'recover_stop', 'publish_notice', 'release', 'close'],
                )
                self.assertIs(result['runtime_preserved'], True)
                self.assertTrue(executor.closed)
                items = unacknowledged(sub_root, expected_profile_id=PROFILE_ID)
                self.assertEqual(len(items), 1)
                self.assertEqual(items[0]['notice']['session_kind'], kind)
                self.assertEqual(items[0]['notice']['wallet_outcome'], expected_outcome)
                self.assertEqual(items[0]['notice']['core_stop'], 'CLEAN')
                self.assertEqual(items[0]['notice']['journal_seq'], 3)
                self.assertEqual(items[0]['notice']['codes'], [err.args[0]])

    def test_capacity_64_during_quit_triggers_notice_persist_failed(self):
        with exclusive_lease(self.root):
            for seq in range(1, MAX_NOTICES + 1):
                publish_notice(
                    self.root,
                    profile_id=PROFILE_ID,
                    session_kind='Q05',
                    wallet_outcome='RUNTIME_PRESERVED',
                    core_stop='CLEAN',
                    codes=('WALLET_MANAGED_RUNTIME_PRESERVED',),
                    journal_seq=seq,
                )
        backend = ManagedWalletBackend(self.root, self.core, self.core)
        owner = _live_mock_owner(self.root)
        backend.owner = owner
        session = Mock(locked=False, faulted=True, _core_reauthentication_required=False)
        session.lock.side_effect = WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')
        backend.session = session
        executor = self._executor(backend)
        with exclusive_lease(self.root), \
                patch('wam_regtest.rpc_scope.identity', return_value=SimpleNamespace(faulted=False)):
            with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                executor.request('quit', timeout=5)
            self.assertTrue(backend._notice_persist_failed)
            self.assertFalse(executor.closed)
            owner.release.assert_not_called()
            owner.close.assert_not_called()
            with self.assertRaisesRegex(WalletExecutorError, '^NOTICE_PERSIST_FAILED$'):
                executor.request('control', 'release', timeout=5)

    def test_real_sigkill_rn1_and_rn2_truthful_in_q05_and_q06_readers(self):
        owner = self.owner()
        profile_id = owner.profile['profile_id']
        owner.close()

        # R-n1 real SIGKILL before link -> Q05 open_owned refuses, Q06 backend surfaces orphan stage.
        stage_rn1, rc_rn1 = QuitNoticeStoreContracts._spawn_publish_and_sigkill_at_boundary(
            self,
            self.root,
            boundary='before_link',
            profile_id=profile_id,
            session_kind='Q06',
            code='Q06_SPEND_RUNTIME_PRESERVED',
            journal_seq=2,
        )
        self.assertEqual(rc_rn1, -signal.SIGKILL)
        owner2 = CoreSupervisor(self.root, self.core, authorized=True)
        self.addCleanup(owner2.close)
        with patch.object(q05_session, '_inputs'):
            with self.assertRaisesRegex(WalletSessionError, '^QUIT_NOTICE_REVIEW_REQUIRED$'):
                WalletSession.open_owned(owner2, self.core, PASSWORD, authorized=True)
        q06_backend = Bip39ReadOnlyBackend(self.root, self.core, self.core)
        q06_backend.owner = owner2
        from wam_regtest.bip39_owner_backend import _read_unresolved_quit_notices
        surfaced_rn1 = _read_unresolved_quit_notices(owner2)
        self.assertEqual(len(surfaced_rn1), 1)
        self.assertEqual(surfaced_rn1[0]['kind'], 'unreadable')
        self.assertEqual(surfaced_rn1[0]['name'], stage_rn1)
        self.assertEqual(surfaced_rn1[0]['reason'], 'NOTICE_STAGE_ORPHAN')
        ack_res = q06_backend.acknowledge_quit_notices()
        self.assertEqual(ack_res['count'], 1)
        self.assertTrue((self.root / stage_rn1).exists())
        self.assertEqual(_read_unresolved_quit_notices(owner2), ())
        owner2.close()

        # R-n2 real SIGKILL after link before unlink -> reopening owner completes stage cleanly.
        stage_rn2, rc_rn2 = QuitNoticeStoreContracts._spawn_publish_and_sigkill_at_boundary(
            self,
            self.root,
            boundary='before_unlink',
            profile_id=profile_id,
            session_kind='Q05',
            code='WALLET_MANAGED_RUNTIME_PRESERVED',
            journal_seq=3,
        )
        self.assertEqual(rc_rn2, -signal.SIGKILL)
        self.assertTrue((self.root / stage_rn2).exists())
        self.assertEqual((self.root / 'supervisor.notice.000001').lstat().st_nlink, 2)
        owner3 = CoreSupervisor(self.root, self.core, authorized=True)
        self.addCleanup(owner3.close)
        surfaced_rn2 = _read_unresolved_quit_notices(owner3)
        self.assertEqual(len(surfaced_rn2), 1)
        self.assertEqual(surfaced_rn2[0]['kind'], 'notice')
        self.assertEqual(surfaced_rn2[0]['notice']['codes'], ['WALLET_MANAGED_RUNTIME_PRESERVED'])
        self.assertFalse((self.root / stage_rn2).exists())
        self.assertEqual((self.root / 'supervisor.notice.000001').lstat().st_nlink, 1)


if __name__ == '__main__':
    unittest.main()
