"""Refuse unqualified/fabricated probe evidence; actual Core runs separately."""
from hashlib import sha256
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
from types import SimpleNamespace

from wam_regtest import q05_checkpoint_scenario as checkpoint
from wam_regtest import q05_crash_scenario as crash
from wam_regtest import q05_security_scenario as security
from wam_regtest.q05_packaged import run

ROOT=Path(__file__).resolve().parents[1]


class QualificationContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name).resolve()
        self.root=self.directory/('wam-fusion-core-'+'a'*16)
        self.args=['--core-dir',str(self.directory),'--wsp-source',str(self.directory),
            '--root',str(self.root),'--receipt',str(self.directory/'receipt.json')]

    def test_checkpoint_requires_consent_before_source_core_or_custody(self):
        with patch.object(checkpoint,'verify_source') as source,patch.object(checkpoint,'verified_core_paths') as core:
            with self.assertRaises(SystemExit):checkpoint.main(self.args)
            source.assert_not_called();core.assert_not_called()
        self.assertEqual(list(self.directory.iterdir()),[])

    def test_checkpoint_incompatible_fault_modes_refuse_before_access(self):
        for flags in (['--reservation','uncertain'],['--complete-pending-recovery'],
                      ['--negative','corrupt','--fund-disposable-wallet']):
            with self.subTest(flags=flags),patch.object(checkpoint,'verify_source') as source:
                with self.assertRaises(SystemExit):
                    checkpoint.main([*self.args,'--confirm-disposable-regtest',*flags])
                source.assert_not_called()

    def test_crash_window_inventory_includes_stage_link_and_multiple_orphans(self):
        self.assertTrue({'stage','stage-linked','multiple-orphans','anchored-hardlink',
                         'symlink','permission'}<=set(checkpoint.NEGATIVE_MODES))

    def test_security_contender_cannot_create_a_missing_profile(self):
        with patch.object(security,'verify_source') as source:
            with self.assertRaisesRegex(ValueError,'DISPOSABLE_SCOPE_DENIED'):
                security.main([*self.args,'--confirm-disposable-regtest','--lease-contender'])
            source.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_security_parent_never_uses_an_existing_profile(self):
        self.root.mkdir();canary=self.root/'preserve';canary.write_bytes(b'public-fixture')
        with patch.object(security,'verify_source') as source:
            with self.assertRaisesRegex(ValueError,'DISPOSABLE_SCOPE_DENIED'):
                security.main([*self.args,'--confirm-disposable-regtest'])
            source.assert_not_called()
        self.assertEqual(canary.read_bytes(),b'public-fixture')

    def test_public_reference_fixture_never_uses_encrypted_envelope_writer_or_overwrites(self):
        if sys.platform=='win32':
            from wam_regtest.windows_private_storage import create_private_directory
            create_private_directory(self.root)
        else:self.root.mkdir(mode=0o700)
        if sys.platform=='linux':
            # File-only native test; actual Linux probes still require the
            # approved Core/witness policy before custody.storage() is exposed.
            from wam_regtest import linux_private_storage
            policy=patch('wam_regtest.custody.storage',return_value=linux_private_storage)
            policy.start();self.addCleanup(policy.stop)
        path=self.root/'reference.bin'
        checkpoint._fixture_bytes(path,b'public-reference')
        self.assertEqual(path.read_bytes(),b'public-reference')
        if sys.platform!='win32':self.assertEqual(path.stat().st_mode&0o777,0o600)
        with self.assertRaises((FileExistsError,ValueError)):
            checkpoint._fixture_bytes(path,b'replacement')
        self.assertEqual(path.read_bytes(),b'public-reference')

    def test_unsafe_permission_fixture_is_actually_rejected_by_native_storage(self):
        if sys.platform=='win32':
            from wam_regtest.windows_private_storage import create_private_directory
            create_private_directory(self.root)
        else:self.root.mkdir(mode=0o700)
        if sys.platform=='linux':
            from wam_regtest import linux_private_storage
            policy=patch('wam_regtest.custody.storage',return_value=linux_private_storage)
            policy.start();self.addCleanup(policy.stop)
        from wam_regtest import custody
        path=self.root/'snapshot-000000001.enc';raw=b'WAMSP02\0'+bytes(64)
        checkpoint._fixture_bytes(path,raw,public_read=True)
        with self.assertRaises(ValueError):custody.storage().read(self.root,path.name)
        self.assertEqual(path.read_bytes(),raw)

    def test_frozen_scenarios_pass_only_bundled_resources_and_explicit_flags(self):
        args=['--root',str(self.root),'--receipt',str(self.directory/'receipt.json'),
              '--confirm-disposable-regtest']
        for scenario,module in (('checkpoint',checkpoint),('security',security),('crash',crash)):
            with patch.object(sys,'frozen',True,create=True),patch.object(sys,'platform','darwin'), \
                    patch.object(module,'main',return_value=0) as execute:
                self.assertEqual(run(self.directory,self.directory,[*args,'--scenario',scenario]),0)
                execute.assert_called_once_with(args,core=self.directory,source=self.directory,frozen=True)

    def test_frozen_supplement_rejects_missing_shutdown_or_altered_source_or_binary(self):
        require=runpy.run_path(str(ROOT/'scripts/qualify_q05_frozen.py'))['require_supplement']
        binary=self.directory/'bootloader';binary.write_bytes(b'public-test-bootloader')
        base={k:'public-fixture' for k in
              ('source_sha','checkout_sha','core_sha256','wsp_source_commit','platform','core_trust')}
        good={**base,'status':'PASS','owner_shutdown_verified':True,'frozen':True,
            'synthetic_rpc':False,'mainnet_allowed':False,
            'source_provenance':{'frozen_executable_sha256':sha256(binary.read_bytes()).hexdigest()},
            'observations':[{'cross_process_competing_owner_refused':True,
                'authenticated_control_reconnect_same_original_owner':True,
                'wrong_hmac_shutdown_refused_without_journal_mutation':True},
                {'credential_bytes_sent':0},{'explicit_original_backend_quit_verified':True}]}
        require(good,base,binary,'security',[])
        for changes in ({'owner_shutdown_verified':False},{'source_sha':'foreign'},
                        {'synthetic_rpc':True},{'source_provenance':{}},
                        {'observations':[]},{'frozen':False}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                require({**good,**changes},base,binary,'security',[])

    def test_frozen_uncertain_recovery_cannot_use_a_gui_or_signed_only_receipt(self):
        require=runpy.run_path(str(ROOT/'scripts/qualify_q05_frozen.py'))['require_supplement']
        binary=self.directory/'bootloader';binary.write_bytes(b'public-test-bootloader')
        base={k:'public-fixture' for k in
              ('source_sha','checkout_sha','core_sha256','wsp_source_commit','platform','core_trust')}
        uncertain_obs={'reservation_state':'uncertain','runtime_preserved':True,
                       'notice_reviewed':sys.platform!='win32',
                       'prior_runtime_refused_before_recovery':True,
                       'explicit_checkpoint_recovery_after_uncertain_broadcast':True}
        other_obs=[{'explicit_pending_commit_completed':True},
                   {'live_session_runtime_retained_on_checkpoint_failure':True},
                   {'reopened_same_wallet_live_resync':True}]
        good={**base,'status':'PASS','owner_shutdown_verified':True,'frozen':True,
            'synthetic_rpc':False,'mainnet_allowed':False,'recovery_completed':True,
            'qualification_scope':'EXPLICIT_PENDING_RECOVERY_COMPLETION',
            'automatic_wallet_transaction_replay':False,'wallet_broadcast_calls_total':1,
            'source_provenance':{'frozen_executable_sha256':sha256(binary.read_bytes()).hexdigest()},
            'observations':[uncertain_obs,*other_obs]}
        require(good,base,binary,'checkpoint',['uncertain'])
        bad_changes=[{'wallet_broadcast_calls_total':0},{'wallet_broadcast_calls_total':2},
                     {'recovery_completed':False},{'automatic_wallet_transaction_replay':True},
                     {'qualification_scope':'CLEAN_OWNER_REOPEN'},
                     {'observations':other_obs},
                     {'observations':[{**uncertain_obs,'runtime_preserved':False},*other_obs]},
                     {'observations':[{**uncertain_obs,'prior_runtime_refused_before_recovery':False},*other_obs]},
                     {'observations':[{**uncertain_obs,'explicit_checkpoint_recovery_after_uncertain_broadcast':False},*other_obs]}]
        if sys.platform!='win32':
            bad_changes.append({'observations':[{**uncertain_obs,'notice_reviewed':False},*other_obs]})
        for changes in bad_changes:
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                require({**good,**changes},base,binary,'checkpoint',['uncertain'])

    def test_frozen_divergence_requires_exact_transition_no_replay_and_preserved_anchor(self):
        require=runpy.run_path(str(ROOT/'scripts/qualify_q05_frozen.py'))['require_supplement']
        binary=self.directory/'bootloader';binary.write_bytes(b'public-test-bootloader')
        base={k:'public-fixture' for k in
              ('source_sha','checkout_sha','core_sha256','wsp_source_commit','platform','core_trust')}
        for state in ('signed','uncertain'):
            observed=[{'unanchored_transition_state':state,
                       'live_session_runtime_retained_on_checkpoint_failure':True},
                      {'divergent_unanchored_reservation_refused':state,
                       'no_recovery_reference_or_anchor_advance':True,
                       'original_unknown_bytes_preserved':True}]
            good={**base,'status':'PASS','owner_shutdown_verified':True,'frozen':True,
                'synthetic_rpc':False,'mainnet_allowed':False,'recovery_completed':False,
                'qualification_scope':'DIVERGENT_RESERVATION_SAFE_REFUSAL',
                'automatic_wallet_transaction_replay':False,'wallet_broadcast_calls_total':0,
                'source_provenance':{'frozen_executable_sha256':sha256(binary.read_bytes()).hexdigest()},
                'observations':observed}
            options=['--transition-cut',state]
            require(good,base,binary,'checkpoint',options)
            changes=[{'wallet_broadcast_calls_total':1},{'recovery_completed':True},
                     {'automatic_wallet_transaction_replay':True},{'observations':[]},
                     {'qualification_scope':'EXPLICIT_PENDING_RECOVERY_COMPLETION'}]
            for field in ('divergent_unanchored_reservation_refused',
                          'no_recovery_reference_or_anchor_advance','original_unknown_bytes_preserved'):
                changes.append({'observations':[observed[0],{**observed[1],field:False}]})
            for change in changes:
                with self.subTest(state=state,change=change),self.assertRaises(ValueError):
                    require({**good,**change},base,binary,'checkpoint',options)

    def test_live_publication_cut_observes_only_original_session_anchor_lease(self):
        from wam_regtest.wallet_session import WalletSessionError
        self.root.mkdir(mode=0o700)
        folder=self.root/'wallet-vault';folder.mkdir(mode=0o700)
        (folder/'snapshot-000000001.enc').write_bytes(b'public-original-ciphertext')
        (self.root/'supervisor.wallet').write_bytes(b'public-reference')
        (self.root/'wallet-runtime.sqlite').write_bytes(b'public-retained-runtime')
        owner=SimpleNamespace(directory=self.root,root=self.root)
        anchor=Mock();anchor.read.return_value=(1,'b'*64)
        session=Mock();session.vault.anchor=anchor
        def publish(directory,name,blob):(directory/name).write_bytes(blob)
        store=SimpleNamespace(publish=publish,read=lambda directory,name:(directory/name).read_bytes())
        def save():
            try:store.publish(folder,'snapshot-000000002.enc',b'public-future-ciphertext')
            except checkpoint.AfterPublicationCut as error:
                raise WalletSessionError('WALLET_ANCHORED_SAVE_FAILED') from error
        def lock():
            session.locked=True;session._password=None
            raise WalletSessionError('WALLET_MANAGED_RUNTIME_PRESERVED')
        session._save.side_effect=save;session.lock.side_effect=lock
        initial={'wallet_id':'a'*32,'reservation_states':['signed'],'reservation_sha256':'c'*64}
        with patch('wam_regtest.custody.anchor') as foreign_anchor,\
                patch('wam_regtest.custody.storage',return_value=store),\
                patch('wam_regtest.wallet_session.WalletSession.open_owned',return_value=session),\
                patch.object(checkpoint,'checkpoint',side_effect=checkpoint.ManagedWalletError('MANAGED_WALLET_EXISTING_RUNTIME_DENIED')):
            result=checkpoint.interrupted_publication(owner,self.directory,b'public-password',None,initial,live=True)
            foreign_anchor.assert_not_called()
        self.assertTrue(result['live_session_runtime_retained_on_checkpoint_failure'])
        self.assertEqual(initial['checkpoint'],[1,'b'*64])
        anchor.advance.assert_not_called();anchor._advance_unlocked.assert_not_called()
        self.assertEqual((self.root/'wallet-runtime.sqlite').read_bytes(),b'public-retained-runtime')

    def test_checkpoint_funding_failure_retains_only_typed_finite_cause_and_closes_transport(self):
        from wam_regtest.core import CoreSmokeError
        from wam_regtest.wsp_live import RealWspScanError
        for cause,expected in ((CoreSmokeError('CORE_RPC_TIMEOUT_UNCERTAIN'),'CORE_RPC_TIMEOUT_UNCERTAIN'),
                (CoreSmokeError('rpcpassword=private-canary'),None),
                (ValueError('CORE_RPC_TIMEOUT_UNCERTAIN'),None)):
            rpc=Mock();record={}
            rpc.call.return_value=0  # a real Core reports its current height
            def fail(*args):
                try:raise cause
                except Exception as inner:raise RealWspScanError('RPC_DENIED') from inner
            rpc._call.side_effect=fail
            with self.assertRaises(RealWspScanError),patch('wam_regtest.wsp_live._public_fixture_payment') as payment:
                checkpoint.fund_checkpoint_fixture(rpc,'public-code','public-address',record)
            self.assertEqual(record,{'fixture_funding_failure':{'stage':'generation',
                **({'cli_code':expected} if expected else {})}})
            rpc._transport.close.assert_called_once();payment.assert_not_called()
            rpc._call.assert_called_once_with('generatetoaddress',['101','public-address'])

    def test_active_container_resolves_recovery_location_only_when_supervisor_exists(self):
        self.root.mkdir(mode=0o700)
        owner=SimpleNamespace(directory=self.root/'chain',root=self.root)
        self.assertEqual(checkpoint._active_container(owner,'a'*32),
                         (self.root/'chain'/'wallet-vault','wallet-runtime.sqlite'))
        (self.root/'supervisor.token').write_bytes(b'x'*32)
        recovered_dir=self.root/'chain'/'wallet-recovery-0123456789abcdef'
        with patch('wam_regtest.wallet_recovery.active_location',
                   return_value=(recovered_dir,'wallet-runtime-recovery-0123456789abcdef.sqlite',(2,'b'*64))) as active:
            self.assertEqual(checkpoint._active_container(owner,'a'*32),
                             (recovered_dir,'wallet-runtime-recovery-0123456789abcdef.sqlite'))
            active.assert_called_once_with(owner,'a'*32)

    def test_preserved_runtime_refusal_requires_prior_runtime_and_existing_runtime_errors(self):
        from wam_regtest.wallet_session import WalletSessionError
        owner=SimpleNamespace(directory=self.root,root=self.root)
        def open_fail(*args,**kwargs):
            try:raise checkpoint.ManagedWalletError('MANAGED_WALLET_PRIOR_RUNTIME_PRESERVED')
            except checkpoint.ManagedWalletError as inner:
                raise WalletSessionError('WALLET_MANAGED_OPEN_DENIED') from inner
        def checkpoint_fail(*args,**kwargs):
            raise checkpoint.ManagedWalletError('MANAGED_WALLET_EXISTING_RUNTIME_DENIED')
        with patch('wam_regtest.wallet_session.WalletSession.open_owned',side_effect=open_fail),\
                patch.object(checkpoint,'checkpoint',side_effect=checkpoint_fail):
            checkpoint._assert_preserved_runtime_refused(owner,self.directory,b'public-password',None)
        with patch('wam_regtest.wallet_session.WalletSession.open_owned',return_value=Mock()),\
                self.assertRaisesRegex(ValueError,'Q05_PRESERVED_RUNTIME_OPEN_ACCEPTED'):
            checkpoint._assert_preserved_runtime_refused(owner,self.directory,b'public-password',None)
        with patch('wam_regtest.wallet_session.WalletSession.open_owned',side_effect=open_fail),\
                patch.object(checkpoint,'checkpoint',return_value={}),\
                self.assertRaisesRegex(ValueError,'Q05_PRESERVED_RUNTIME_CHECKPOINT_ACCEPTED'):
            checkpoint._assert_preserved_runtime_refused(owner,self.directory,b'public-password',None)

    def test_quit_notice_review_after_preserved_runtime_stops_publishes_reopens_and_acks(self):
        from wam_regtest.wallet_session import WalletSessionError
        events=[]
        owner=SimpleNamespace(root=self.root,directory=self.root/'chain',cli=Path('/cli'),
            profile={'profile_id':'a'*32},journal=SimpleNamespace(events=[{'seq':3}]),process=None)
        reopened=SimpleNamespace(root=self.root,directory=self.root/'chain',cli=Path('/cli'),
            profile={'profile_id':'a'*32},process=None)
        owner.recover_stop=lambda:events.append('recover_stop')
        owner.release=lambda:events.append('release')
        owner.close=lambda:events.append('close')
        reopened.start=lambda timeout=30:events.append(('start',timeout))
        notice={'notice':{'wallet_outcome':'RUNTIME_PRESERVED','core_stop':'CLEAN',
                          'codes':['WALLET_MANAGED_RUNTIME_PRESERVED']}}
        args=SimpleNamespace(root=self.root,core_dir=self.directory,wsp_source=self.directory)
        def publish(root,**kwargs):events.append(('publish',kwargs))
        def unack(root,**kwargs):
            return (notice,) if not any(e=='ack' for e in events) else ()
        def ack(root,**kwargs):
            events.append('ack')
            return ({'kind':'notice','seq':1},)
        with patch.object(checkpoint,'CoreSupervisor',return_value=reopened),\
                patch('wam_regtest.core._read_cli',return_value=['txid-1']),\
                patch('wam_regtest.quit_notice.publish_notice',side_effect=publish),\
                patch('wam_regtest.quit_notice.unacknowledged',side_effect=unack),\
                patch('wam_regtest.quit_notice.acknowledge_unresolved',side_effect=ack),\
                patch('wam_regtest.wallet_session.WalletSession.open_owned',
                      side_effect=WalletSessionError('QUIT_NOTICE_REVIEW_REQUIRED')):
            got=checkpoint._review_quit_notice_after_preserved_runtime(
                owner,args,b'public-password',None,'txid-1')
        self.assertIs(got,reopened)
        self.assertEqual(events[0],'recover_stop')
        self.assertEqual(events[1][0],'publish')
        self.assertEqual(events[1][1]['wallet_outcome'],'RUNTIME_PRESERVED')
        self.assertEqual(events[1][1]['codes'],('WALLET_MANAGED_RUNTIME_PRESERVED',))
        self.assertEqual(events[2:5],['release','close',('start',30)])
        self.assertEqual(events[5],'ack')
