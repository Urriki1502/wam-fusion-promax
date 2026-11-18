"""Fresh-profile mnemonic restoration from real historical REGTEST blocks.

Qualification only: three NEW namespaces, two Core owners at a time. A second
participant is positively stopped before a fresh participant on new ports restores the seed
and syncs historical blocks from the sole coordinator. No chain/vault/anchor is
copied; restored custody remains read-only and original reservations survive.
"""
from collections.abc import Mapping
from hashlib import sha256
import json
import errno
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys
import time
from .wallet_executor import WalletExecutor, WalletExecutorError
from .bip39_owner_backend import Bip39ReadOnlyBackend
from .shared_regtest import SharedRegtestProfile
from .custody import create_directory

RESERVATION_DENIED_CODE = 'Q06_SAME_CHAIN_RESTORE_RESERVATION_DENIED'
UNCERTAIN_FIXTURE_STATUS = (
    "UNREACHABLE: no non-faked executor action stops in 'uncertain' without "
    "a mid-broadcast Core/save fault (and signed fixture locks remaining coin)"
)


def _rows_to_reservation_map(rows):
    mapping = {}
    for row in rows:
        if type(row) not in (tuple, list, sqlite3.Row) or len(row) != 5:
            raise ValueError(RESERVATION_DENIED_CODE)
        txid, vout, token, state, created = tuple(row)
        coin = (txid, vout)
        if coin in mapping:
            raise ValueError(RESERVATION_DENIED_CODE)
        mapping[coin] = (token, state, created)
    return mapping


def _valid_reservation_map(mapping):
    if not isinstance(mapping, Mapping):
        raise ValueError(RESERVATION_DENIED_CODE)
    out = {}
    for coin, entry in mapping.items():
        if (type(coin) is not tuple or len(coin) != 2
                or type(entry) is not tuple or len(entry) < 2):
            raise ValueError(RESERVATION_DENIED_CODE)
        out[coin] = entry
    return out


def verify_restore_reservation_contract(
    *,
    before_original_map,
    after_original_map,
    restored_map,
    signed_outpoints=None,
    signed_token=None,
    before_intents=None,
    after_intents=None,
):
    """Enforce PROBE-FLAG-01: restored map empty, original unchanged, signed fixture retained."""
    before_map = _valid_reservation_map(before_original_map)
    after_map = _valid_reservation_map(after_original_map)
    restored = _valid_reservation_map(restored_map)
    if restored:
        raise ValueError(RESERVATION_DENIED_CODE)
    if after_map != before_map:
        raise ValueError(RESERVATION_DENIED_CODE)
    signed_before = {
        coin: entry for coin, entry in before_map.items() if entry[1] == 'signed'
    }
    if not signed_before:
        raise ValueError(RESERVATION_DENIED_CODE)
    if signed_token is not None:
        if not any(entry[0] == signed_token for entry in signed_before.values()):
            raise ValueError(RESERVATION_DENIED_CODE)
    if signed_outpoints is not None:
        coins = tuple(signed_outpoints)
        if not coins:
            raise ValueError(RESERVATION_DENIED_CODE)
        for coin in coins:
            if coin not in signed_before or coin in restored:
                raise ValueError(RESERVATION_DENIED_CODE)
            if signed_token is not None and signed_before[coin][0] != signed_token:
                raise ValueError(RESERVATION_DENIED_CODE)
            if after_map.get(coin) != before_map[coin]:
                raise ValueError(RESERVATION_DENIED_CODE)
    if before_intents is not None or after_intents is not None:
        if (type(before_intents) not in (list, tuple)
                or type(after_intents) not in (list, tuple)
                or list(after_intents) != list(before_intents)):
            raise ValueError(RESERVATION_DENIED_CODE)
        if not any(
                isinstance(item, Mapping)
                and item.get('state') == 'signed'
                and item.get('classification') == 'SIGNED_NOT_SUBMITTED_RESUMABLE'
                and (signed_token is None or item.get('token') == signed_token)
                for item in after_intents):
            raise ValueError(RESERVATION_DENIED_CODE)


def _complete_backup_challenge(worker, phrase_value):
    words = phrase_value.split()
    challenge = worker.request('backup_challenge', timeout=30)
    answers = tuple(words[i - 1] for i in challenge['positions'])
    if worker.request('backup_verify', challenge['challenge_id'], answers, timeout=30) is not True:
        raise ValueError('Q06_SAME_CHAIN_RESTORE_BACKUP_DENIED')


def qualify(core, source, parent, adapter, *, port_base=29554):
    if type(port_base) is not int or not 1024<=port_base<=65530:
        raise ValueError('Q06_SAME_CHAIN_RESTORE_PORT_SCOPE_DENIED')
    lab = parent / ('same-chain-restore-' + secrets.token_hex(8))
    create_directory(lab)
    report = {'status':'FAIL','synthetic_rpc':False,'mainnet_allowed':False,
              'physical_accepted':False,'independent_reviewed':False,
              'chain_copied':False,'native_anchor_copied':False,
              'old_profile_overwritten':False,'restored_signer_enabled':False,
              'mnemonic_does_not_restore_signed_reservations':False,
              'uncertain_fixture':UNCERTAIN_FIXTURE_STATUS,
              'platform':adapter.platform_id,'ports':[[port_base+i,port_base+i+1] for i in (0,2,4)]}
    profiles = [SharedRegtestProfile('127.0.0.1',coordinator=True,
                    rpc_port=port_base,p2p_port=port_base+1,peer_port=port_base+3),
                SharedRegtestProfile('127.0.0.1',coordinator=False,
                    rpc_port=port_base+2,p2p_port=port_base+3,peer_port=port_base+1),
                SharedRegtestProfile('127.0.0.1',coordinator=False,
                    rpc_port=port_base+4,p2p_port=port_base+5,peer_port=port_base+1)]
    workers = []
    password = b'public-disposable-same-chain-profile-restore'
    phrase = None
    restore_tip = None
    def step(name):
        report['stage'] = name
        print('Q06_SAME_CHAIN_RESTORE_STAGE=' + name, flush=True)
    class ObservedBackend(Bip39ReadOnlyBackend):
        def _start_core(self):
            self.owner.start(timeout=90,
                _defer_shared_network=self.shared_profile is profiles[2])

        def _read_readonly_reservation_map(self):
            from .managed_wallet_checkpoint import _owned
            from .bip39_seed_vault import open_owned_seed_container
            from .wallet_session import WalletCoreCli
            from . import custody
            from .managed_wallet_session import RuntimeGuard
            from wam_sp.scanner import Scanner
            owner = self._core()
            _owned(owner)
            if (any(p.name.startswith('bip39-12-scan-') for p in owner.directory.iterdir())
                    or (owner.directory / 'q06-payment-evidence').exists()):
                raise ValueError(RESERVATION_DENIED_CODE)
            runtime_dir = owner.directory / ('q06-res-' + secrets.token_hex(16))
            custody.create_directory(runtime_dir)
            db_path = runtime_dir / 'wallet-runtime.sqlite'
            scanner = guard = rpc = keys = None
            cleaned = False
            try:
                keys = open_owned_seed_container(
                    owner, self._seed_folder, self.source, bytes(self._secret),
                    authorized=True, keychain=self.keychain)
                if sys.platform == 'win32':
                    from .windows_private_storage import create_managed_runtime
                    create_managed_runtime(db_path)
                scanner = Scanner(db_path, keys.accounts())
                guard = RuntimeGuard(db_path)
                rpc = WalletCoreCli(owner.cli, owner.directory)
                rpc.attest()
                scanner.sync(rpc)
                scanner.assert_current()
                with scanner.store.transaction():
                    rows = scanner.store.db.execute(
                        'SELECT txid,vout,token,state,created FROM reservations ORDER BY txid,vout'
                    ).fetchall()
                guard.check()
                cleaned = True
                return _rows_to_reservation_map(rows)
            finally:
                if scanner is not None:
                    scanner.close()
                if rpc is not None and getattr(rpc, '_transport', None) is not None:
                    rpc._transport.close()
                if keys is not None:
                    keys.close()
                if guard is not None:
                    if cleaned:
                        lock = db_path.with_name(db_path.name + '.scan.lock')
                        if lock.exists() or lock.is_symlink():
                            info = lock.lstat()
                            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                                    or lock.is_symlink()
                                    or (sys.platform != 'win32'
                                        and (info.st_uid != os.geteuid()
                                             or stat.S_IMODE(info.st_mode) != 0o600))):
                                raise ValueError('Q06_SAME_CHAIN_RESTORE_SCAN_LOCK_UNCERTAIN')
                            lock.unlink()
                        guard.remove_owned()
                        runtime_dir.rmdir()
                    else:
                        guard.close()

        def _read_reservation_map(self):
            if self._spend_session is not None:
                with self._spend_session.scanner.store.transaction():
                    rows = self._spend_session.scanner.store.db.execute(
                        'SELECT txid,vout,token,state,created FROM reservations ORDER BY txid,vout'
                    ).fetchall()
                return _rows_to_reservation_map(rows)
            return self._read_readonly_reservation_map()

        def execute(self, action, args, kwargs):
            try:
                result=super().execute(action,args,kwargs)
                if action=='open' and self.shared_profile is profiles[2]:
                    # Hold P2P inactive through original-process/HTTP
                    # attestation AND native seed opening. Only then enable
                    # this disposable participant and await real blocks.
                    from .core import _read_cli
                    owner=self.owner
                    prefix=[str(owner.cli),'-datadir='+str(owner.directory)]
                    _read_cli(prefix+['setnetworkactive','true'])
                    deadline=time.monotonic()+120
                    while True:
                        remaining=deadline-time.monotonic()
                        if remaining<=0:
                            raise ValueError('Q06_RESTORED_CORE_BOOTSTRAP_SYNC_TIMEOUT')
                        info=_read_cli(prefix+['getblockchaininfo'],timeout=min(15,remaining))
                        if (info['blocks'],info['bestblockhash'])==restore_tip:break
                        if info['blocks']>restore_tip[0]:
                            raise ValueError('Q06_RESTORED_CORE_BOOTSTRAP_TIP_DENIED')
                        time.sleep(.1)
                    from .managed_wallet_checkpoint import _owned
                    _owned(owner)  # Unchanged HTTP and custody checks after sync.
                    report['restored_core_attested_before_network_sync']=True
                    report['restored_core_synced_before_history_scan']=True
                if action == 'snapshot' and type(result) is dict:
                    result = dict(result, reservation_map=self._read_reservation_map())
                return result
            except Exception as error:
                # Public type/errno only: never exception strings, args,
                # mnemonic, credentials, chain records or signed payloads.
                report['backend_failure']={'action':action,
                    'type':type(error).__name__,
                    'errno':error.errno if isinstance(error,OSError) else None}
                owner=self.owner
                if owner is not None:
                    report['backend_failure']['owner_state']=owner.state
                    report['backend_failure']['owner_faulted']=owner._faulted
                    from .supervisor_store import read_exact
                    from .core_supervisor import DIAGNOSTIC_CODES
                    try:
                        failure=json.loads(read_exact(owner.root,'supervisor.failure'))
                        if (type(failure) is dict and set(failure)=={'stage','code'}
                                and failure['stage'] in ('start','status','recover-stop')
                                and failure['code'] in DIAGNOSTIC_CODES|{'MANAGED_UNCLASSIFIED_FAILURE'}):
                            report['backend_failure']['supervisor_failure']=failure
                    except (OSError,ValueError,TypeError):pass
                # Seed custody intentionally masks underlying owner failures.
                # Retain only these fixed public categories, never exception
                # text/arguments, paths, credentials or arbitrary cause strings.
                cause=error.__context__
                if (cause is not None and cause.args in (
                        ('MANAGED_WALLET_ORIGINAL_OWNER_REQUIRED',),
                        ('MANAGED_WALLET_RUNNING_JOURNAL_REQUIRED',),
                        ('MANAGED_WALLET_OWNED_CORE_UNVERIFIED',))):
                    report['backend_failure']['owner_failure_code']=cause.args[0]
                frames=[]
                tb=error.__traceback__
                while tb is not None:
                    if tb.tb_frame.f_code.co_filename.endswith('/core_supervisor.py'):
                        frames.append({'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno})
                    tb=tb.tb_next
                if frames:report['backend_failure']['supervisor_frames']=frames
                stage=getattr(error,'open_stage',None)
                if type(stage) is str and stage.replace('_','').isalnum():
                    report['backend_failure']['open_stage']=stage
                print('Q06_SAME_CHAIN_BACKEND_FAILURE='+json.dumps(report['backend_failure']),flush=True)
                raise
    def start(index, mode, mnemonic='', existing_root=None):
        root = existing_root or lab / ('wam-fusion-core-' + secrets.token_hex(8))
        options = ({'_anchor_factory':adapter.make_anchor} if mode != 'reopen' else
                   {'keychain':adapter.reopen_anchor(root) if adapter.platform_id=='macos-arm64' else None})
        worker = WalletExecutor(lambda:ObservedBackend(
            root,core,source,shared_profile=profiles[index],**options))
        workers.append(worker)
        # Covers bounded Core bootstrap (90s) plus historical sync (120s).
        opened = worker.request('open',password,mode,mnemonic,timeout=240)
        return worker, opened, root
    def wait(predicate):
        deadline = time.monotonic() + 120
        while not predicate():
            if time.monotonic() >= deadline:
                raise ValueError('Q06_SAME_CHAIN_RESTORE_SYNC_TIMEOUT')
            time.sleep(.1)
    def state(worker):
        return worker.request('network_status',timeout=30)
    def stop(worker):
        worker.request('quit',timeout=60)
        if not worker.join(15) or not worker.closed:
            raise ValueError('Q06_SAME_CHAIN_RESTORE_ORIGINAL_OWNER_LIVE')
    try:
        step('NEW_COORDINATOR_AND_PARTICIPANT')
        a, opened, _ = start(0,'create')
        phrase = opened['mnemonic_once']
        a.request('acknowledge_create_pending',opened['seed_folder'],timeout=30)
        # Exercise the actual owner/executor and native seed, including in the
        # final frozen executable. Only these newly created REGTEST profiles.
        denied = []
        def refused(label, *args):
            try:
                a.request('backup_verify', *args, timeout=30)
            except WalletExecutorError as error:
                if not error.args or not error.args[0].startswith('Q06_GUI_BACKUP_'):
                    raise
                denied.append(label)
            else:
                raise ValueError('Q06_BACKUP_CHALLENGE_NEGATIVE_ACCEPTED')
        words = phrase.split()
        for count in (1, 2):
            challenge = a.request('backup_challenge', timeout=30)
            answers = tuple(words[i-1] for i in challenge['positions'])
            refused('short-'+str(count), challenge['challenge_id'], answers[:count])
        refused('caller-selected-positions', (1, 6, 12), tuple(words[i-1] for i in (1, 6, 12)))
        challenge = a.request('backup_challenge', timeout=30)
        answers = tuple(words[i-1] for i in challenge['positions'])
        if a.request('backup_verify', challenge['challenge_id'], ('wrong',)*3, timeout=30) is not False:
            raise ValueError('Q06_BACKUP_CHALLENGE_WRONG_ANSWER_ACCEPTED')
        refused('wrong-answer-replay', challenge['challenge_id'], answers)
        challenge = a.request('backup_challenge', timeout=30)
        a.request('backup_challenge_cancel', timeout=30)
        refused('cancelled', challenge['challenge_id'], tuple(words[i-1] for i in challenge['positions']))
        challenge = a.request('backup_challenge', timeout=30)
        a.request('lock', timeout=30)
        a.request('open', password, 'reopen', '', timeout=120)
        refused('lock-reopen', challenge['challenge_id'], tuple(words[i-1] for i in challenge['positions']))
        challenge = a.request('backup_challenge', timeout=30)
        positions = challenge['positions']
        answers = tuple(phrase.split()[i-1] for i in positions)
        if a.request('backup_verify',challenge['challenge_id'],answers,timeout=30) is not True:
            raise ValueError('Q06_SAME_CHAIN_RESTORE_BACKUP_DENIED')
        refused('success-replay', challenge['challenge_id'], answers)
        report['backend_backup_challenge_negative_cases'] = denied
        report['backend_backup_challenge_exact_three_native_ack'] = True
        answers = words = None
        b, unused, _ = start(1,'create')
        unused = None
        wait(lambda:state(a)['connected'] and state(b)['connected'])
        peers = state(a)['peers'] + state(b)['peers']
        if not peers or any(p['subver']!='/WAM:0.1.13/' or p['version']!=70016 for p in peers):
            raise ValueError('Q06_SAME_CHAIN_RESTORE_PEER_IDENTITY_DENIED')
        report['observed_peer_subversions'] = sorted({p['subver'] for p in peers})
        report['observed_peer_protocols'] = sorted({p['version'] for p in peers})
        try:b.request('mine',timeout=30)
        except WalletExecutorError as error:
            if error.args != ('SHARED_SINGLE_COORDINATOR_REQUIRED',):raise
        else:raise ValueError('Q06_SAME_CHAIN_RESTORE_PARTICIPANT_MINED')
        step('REAL_HISTORICAL_FUNDS_AND_PAYMENT')
        a.request('mine',timeout=240)
        active = a.request('activate',timeout=240)
        from mnemonic import Mnemonic
        from .bip39_12 import Bip39Regtest12Keys
        with Bip39Regtest12Keys(Mnemonic('english').to_mnemonic(bytes([2]*16)),
                                source=source,authorized_disposable=True) as payee:
            destination = payee.public_metadata()['receive_code']
        draft = a.request('prepare',destination,50_000,1_000,timeout=240)
        a.request('sign',draft.commitment,timeout=240)
        txid = a.request('broadcast',draft.commitment,timeout=240)
        confirmed = a.request('confirm',txid,timeout=240)
        initial = a.request('snapshot',timeout=240)
        if (confirmed['txid']!=txid or initial['history_count_shown']<2
                or initial['reservation_count']!=1):
            raise ValueError('Q06_SAME_CHAIN_RESTORE_ORIGINAL_HISTORY_DENIED')
        wait(lambda:state(b)['tip']==initial['tip'])
        step('ORIGINAL_SIGNED_UNSUBMITTED_FIXTURE')
        signed_draft = a.request('prepare',destination,40_000,1_000,timeout=240)
        signed_review = a.request('sign',signed_draft.commitment,timeout=240)
        if signed_review.commitment != signed_draft.commitment:
            raise ValueError(RESERVATION_DENIED_CODE)
        before = a.request('snapshot',timeout=240)
        before_intents = a.request('intent_status',timeout=240)
        before_map = _valid_reservation_map(before.get('reservation_map'))
        signed_rows = {
            coin: entry for coin, entry in before_map.items()
            if entry[1] == 'signed'
        }
        signed_tokens = {entry[0] for entry in signed_rows.values()}
        if (before['reservation_count'] != 2
                or before['payment_signed'] is not True
                or not signed_rows
                or len(signed_tokens) != 1):
            raise ValueError(RESERVATION_DENIED_CODE)
        signed_token = next(iter(signed_tokens))
        signed_outpoints = tuple(sorted(signed_rows))
        if not any(
                isinstance(item, Mapping)
                and item.get('token') == signed_token
                and item.get('state') == 'signed'
                and item.get('classification') == 'SIGNED_NOT_SUBMITTED_RESUMABLE'
                and item.get('txid') != txid
                for item in before_intents.get('intents', ())):
            raise ValueError(RESERVATION_DENIED_CODE)
        report['uncertain_fixture'] = UNCERTAIN_FIXTURE_STATUS
        step('VERIFIED_ORIGINAL_PARTICIPANT_SHUTDOWN')
        stop(b)
        report['original_participant_shutdown_verified'] = True
        step('NEW_PROFILE_RESTORE_THEN_SYNC_HISTORICAL_CHAIN')
        # Do not adopt/reuse an endpoint whose old TCP lifetime may remain
        # reserved after clean shutdown. The new participant initiates its
        # one manual connection to A; A's unchanged inbound peer policy still
        # attests the configured private host and exact Core subversion.
        from .shared_regtest import reserve_ports
        try:
            with reserve_ports(profiles[1]):pass
            report['retired_endpoint_available'] = True
        except OSError as error:
            if error.errno != errno.EADDRINUSE:raise
            report['retired_endpoint_available'] = False
            report['retired_endpoint_not_adopted'] = True
        restore_tip = (before['height'],before['tip'])
        c, restored, restored_root = start(2,'restore',phrase)
        if (restored['receive_code']!=opened['receive_code'] or restored['mnemonic_once']
                or restored['account_id']!=opened['account_id']
                or restored['signer_allowed'] is not False):
            raise ValueError('Q06_SAME_CHAIN_RESTORE_FRESH_IDENTITY_DENIED')
        if restored.get('backup_status') != 'verified':
            _complete_backup_challenge(c, phrase)
        wait(lambda:state(a)['connected'] and state(c)['connected']
                       and state(c)['tip']==before['tip'])
        recovered = c.request('snapshot',timeout=240)
        after = a.request('snapshot',timeout=240)
        after_intents = a.request('intent_status',timeout=240)
        expected = {row['txid'] for row in before['history']}
        actual = {row['txid'] for row in recovered['history']}
        if (recovered['height']!=before['height'] or recovered['tip']!=before['tip']
                or recovered['receive_code']!=opened['receive_code']
                or recovered['confirmed_atoms']!=before['confirmed_atoms']
                or recovered['signer_allowed'] is not False
                or txid not in actual or actual!=expected
                or after['reservation_count']!=before['reservation_count']
                or after['confirmed_atoms']!=before['confirmed_atoms']):
            raise ValueError('Q06_SAME_CHAIN_RESTORE_FUNDS_HISTORY_DENIED')
        verify_restore_reservation_contract(
            before_original_map=before.get('reservation_map'),
            after_original_map=after.get('reservation_map'),
            restored_map=recovered.get('reservation_map'),
            signed_outpoints=signed_outpoints,
            signed_token=signed_token,
            before_intents=before_intents.get('intents'),
            after_intents=after_intents.get('intents'),
        )
        report.update(status='FRESH_PROFILE_SAME_CHAIN_HISTORY_RESTORE_PASS',
            restored_receive_code_sha256=sha256(restored['receive_code'].encode('ascii')).hexdigest(),
            confirmed_txid=txid,confirmed_height=before['height'],confirmed_tip=before['tip'],
            confirmed_atoms=before['confirmed_atoms'],history_count=len(actual),
            original_irreversible_reservations_preserved=True,
            signed_unsubmitted_fixture_verified=True,
            uncertain_fixture=UNCERTAIN_FIXTURE_STATUS,
            mnemonic_does_not_restore_signed_reservations=True)
        step('RESTORED_PROFILE_CORE_RESTART_AND_HISTORY')
        stop(c)
        c, reopened, _ = start(2,'reopen',existing_root=restored_root)
        if reopened.get('backup_status') != 'verified':
            _complete_backup_challenge(c, phrase)
        wait(lambda:state(a)['connected'] and state(c)['connected']
                       and state(c)['tip']==before['tip'])
        reopened_view = c.request('snapshot',timeout=240)
        if (reopened['mnemonic_once'] or reopened['receive_code']!=opened['receive_code']
                or reopened_view['confirmed_atoms']!=before['confirmed_atoms']
                or {row['txid'] for row in reopened_view['history']}!=expected
                or reopened_view['signer_allowed'] is not False):
            raise ValueError('Q06_SAME_CHAIN_RESTORE_POST_RESTART_HISTORY_DENIED')
        try:
            if _valid_reservation_map(reopened_view.get('reservation_map')):
                raise ValueError(RESERVATION_DENIED_CODE)
        except ValueError:
            report['mnemonic_does_not_restore_signed_reservations'] = False
            raise
        report['restored_same_owner_core_reopened'] = True
        step('RESTORED_AND_ORIGINAL_OWNERS_CLEAN_SHUTDOWN')
        stop(c)
        stop(a)
    except Exception as error:
        report['status'] = 'FAIL'
        code = error.args[0] if len(error.args)==1 and type(error.args[0]) is str else ''
        report['failure_code'] = code if re.fullmatch('[A-Z0-9_]{5,100}',code) else 'Q06_SAME_CHAIN_RESTORE_DENIED'
        print('Q06_SAME_CHAIN_RESTORE_FAILURE=' + report['failure_code'], flush=True)
    finally:
        clean = True
        for worker in reversed(workers):
            if worker.closed:continue
            if worker.busy:
                clean = False
                continue
            try:stop(worker)
            except Exception:clean = False
        report['all_original_owners_shutdown_verified'] = clean
        if not clean:report['status']='FAIL'
        phrase = None
        (lab/'public-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
