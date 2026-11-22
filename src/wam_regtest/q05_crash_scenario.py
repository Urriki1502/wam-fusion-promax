"""Native/frozen cold-crash proof after an owned Core flush. No GUI spend.

Consent and a new disposable root are required for a PASS receipt. Native
source is attested; frozen execution additionally uses package provenance.
This scenario constructs CoreSupervisor and the checkpoint engine
only. It does not construct a product wallet backend and it does not spend.
"""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

from .core import verified_core_paths
from .core_supervisor import CoreSupervisor
from .custody import create_directory
from .managed_wallet_checkpoint import checkpoint
from .probe_source import verify_source
from .q05_platforms import detect_adapter
from .wallet_session import WalletCoreCli
from .wsp_live import PINNED_WSP_COMMIT, _pinned_source, public_regtest_mining_address


def main(argv=None, *, core=None, source=None, frozen=False):
    p = argparse.ArgumentParser()
    if not frozen:
        p.add_argument('--core-dir', type=Path, required=True)
        p.add_argument('--wsp-source', type=Path, required=True)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--receipt', type=Path, required=True)
    p.add_argument('--confirm-disposable-regtest', action='store_true')
    p.add_argument('--linux-developer-manifest')
    p.add_argument('--linux-root-witness', type=Path)
    p.add_argument('--qualification-test-witness', action='store_true')
    a = p.parse_args(argv)
    if (not a.confirm_disposable_regtest or not a.root.is_absolute()
            or not re.fullmatch('wam-fusion-core-[0-9a-f]{16}', a.root.name)
            or a.root.exists() or a.root.is_symlink()
            or not a.receipt.is_absolute() or a.receipt.exists() or a.receipt.is_symlink()
            or type(frozen) is not bool):
        raise ValueError('Q05_CRASH_DISPOSABLE_SCOPE_DENIED')
    if frozen:
        from .q05_package_provenance import read
        proof = read()
        a.core_dir = core
        a.wsp_source = source
        if sys.platform == 'linux' and (not a.linux_developer_manifest or not a.linux_root_witness):
            raise ValueError('Q05_FROZEN_EXPLICIT_SCOPE_REQUIRED')
    else:
        proof = verify_source(Path(__file__).resolve().parents[2])
    adapter = detect_adapter()
    adapter.enforce_host()
    adapter.prepare_trust(a.core_dir, a.linux_developer_manifest, a.linux_root_witness,
                          test_witness=a.qualification_test_witness)
    node, cli, _ = verified_core_paths(a.core_dir)
    _pinned_source(a.wsp_source)
    record = {
        'schema': 'q05-cold-crash-native/v1', 'status': 'FAIL',
        'source_provenance': proof,
        'source_sha': proof['candidate_source_sha'], 'checkout_sha': proof['checkout_sha'],
        'platform': adapter.platform_id, 'core_version': 'v0.1.13',
        'core_trust': adapter.core_trust,
        'core_sha256': {path.name: sha256(path.read_bytes()).hexdigest() for path in (node, cli)},
        'wsp_source_commit': PINNED_WSP_COMMIT, 'frozen': frozen, 'synthetic_rpc': False,
        'mainnet_allowed': False, 'profile_root': str(a.root), 'observations': [],
    }
    owner = None
    original = None
    password = b'public-cold-crash-fixture-only'
    send_calls = []
    original_call = WalletCoreCli.call

    def observe_call(client, method, params=None):
        if method == 'sendrawtransaction':
            send_calls.append(True)
        return original_call(client, method, params)

    WalletCoreCli.call = observe_call
    try:
        create_directory(a.root)
        owner = CoreSupervisor(a.root, a.core_dir, authorized=True)
        owner.start(timeout=30)
        original = owner.process
        keychain = adapter.make_anchor(a.root)
        checkpoint(owner, a.wsp_source, password, authorized=True, keychain=keychain, create=True)
        address = public_regtest_mining_address(a.wsp_source)
        rpc = WalletCoreCli(owner.cli, owner.directory)
        try:
            rpc.attest()
            mined = rpc._call('generatetoaddress', ['1', address])
            if type(mined) is not list or len(mined) != 1:
                raise ValueError('Q05_CRASH_FLUSH_DENIED')
        finally:
            if getattr(rpc, '_transport', None) is not None:
                rpc._transport.close()
        flushed = checkpoint(owner, a.wsp_source, password, authorized=True, keychain=keychain)
        if (original.poll() is not None or owner.process is not original
                or flushed['height'] < 1 or send_calls
                or type(flushed.get('history_sha256')) is not str
                or type(flushed.get('reservation_sha256')) is not str):
            raise ValueError('Q05_CRASH_FLUSH_DENIED')
        owner.binding._assert_image()
        record['observations'].append({
            'owned_Core_flush_before_cold_crash': True,
            'height': flushed['height'], 'tip': flushed['tip'],
            'history_sha256': flushed['history_sha256'],
            'reservation_sha256': flushed['reservation_sha256'],
            'no_clean_shutdown_of_this_Core_before_SIGKILL': True,
        })
        original.kill()
        original.wait(timeout=10)
        failed = owner.status()
        if failed['state'] != 'recovery-needed' or owner.journal.state != 'FAULT':
            raise ValueError('Q05_CRASH_NOT_DIRTY')
        owner.recover_dead(authorized=True)
        if owner.process is original or owner.process.poll() is not None:
            raise ValueError('Q05_CRASH_SAME_OWNER_RECOVERY_DENIED')
        restored = checkpoint(owner, a.wsp_source, password, authorized=True, keychain=keychain)
        if (send_calls or restored['history_sha256'] != flushed['history_sha256']
                or restored['reservation_sha256'] != flushed['reservation_sha256']
                or restored['height'] != flushed['height'] or restored['tip'] != flushed['tip']):
            raise ValueError('Q05_CRASH_RECOVERY_IDENTITY_CHANGED')
        record['observations'].append({
            'same_owner_core_crash_recovered': True,
            'height': restored['height'], 'tip': restored['tip'],
            'history_sha256': restored['history_sha256'],
            'reservation_sha256': restored['reservation_sha256'],
            'automatic_wallet_replay': False,
            'crash_scope': 'after-owned-Core-flush-without-clean-shutdown',
        })
        owner.shutdown()
        record['status'] = 'PASS'
    except Exception as error:
        record['failure_type'] = type(error).__name__
        code = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else None
        if type(code) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{1,95}', code):
            record['failure_code'] = code
    finally:
        WalletCoreCli.call = original_call
        if owner is not None and owner.process is not None and owner.process.poll() is None:
            try:
                owner.recover_stop()
            except (OSError, ValueError, RuntimeError):
                record['original_owner_retained'] = True
        safe = owner is None or owner.process is None or owner.process.poll() is not None
        if owner is not None and safe:
            try:
                owner.release()
                owner.close()
            except (OSError, ValueError, RuntimeError):
                safe = False
        record['owner_shutdown_verified'] = safe
        if safe and record['status'] == 'PASS':
            adapter.teardown()
        elif getattr(adapter, '_witness', None) is not None:
            record['retained_qualification_witness_root'] = str(adapter._witness.root)
        record['timestamp_utc'] = datetime.now(timezone.utc).isoformat()
        with a.receipt.open('x') as out:
            json.dump(record, out, indent=2)
            out.write('\n')
    print(json.dumps({'status': record['status'], 'source_sha': record['source_sha']}))
    return 0 if record['status'] == 'PASS' and record['owner_shutdown_verified'] is True else 2
