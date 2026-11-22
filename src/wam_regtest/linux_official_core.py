"""Official signed v0.1.13 Linux identity, separate from developer policy.

Member pins come from independent signed-archive intake, never a supplied
receipt. Closed reviewed Ubuntu 24.04 loader closures:
  - 4052c4a75dee853f5a27c2fb1869aee841a075ed8d6187b90a9d1c06a88cf3c2:
    Ubuntu 24.04 closure reviewed from native run 42060782393 (preserved).
  - c2b9b8f0b549de54f2ad02c0afded0d172e321eb7d2596dfd2c188ef69ec312f:
    Ubuntu 24.04 closure (libc6 2.39-0ubuntu8.12, libgcc-s1/libstdc++6
    14.2.0-4ubuntu2~24.04.1) authenticated via GPG-signed Ubuntu InRelease
    (key F6ECB3762474EDA9D21B7022871920D1991BC93C) -> Packages.xz -> .deb
    ELF members AND byte-matched on native GitHub Ubuntu 24.04 intake run
    45032995049 (NATIVE_OFFICIAL_CORE_INTAKE_101_BLOCKS_PASS).
Any future library update requires dual-source review/requalification.
Root witness stays separate.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from .linux_developer_core import native, inspect_elf, _read_binary, _system_file, library_identity, LinuxCoreError
from .official_core_v013 import MEMBERS, SUMS_SHA256, SIGNATURE_SHA256

MANIFEST_NAME='LINUX_OFFICIAL_CORE_MANIFEST.json'
SIGNING_KEY_SHA256='842d9419593efc8fe0a5f45feaeab86710c03b27b3e2416a2dc9205fe506ee63'
LEGACY_MANIFEST_SHA256='4052c4a75dee853f5a27c2fb1869aee841a075ed8d6187b90a9d1c06a88cf3c2'
MANIFEST_SHA256='c2b9b8f0b549de54f2ad02c0afded0d172e321eb7d2596dfd2c188ef69ec312f'


def _build_expected(*, loader_sha256, libc_sha256, libm_sha256):
    libs = {
        'libc.so.6': {'path': '/usr/lib/x86_64-linux-gnu/libc.so.6', 'sha256': libc_sha256},
        'libgcc_s.so.1': {'path': '/usr/lib/x86_64-linux-gnu/libgcc_s.so.1',
                          'sha256': 'd93224d2b0dab4247598be683adca02f5cf00586f99c187579cd7e92058fb7cb'},
        'libm.so.6': {'path': '/usr/lib/x86_64-linux-gnu/libm.so.6', 'sha256': libm_sha256},
        'libstdc++.so.6': {'path': '/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.33',
                           'sha256': '1fd75fe70354a416d75aef22bcae68c47bd25d20e2d0568c30b1a9838cf62f11'},
    }
    loader = {'path': '/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2', 'sha256': loader_sha256}
    elf = {'architecture': 'ELF64-x86_64', 'gnu_stack': 'RW',
           'interpreter': '/lib64/ld-linux-x86-64.so.2'}
    return {
        'files': {
            'wam-cli': {'elf': dict(elf), 'libraries': {k: dict(v) for k, v in libs.items()},
                        'loader': dict(loader),
                        'sha256': 'd99fc90e3aa4233979056d9981a388360e5d7ff77090d00b9bc37191a2425300'},
            'wamd': {'elf': dict(elf), 'libraries': {k: dict(v) for k, v in libs.items()},
                     'loader': dict(loader),
                     'sha256': 'a3e3bf810e74824e3739fd4cbd1a45037cae997056b8c978c4dc1a61d674f0c7'},
        },
        'mainnet_allowed': False,
        'official_signed_release': True,
        'platform': 'linux-x86_64',
        'policy': 'OFFICIAL_SIGNED_V013_REGTEST_ONLY',
        'process_loader_binding_qualified': False,
        'schema': 'wam-linux-official-signed-core/v1',
        'sources': {'wam': 'b3fb899ddb1ceab7e9b3b12ccd034ad1b4be8186'},
    }


LEGACY_EXPECTED = _build_expected(
    loader_sha256='c20a2dc8917c755f02b94049356320fe1f62ac7d9f8994731f807d9df39302da',
    libc_sha256='3a15d66867d83762c7f2f1e37359cb8f6c5743edb369c65285cb0b1c4f7498bf',
    libm_sha256='fce00b6f25f459cf4ae0b7fae4257909a1a8a86f9149e7c029a5d617baf1ccd0',
)
EXPECTED = _build_expected(
    loader_sha256='5fc0940888e9d2e1a00e66d6b1a559c36364ee867683652e1074fa576952cc3f',
    libc_sha256='755a371e86cc9f564ab54f66140747700fb0a103f698f659f2060f707897e09a',
    libm_sha256='5dcc4d25466e29ca390ed6fabb371c69b65dff6fa4e91c34561057a020d6994a',
)
APPROVED_MANIFESTS = {
    LEGACY_MANIFEST_SHA256: LEGACY_EXPECTED,
    MANIFEST_SHA256: EXPECTED,
}


def manifest_bytes(manifest_sha256=None):
    pin = MANIFEST_SHA256 if manifest_sha256 is None else manifest_sha256
    expected = APPROVED_MANIFESTS.get(pin)
    if expected is None:
        raise LinuxCoreError('LINUX_OFFICIAL_MANIFEST_APPROVAL_REQUIRED')
    raw=(json.dumps(expected,sort_keys=True,indent=2)+'\n').encode('ascii')
    if sha256(raw).hexdigest()!=pin:raise LinuxCoreError('LINUX_OFFICIAL_MANIFEST_SOURCE_DENIED')
    return raw


def _public(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid not in (0,os.geteuid())
            or before.st_mode&0o022 or not 1<=before.st_size<=limit):raise LinuxCoreError('LINUX_OFFICIAL_METADATA_CUSTODY_DENIED')
        raw=os.read(fd,limit+1);after=os.fstat(fd)
        if len(raw)!=before.st_size or any(getattr(before,k)!=getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')):
            raise LinuxCoreError('LINUX_OFFICIAL_METADATA_CHANGED')
        return raw
    finally:os.close(fd)


def verify(directory,manifest_sha256,*,authorized=False):
    native()
    expected_manifest=APPROVED_MANIFESTS.get(manifest_sha256)
    if authorized is not True or expected_manifest is None:raise LinuxCoreError('LINUX_OFFICIAL_MANIFEST_APPROVAL_REQUIRED')
    if not directory.is_absolute() or directory.is_symlink():raise LinuxCoreError('LINUX_CORE_DIRECTORY_DENIED')
    from .linux_private_storage import _walk
    fd=_walk(directory,private=False);os.close(fd)
    raw=_public(directory/MANIFEST_NAME,65536)
    if sha256(raw).hexdigest()!=manifest_sha256 or json.loads(raw)!=expected_manifest:raise LinuxCoreError('LINUX_OFFICIAL_MANIFEST_PIN_DENIED')
    # These exact signed public bytes were authenticated at intake. Runtime
    # never needs GnuPG, network access or mutable metadata as trust authority.
    for name,pin in (('SHA256SUMS',SUMS_SHA256),('SHA256SUMS.asc',SIGNATURE_SHA256),('SIGNING-KEY.asc',SIGNING_KEY_SHA256)):
        if sha256(_public(directory/name,32768)).hexdigest()!=pin:raise LinuxCoreError('LINUX_OFFICIAL_SIGNATURE_BYTES_DENIED')
    for name,pin in MEMBERS['linux-x86_64'].items():
        payload=_read_binary(directory/name);expected=expected_manifest['files'][name]
        if sha256(payload).hexdigest()!=pin:raise LinuxCoreError('LINUX_BINARY_APPROVED_HASH_DENIED')
        elf=inspect_elf(payload)
        if elf!=expected['elf'] or _system_file(elf['interpreter'])!=expected['loader'] or library_identity(directory/name)!=expected['libraries']:
            raise LinuxCoreError('LINUX_LOADER_LIBRARY_IDENTITY_DENIED')
    return directory/'wamd',directory/'wam-cli',expected_manifest


def stage(destination,*,manifest_sha256=MANIFEST_SHA256):
    from .official_core_v013 import stage_tar
    stage_tar('linux-x86_64',destination)
    (destination/MANIFEST_NAME).write_bytes(manifest_bytes(manifest_sha256))
    (destination/'manifest.sha256').write_text(manifest_sha256+'\n')
    verify(destination,manifest_sha256,authorized=True)
