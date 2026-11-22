"""Verify current macOS native primitives, separately from product GUI proof.

The legacy managed GUI was retired by PM-086. This verifier does not promote
these receipts to current BIP39 GUI, frozen, physical or full-Q acceptance.
"""
import re

from .q05_checkpoint_scenario import NEGATIVE_MODES
from .release import ARCHIVES, CLI_SHA256
from .wsp_live import PINNED_WSP_COMMIT

MACOS_CASES = frozenset(('security', 'signed-completion', 'uncertain-completion',
                        'signed-divergent-cut', 'uncertain-divergent-cut', 'cold-crash',
                        'authenticated-control',
                        *('negative-' + mode for mode in NEGATIVE_MODES)))


def require_matrix(matrix, receipts, source, platform, *, source_provenance):
    def require(condition):
        if not condition:
            raise ValueError('Q05_NATIVE_MATRIX_RECEIPT_DENIED')

    require(platform == 'macos-arm64' and re.fullmatch('[0-9a-f]{40}', source))
    expected = MACOS_CASES
    completed = matrix.get('completed', [])
    proof = matrix.get('source_provenance', {})
    require(proof == source_provenance
            and matrix.get('status') == 'PASS' and matrix.get('platform') == platform
            and matrix.get('last_owner_shutdown_verified') is True
            and len(completed) == len(expected) and set(completed) == expected
            and set(receipts) == expected and proof.get('candidate_source_sha') == source
            and re.fullmatch('[0-9a-f]{40}', proof.get('checkout_sha', ''))
            and type(proof.get('literal_python_files_verified')) is int
            and proof['literal_python_files_verified'] > 0
            and re.fullmatch('[0-9a-f]{64}', proof.get('raw_python_tree_sha256', '')))
    for name, item in receipts.items():
        shutdown_field = ('core_shutdown_confirmed' if name == 'authenticated-control'
                          else 'owner_shutdown_verified')
        require(item.get('status') == 'PASS'
                and item.get(shutdown_field) is True
                and item.get('source_sha') == source
                and item.get('checkout_sha') == proof['checkout_sha']
                and item.get('platform') == platform and item.get('frozen') is False
                and item.get('synthetic_rpc') is False and item.get('mainnet_allowed') is False
                and item.get('core_version') == 'v0.1.13'
                and item.get('core_trust') == 'official-signed-v0.1.13'
                and item.get('core_sha256') == {'wamd': ARCHIVES[platform][1],
                                               'wam-cli': CLI_SHA256[platform]}
                and item.get('wsp_source_commit') == PINNED_WSP_COMMIT)
        # The older lifecycle producer binds source/checkout directly and
        # independently authenticates Core; other producers emit the full tree.
        if name != 'authenticated-control':
            require(item.get('source_provenance') == proof)
    observations = receipts['cold-crash'].get('observations', [])
    require(len(observations) == 2)
    flush, recovered = observations
    require(flush.get('owned_Core_flush_before_cold_crash') is True
            and flush.get('no_clean_shutdown_of_this_Core_before_SIGKILL') is True
            and type(flush.get('height')) is int and flush['height'] >= 1
            and re.fullmatch('[0-9a-f]{64}', flush.get('tip', ''))
            and recovered.get('same_owner_core_crash_recovered') is True
            and recovered.get('automatic_wallet_replay') is False
            and recovered.get('height') == flush['height']
            and recovered.get('tip') == flush['tip']
            and recovered.get('crash_scope') == 'after-owned-Core-flush-without-clean-shutdown')
    for field in ('history_sha256', 'reservation_sha256'):
        require(re.fullmatch('[0-9a-f]{64}', flush.get(field, ''))
                and recovered.get(field) == flush[field])
