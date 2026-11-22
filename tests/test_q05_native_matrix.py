"""Native matrix receipts must identify every executed case, not a GUI count."""
import copy
import unittest

from wam_regtest.official_core_v013 import MEMBERS
from wam_regtest.q05_checkpoint_scenario import NEGATIVE_MODES
from wam_regtest.q05_native_matrix import BASE_CASES, PLATFORM_CORE_TRUST, require_matrix
from wam_regtest.release import ARCHIVES, CLI_SHA256
from wam_regtest.wsp_live import PINNED_WSP_COMMIT


class NativeMatrixTests(unittest.TestCase):
    def setUp(self):
        self.source = 'a' * 40
        self.proof = dict(candidate_source_sha=self.source, checkout_sha='b' * 40,
                          literal_python_files_verified=440,
                          raw_python_tree_sha256='c' * 64)
        names = ['security', 'signed-completion', 'uncertain-completion',
                 'signed-divergent-cut', 'uncertain-divergent-cut', 'cold-crash',
                 *('negative-' + mode for mode in NEGATIVE_MODES), 'authenticated-control']
        self.matrix = dict(status='PASS', platform='macos-arm64',
                           last_owner_shutdown_verified=True, completed=names,
                           source_provenance=copy.deepcopy(self.proof))
        base = dict(status='PASS', owner_shutdown_verified=True, source_sha=self.source,
                    checkout_sha='b' * 40, source_provenance=self.proof,
                    platform='macos-arm64', core_version='v0.1.13',
                    core_trust='official-signed-v0.1.13',
                    core_sha256={'wamd': ARCHIVES['macos-arm64'][1],
                                 'wam-cli': CLI_SHA256['macos-arm64']},
                    wsp_source_commit=PINNED_WSP_COMMIT, frozen=False,
                    synthetic_rpc=False, mainnet_allowed=False)
        self.receipts = {name: copy.deepcopy(base) for name in names}
        del self.receipts['authenticated-control']['source_provenance']
        del self.receipts['authenticated-control']['owner_shutdown_verified']
        self.receipts['authenticated-control']['core_shutdown_confirmed'] = True
        self.receipts['cold-crash']['observations'] = [
            dict(owned_Core_flush_before_cold_crash=True, height=1, tip='d' * 64,
                 history_sha256='e' * 64, reservation_sha256='f' * 64,
                 no_clean_shutdown_of_this_Core_before_SIGKILL=True),
            dict(same_owner_core_crash_recovered=True, automatic_wallet_replay=False,
                 height=1, tip='d' * 64,
                 history_sha256='e' * 64, reservation_sha256='f' * 64,
                 crash_scope='after-owned-Core-flush-without-clean-shutdown')]

    def check(self):
        require_matrix(self.matrix, self.receipts, self.source, 'macos-arm64',
                       source_provenance=self.proof)

    def test_complete_native_set_passes_without_claiming_gui(self):
        self.check()
        self.assertNotIn('gui', self.matrix['completed'])

    def test_missing_duplicate_extra_or_wrong_platform_case_denied(self):
        for kind in ('missing', 'duplicate', 'extra', 'platform'):
            with self.subTest(kind=kind):
                original = copy.deepcopy(self.matrix)
                if kind == 'missing': self.matrix['completed'].remove('cold-crash')
                elif kind == 'duplicate': self.matrix['completed'].append('security')
                elif kind == 'extra': self.matrix['completed'].append('gui')
                else: self.matrix['platform'] = 'windows-x64'
                with self.assertRaisesRegex(ValueError, 'NATIVE_MATRIX'):
                    self.check()
                self.matrix = original

    def test_each_case_requires_source_core_wsp_and_safe_owner(self):
        for name in self.receipts:
            for field, bad in (('status', 'FAIL'), ('owner_shutdown_verified', False),
                    ('source_sha', '0' * 40), ('checkout_sha', '0' * 40),
                    ('source_provenance', {}), ('core_version', 'v0.1.11'),
                    ('core_trust', 'unverified'), ('core_sha256', {}),
                    ('wsp_source_commit', '0' * 40), ('frozen', True),
                    ('synthetic_rpc', True), ('mainnet_allowed', True)):
                with self.subTest(name=name, field=field):
                    if name == 'authenticated-control' and field == 'source_provenance':
                        continue  # This producer binds source/checkout directly.
                    if name == 'authenticated-control' and field == 'owner_shutdown_verified':
                        field = 'core_shutdown_confirmed'
                    good = self.receipts[name][field]
                    self.receipts[name][field] = bad
                    with self.assertRaisesRegex(ValueError, 'NATIVE_MATRIX'):
                        self.check()
                    self.receipts[name][field] = good

    def test_matrix_requires_attested_source_tree_and_shutdown(self):
        for field, bad in (('status', 'FAIL'), ('last_owner_shutdown_verified', False),
                           ('source_provenance', {})):
            with self.subTest(field=field):
                good = self.matrix[field]
                self.matrix[field] = bad
                with self.assertRaisesRegex(ValueError, 'NATIVE_MATRIX'):
                    self.check()
                self.matrix[field] = good

    def test_matching_receipts_cannot_substitute_another_python_tree(self):
        self.matrix['source_provenance']['raw_python_tree_sha256'] = '0' * 64
        for name, item in self.receipts.items():
            if name != 'authenticated-control':
                item['source_provenance']['raw_python_tree_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'NATIVE_MATRIX'):
            self.check()

    def test_receipt_cannot_substitute_the_wrong_shutdown_authority(self):
        for name, item in self.receipts.items():
            with self.subTest(name=name):
                field = ('core_shutdown_confirmed' if name == 'authenticated-control'
                         else 'owner_shutdown_verified')
                other = ('owner_shutdown_verified' if name == 'authenticated-control'
                         else 'core_shutdown_confirmed')
                del item[field]
                item[other] = True
                with self.assertRaisesRegex(ValueError, 'NATIVE_MATRIX'):
                    self.check()
                item[field] = True
                del item[other]

    def test_unrecovered_crash_replay_or_changed_financial_state_denied(self):
        crash = self.receipts['cold-crash']
        for index, field, bad in ((0, 'owned_Core_flush_before_cold_crash', False),
                (0, 'no_clean_shutdown_of_this_Core_before_SIGKILL', False),
                (0, 'height', 0), (0, 'history_sha256', 'invalid'),
                (1, 'same_owner_core_crash_recovered', False),
                (1, 'height', 2), (1, 'tip', '0' * 64),
                (1, 'automatic_wallet_replay', True),
                (1, 'history_sha256', '0' * 64), (1, 'reservation_sha256', '0' * 64)):
            with self.subTest(field=field, index=index):
                good = crash['observations'][index][field]
                crash['observations'][index][field] = bad
                with self.assertRaisesRegex(ValueError, 'NATIVE_MATRIX'):
                    self.check()
                crash['observations'][index][field] = good
        crash['observations'] = []
        with self.assertRaisesRegex(ValueError, 'NATIVE_MATRIX'):
            self.check()

    def test_windows_and_linux_18_case_native_sets_validate_platform_pins(self):
        for plat in ('windows-x64', 'linux-x86_64'):
            with self.subTest(platform=plat):
                names = sorted(BASE_CASES)
                matrix = dict(status='PASS', platform=plat,
                              last_owner_shutdown_verified=True, completed=names,
                              source_provenance=copy.deepcopy(self.proof))
                base = dict(status='PASS', owner_shutdown_verified=True, source_sha=self.source,
                            checkout_sha='b' * 40, source_provenance=self.proof,
                            platform=plat, core_version='v0.1.13',
                            core_trust=PLATFORM_CORE_TRUST[plat],
                            core_sha256=dict(MEMBERS[plat]),
                            wsp_source_commit=PINNED_WSP_COMMIT, frozen=False,
                            synthetic_rpc=False, mainnet_allowed=False)
                receipts = {name: copy.deepcopy(base) for name in names}
                receipts['cold-crash']['observations'] = copy.deepcopy(
                    self.receipts['cold-crash']['observations'])
                require_matrix(matrix, receipts, self.source, plat, source_provenance=self.proof)
                # Wrong binary keys (e.g. POSIX names on Windows) must be refused.
                receipts['security']['core_sha256'] = dict(MEMBERS['macos-arm64'])
                with self.assertRaisesRegex(ValueError, 'NATIVE_MATRIX'):
                    require_matrix(matrix, receipts, self.source, plat, source_provenance=self.proof)


if __name__ == '__main__':
    unittest.main()
