"""Safety copy separates unconditional prohibitions from automatic retry rules."""
import unittest

from wam_regtest.presentation.strings import CATALOG


class SafetyScopeTests(unittest.TestCase):
    def test_lock_release_prohibition_stands_alone(self):
        # Full sentences, so an automatic adverb cannot govern lock release.
        clauses = {
            'vi': ('Không bao giờ giải phóng khóa.', 'Đừng giải phóng khóa.'),
            'zh-Hans': ('绝不解除锁定。', '请不要释放锁定。'),
            'ko': ('잠금을 해제하지 않습니다.', '잠금을 해제하지 마십시오.'),
            'id': ('Jangan pernah melepas kunci.', 'Jangan melepas kunci.'),
        }
        for language, (reservation, signing) in clauses.items():
            self.assertIn(reservation, CATALOG[language]['owner.reservations_warning'])
            self.assertIn(signing, CATALOG[language]['errors.WALLET_SIGN_UNCERTAIN_LOCK_RETAINED'])
        self.assertIn('ロックを解除しないでください。',
                      CATALOG['ja']['errors.WALLET_SIGN_UNCERTAIN_LOCK_RETAINED'])

    def test_resume_prohibitions_are_independent(self):
        for language, clauses in {
            'vi': ('Không bao giờ ký lại.', 'Không bao giờ tự động thử lại.',
                   'Không bao giờ giải phóng các khoản giữ chỗ.'),
            'zh-Hans': ('绝不重新签名。', '绝不自动重试。', '绝不解除预留。'),
            'ko': ('다시 서명하지 않습니다.', '자동으로 다시 시도하지 않습니다.',
                   '잠금을 해제하지 않습니다.'),
            'id': ('Tidak pernah menandatangani ulang.',
                   'Tidak pernah mencoba ulang secara otomatis.',
                   'Tidak pernah melepas kunci.'),
        }.items():
            value = CATALOG[language]['owner.resume_tooltip']
            for clause in clauses:
                self.assertIn(clause, value)

    def test_external_node_adoption_is_forbidden_independently(self):
        for language, clause in {
            'vi': 'Không được nhận nút bên ngoài.',
            'ja': '外部ノードの採用は許可されません。',
            'zh-Hans': '不允许采纳外部节点。',
            'ko': '외부 노드 채택은 허용되지 않습니다.',
            'id': 'Mengadopsi node eksternal tidak diizinkan.',
        }.items():
            self.assertIn(clause, CATALOG[language]['errors.WALLET_CORE_REAUTHENTICATION_REQUIRED'])

    def test_japanese_confirmation_label_matches_guidance(self):
        label = CATALOG['ja']['owner.confirm_block']
        self.assertEqual(label, '1 REGTEST ブロックを確認')
        self.assertIn('「' + label + '」', CATALOG['ja']['owner.awaiting_confirmation'])
        self.assertNotIn('承認', label)
