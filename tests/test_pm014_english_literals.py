"""PM-014: pinned English literals still match the presentation catalog."""
import json
import unittest
from pathlib import Path

from wam_regtest.presentation.strings import CATALOG, text

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / 'tests/pm014_english_literals.json').read_text())


class Pm014EnglishLiterals(unittest.TestCase):
    def test_legacy_english_and_vietnamese_literals(self):
        for language, entries in FIXTURE['legacy'].items():
            for key, literal in entries.items():
                self.assertEqual(CATALOG[language][key].encode(), literal.encode(), key)

    def test_error_literals(self):
        for code, literal in FIXTURE['errors'].items():
            self.assertEqual(text('errors.' + code, 'en').encode(), literal.encode(), code)

    def test_not_observed_locally_has_no_not_gone_claim(self):
        self.assertEqual(
            CATALOG['en']['rec1.NOT_OBSERVED_LOCALLY'],
            'Not seen by this node. This does not mean the payment failed. '
            'Funds stay reserved and no automatic action is taken.')
        for language, entries in CATALOG.items():
            value = entries['rec1.NOT_OBSERVED_LOCALLY']
            self.assertNotIn('not gone', value.lower(), language)
            self.assertNotIn('chưa biến mất', value, language)
            self.assertNotIn('并未消失', value, language)


if __name__ == '__main__':
    unittest.main()
