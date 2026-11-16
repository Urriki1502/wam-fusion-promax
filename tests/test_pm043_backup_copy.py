"""D5-B exact copy and format contracts; native language review remains pending."""
import json
from pathlib import Path
from string import Formatter
import unittest

from wam_regtest.presentation.strings import CATALOG

LEDGER = json.loads(Path(__file__).with_name('pm043_copy_ledger.json').read_text())


def fields(value):
    return [(name, spec, conversion) for _, name, spec, conversion
            in Formatter().parse(value) if name is not None]


class BackupCopyTests(unittest.TestCase):
    def test_exact_english_security_copy(self):
        for key, expected in LEDGER['english'].items():
            with self.subTest(key=key, review=LEDGER['review'][key]):
                self.assertEqual(CATALOG['en'][key], expected)

    def test_changed_copy_format_parity_in_all_six_languages(self):
        self.assertEqual(set(CATALOG), {'en', 'zh-Hans', 'vi', 'ko', 'id', 'ja'})
        for key, english in LEDGER['english'].items():
            for language, catalog in CATALOG.items():
                with self.subTest(key=key, language=language):
                    self.assertEqual(fields(catalog[key]), fields(english))
                    self.assertTrue(catalog[key].strip())
        for language, catalog in CATALOG.items():
            self.assertIn('1,234,567', catalog['owner.recovery_result'].format(
                history_count=42, confirmed_atoms=1234567), language)
            self.assertIn('7', catalog['recovery_word_position'].format(position=7), language)
