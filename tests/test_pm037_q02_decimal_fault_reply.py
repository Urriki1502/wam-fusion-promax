"""PM-037: Q02's getnetworkinfo fault injection survives Decimal-decoded replies.

Regression found by FC-15 (frozen Q02_CASE=RPC-VERSION): since FEE-1, cli_rpc
decodes getnetworkinfo with parse_float=Decimal, and the probe's json.dumps
re-encoding of the genuine reply raised TypeError.
"""
import json
import unittest
from decimal import Decimal


class Q02ExactFaultReply(unittest.TestCase):
    def test_genuine_decimal_reply_round_trips_exactly_with_the_injected_field(self):
        from wam_regtest.cli_rpc import decode
        from wam_regtest.q02_probe import _exact_json
        raw = (b'{"version":113,"subversion":"/WAM:0.1.13/","protocolversion":70016,'
               b'"relayfee":0.00001000,"incrementalfee":0.00001000,"connections":0,"networks":[]}')
        genuine = decode(raw, 'getnetworkinfo', [])
        self.assertIs(type(genuine['relayfee']), Decimal)
        with self.assertRaises(TypeError):
            json.dumps(genuine)  # the FC-15 failure mode
        for key, bad in (('version', 112), ('version', 113.0), ('subversion', '/WAM:0.1.12/'),
                         ('protocolversion', 0)):
            with self.subTest(key=key, bad=bad):
                mutated = decode(_exact_json({**genuine, key: bad}), 'getnetworkinfo', [])
                self.assertEqual(mutated[key], bad)
                self.assertEqual(mutated['relayfee'], Decimal('0.00001000'))
                self.assertEqual(mutated['incrementalfee'], Decimal('0.00001000'))
                for other in ('version', 'subversion', 'protocolversion', 'connections'):
                    if other != key:
                        self.assertEqual(mutated[other], genuine[other])

    def test_strings_and_keys_resembling_tokens_or_numbers_stay_strings(self):
        # Codex PEER-107 reproductions: a placeholder-shaped string, a matching
        # key, and an escaped-quote string must survive unchanged.
        from wam_regtest.cli_rpc import decode
        from wam_regtest.q02_probe import _exact_json
        genuine = {
            'relayfee': Decimal('0.00001000'),
            'warnings': '__Q02_DECIMAL_0__',
            '__Q02_DECIMAL_0__': 'key text',
            'quoted': 'prefix"__Q02_DECIMAL_0__',
            'numberish': '0.00001000',
            'nested': [Decimal('-1E-8'), {'a': Decimal('0E-8'), 'b': [True, None, 3]}],
        }
        round_trip = json.loads(_exact_json(genuine), parse_float=Decimal)
        self.assertEqual(round_trip, genuine)
        self.assertIs(type(round_trip['warnings']), str)
        self.assertIs(type(round_trip['numberish']), str)
        self.assertEqual(decode(_exact_json(genuine), 'getnetworkinfo', [])['quoted'], 'prefix"__Q02_DECIMAL_0__')

    def test_non_finite_or_unknown_values_are_refused(self):
        from wam_regtest.q02_probe import _exact_json
        with self.assertRaises(TypeError):
            _exact_json({'x': Decimal('NaN')})
        with self.assertRaises(TypeError):
            _exact_json({'x': object()})
        with self.assertRaises(TypeError):
            _exact_json({1: 'non-string key'})
        with self.assertRaises(TypeError):
            _exact_json({'x': float('nan')})


if __name__ == '__main__':
    unittest.main()
