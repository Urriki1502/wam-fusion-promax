"""FEE-1: automatic fee policy (pure component, read-only adapter, exact size).

Two fixture families, never mixed:
  * ACTUAL: real official WAM Core v0.1.13 REGTEST responses
    (tests/fixtures/fee_rpc_regtest_v013_empty.json).
  * HISTORICAL_MEASUREMENT_2026: the WAM maintainer's mainnet observation
    (relay floors 0.00001000; estimatesmartfee 2/6/25 = 0.00020064; short
    horizon insufficient; ~43.93 medium samples). Recorded evidence of a
    weak, self-referential estimator, NOT current market data or constants.
  * SIMULATED: hand-built fee-market conditions, labelled as such.
"""
import copy
import json
import re
import unittest
from decimal import Decimal
from pathlib import Path

from wam_regtest.domain import fee_policy as fp

ROOT = Path(__file__).resolve().parents[1]
NUMBER = re.compile(r'-?\d+(\.\d+)?(E[+-]?\d+)?\Z', re.I)


def _decimalize(value, key=None):
    if isinstance(value, dict):
        return {k: _decimalize(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_decimalize(v) for v in value]
    if isinstance(value, str) and key not in ('subversion',) and NUMBER.match(value):
        return Decimal(value)
    return value


ACTUAL = _decimalize(json.loads((ROOT / 'tests/fixtures/fee_rpc_regtest_v013_empty.json').read_text()))


def actual_inputs():
    smart = {t: ACTUAL['estimatesmartfee_%d_conservative' % t] for t in fp.ESTIMATE_TARGETS}
    return fp.parse_policy_inputs('regtest', ACTUAL['getnetworkinfo'], ACTUAL['getmempoolinfo'],
                                  smart, {6: ACTUAL['estimaterawfee_6']})


def historical_maintainer_inputs():
    """HISTORICAL_MEASUREMENT_2026 (maintainer, live WAM mainnet). Not constants."""
    floor = Decimal('0.00001000')
    smart = {t: {'feerate': Decimal('0.00020064'), 'blocks': t} for t in fp.ESTIMATE_TARGETS}
    raw = {6: {
        'short': {'decay': Decimal('0.962'), 'scale': 1, 'errors': ['Insufficient data or no feerate found which meets threshold'],
                  'fail': {'totalconfirmed': Decimal('0')}},
        'medium': {'feerate': Decimal('0.00020064'), 'decay': Decimal('0.9952'), 'scale': 2,
                   'pass': {'totalconfirmed': Decimal('43.93')}},
    }}
    return fp.parse_policy_inputs(
        'mainnet', {'version': 113, 'relayfee': floor, 'incrementalfee': floor},
        {'loaded': True, 'size': 0, 'mempoolminfee': floor, 'minrelaytxfee': floor,
         'incrementalrelayfee': floor}, smart, raw)


def simulated_inputs(*, relay='0.00001000', mempoolmin='0.00001000', minrelay='0.00001000',
                     smart_rates=('0.00008000', '0.00005000', '0.00003000'), short_samples='500',
                     raw_errors=False, incremental='0.00001000', mempool_size=0):
    """SIMULATED fee-market condition with independent, well-sampled estimates."""
    smart = {t: {'feerate': Decimal(r), 'blocks': t} for t, r in zip(fp.ESTIMATE_TARGETS, smart_rates)}
    short = {'decay': Decimal('0.962'), 'scale': 1, 'feerate': Decimal(smart_rates[1]),
             'pass': {'totalconfirmed': Decimal(short_samples)}}
    if raw_errors:
        short = {'decay': Decimal('0.962'), 'scale': 1, 'errors': ['Insufficient data']}
    return fp.parse_policy_inputs(
        'regtest', {'version': 113, 'relayfee': Decimal(relay), 'incrementalfee': Decimal(incremental)},
        {'loaded': True, 'size': mempool_size, 'mempoolminfee': Decimal(mempoolmin),
         'minrelaytxfee': Decimal(minrelay)}, smart, {6: {'short': short}})


class RateConversion(unittest.TestCase):
    def test_exact_decimal_rates_convert_to_integer_atoms_per_kvb(self):
        self.assertEqual(fp.coin_rate_to_atoms_per_kvb(Decimal('0.00001000')), 1000)
        self.assertEqual(fp.coin_rate_to_atoms_per_kvb(Decimal('0.00020064')), 20064)
        self.assertEqual(fp.coin_rate_to_atoms_per_kvb(0), 0)
        self.assertEqual(fp.coin_rate_to_atoms_per_kvb(Decimal('1')), 100_000_000)

    def test_floats_strings_bools_and_imprecise_or_out_of_range_rates_are_refused(self):
        for bad, code in ((0.00001, 'FEE_POLICY_RATE_TYPE'), ('0.00001000', 'FEE_POLICY_RATE_TYPE'),
                          (True, 'FEE_POLICY_RATE_TYPE'), (None, 'FEE_POLICY_RATE_TYPE'),
                          (Decimal('0.000010001'), 'FEE_POLICY_RATE_PRECISION'),
                          (Decimal('NaN'), 'FEE_POLICY_RATE_PRECISION'),
                          (Decimal('-0.00001'), 'FEE_POLICY_RATE_RANGE'),
                          (Decimal('1.00000001'), 'FEE_POLICY_RATE_RANGE')):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(fp.FeePolicyError, code):
                    fp.coin_rate_to_atoms_per_kvb(bad)


class Arithmetic(unittest.TestCase):
    def test_fee_is_the_integer_ceiling(self):
        self.assertEqual(fp.fee_for_vsize(154, 1000), 154)
        self.assertEqual(fp.fee_for_vsize(154, 1001), 155)     # 154.154 -> 155
        self.assertEqual(fp.fee_for_vsize(1000, 1999), 1999)
        self.assertEqual(fp.fee_for_vsize(1, 1), 1)            # 0.001 -> 1
        self.assertEqual(fp.fee_for_vsize(7457, 20064), 149618)  # 149617.248 -> 149618
        for vsize in range(1, 400):
            for rate in (1, 999, 1000, 1001, 20064):
                fee = fp.fee_for_vsize(vsize, rate)
                self.assertGreaterEqual(fee * 1000, vsize * rate)
                self.assertLess((fee - 1) * 1000, vsize * rate)

    def test_invalid_sizes_and_rates_are_refused(self):
        for vsize, rate in ((0, 1000), (-1, 1000), (1.0, 1000), (154, 0), (154, 10**9), (154, 1000.0)):
            with self.subTest(vsize=vsize, rate=rate):
                with self.assertRaises(fp.FeePolicyError):
                    fp.fee_for_vsize(vsize, rate)


class ActualRegtestCore(unittest.TestCase):
    def test_empty_regtest_has_no_estimate_and_uses_the_verified_floor(self):
        inputs = actual_inputs()
        self.assertEqual((inputs.relayfee, inputs.mempoolminfee, inputs.minrelaytxfee), (1000, 1000, 1000))
        self.assertEqual(fp.classify_estimator(inputs)[0], fp.UNAVAILABLE)
        quote = fp.quote(inputs)
        self.assertEqual((quote.rate_atoms_per_kvb, quote.source), (1000, fp.SOURCE_FLOOR))
        self.assertEqual(fp.fee_for_vsize(154, quote.rate_atoms_per_kvb), 154)


class HistoricalMaintainerMeasurement(unittest.TestCase):
    def test_identical_weakly_sampled_estimates_are_not_trusted(self):
        inputs = historical_maintainer_inputs()
        classification, reasons = fp.classify_estimator(inputs)
        self.assertEqual(classification, fp.UNVALIDATED)
        for reason in ('HORIZONS_IDENTICAL', 'SHORT_HORIZON_INSUFFICIENT', 'SAMPLES_BELOW_THRESHOLD'):
            self.assertIn(reason, reasons)
        quote = fp.quote(inputs)
        # The floor-based policy, not the 0.00020064 estimate or the fallback.
        self.assertEqual((quote.rate_atoms_per_kvb, quote.source), (1000, fp.SOURCE_FLOOR))

    def test_an_estimate_equal_to_cores_fallback_is_not_evidence(self):
        inputs = simulated_inputs(smart_rates=('0.00020000', '0.00020000', '0.00010000'))
        self.assertIn('EQUALS_CORE_FALLBACK', fp.classify_estimator(inputs)[1])


class SimulatedMarkets(unittest.TestCase):
    def test_usable_independent_estimate_above_the_floor_is_used(self):
        quote = fp.quote(simulated_inputs())
        self.assertEqual(fp.classify_estimator(simulated_inputs())[0], fp.USABLE)
        self.assertEqual((quote.rate_atoms_per_kvb, quote.source), (5000, fp.SOURCE_ESTIMATOR))

    def test_usable_estimate_below_the_floor_never_undercuts_it(self):
        inputs = simulated_inputs(mempoolmin='0.00009000')
        quote = fp.quote(inputs)
        self.assertEqual((quote.rate_atoms_per_kvb, quote.source), (9000, fp.SOURCE_FLOOR))

    def test_an_empty_mempool_alone_does_not_discard_good_evidence(self):
        self.assertEqual(fp.classify_estimator(simulated_inputs(mempool_size=0))[0], fp.USABLE)

    def test_floor_is_the_maximum_of_the_three_minimums(self):
        for relay, mempoolmin, minrelay, expected in (
                ('0.00003000', '0.00001000', '0.00001000', 3000),
                ('0.00001000', '0.00004000', '0.00001000', 4000),
                ('0.00001000', '0.00002000', '0.00002000', 2000)):
            with self.subTest(expected=expected):
                inputs = simulated_inputs(relay=relay, mempoolmin=mempoolmin, minrelay=minrelay,
                                          smart_rates=('0.00001000',) * 3, raw_errors=True)
                self.assertEqual(fp.quote(inputs).floor_atoms_per_kvb, expected)
                self.assertEqual(fp.quote(inputs).rate_atoms_per_kvb, expected)

    def test_incremental_fee_is_not_added_to_new_transactions(self):
        inputs = simulated_inputs(incremental='0.00050000', raw_errors=True)
        self.assertEqual(fp.quote(inputs).rate_atoms_per_kvb, 1000)

    def test_rising_mempool_floor_invalidates_an_unsigned_quote(self):
        quote = fp.quote(simulated_inputs(raw_errors=True))
        self.assertTrue(fp.quote_still_valid(quote, simulated_inputs(raw_errors=True)))
        self.assertFalse(fp.quote_still_valid(quote, simulated_inputs(mempoolmin='0.00002000', raw_errors=True)))
        lower = fp.quote(simulated_inputs(mempoolmin='0.00002000', raw_errors=True))
        self.assertTrue(fp.quote_still_valid(lower, simulated_inputs(raw_errors=True)))  # floor fell

    def test_quote_is_bound_to_its_network(self):
        quote = fp.quote(actual_inputs())
        self.assertFalse(fp.quote_still_valid(quote, historical_maintainer_inputs()))

    def test_missing_raw_evidence_can_only_weaken_the_estimator(self):
        smart = {t: {'feerate': Decimal(r), 'blocks': t}
                 for t, r in zip(fp.ESTIMATE_TARGETS, ('0.00008000', '0.00005000', '0.00003000'))}
        inputs = fp.parse_policy_inputs('regtest', {'version': 113, 'relayfee': Decimal('0.00001')},
                                        {'loaded': True, 'mempoolminfee': Decimal('0.00001'),
                                         'minrelaytxfee': Decimal('0.00001')}, smart, {6: None})
        classification, reasons = fp.classify_estimator(inputs)
        self.assertEqual(classification, fp.UNVALIDATED)
        self.assertIn('RAW_EVIDENCE_MISSING', reasons)
        self.assertEqual(fp.quote(inputs).source, fp.SOURCE_FLOOR)

    def test_digest_tracks_every_input_a_quote_depends_on(self):
        a, b = simulated_inputs(), simulated_inputs(mempoolmin='0.00002000')
        self.assertEqual(a.digest(), simulated_inputs().digest())
        self.assertNotEqual(a.digest(), b.digest())


class InvalidInputs(unittest.TestCase):
    def _parse(self, mutate):
        net = copy.deepcopy(ACTUAL['getnetworkinfo'])
        mem = copy.deepcopy(ACTUAL['getmempoolinfo'])
        smart = {t: copy.deepcopy(ACTUAL['estimatesmartfee_%d_conservative' % t]) for t in fp.ESTIMATE_TARGETS}
        mutate(net, mem, smart)
        return fp.parse_policy_inputs('regtest', net, mem, smart, {6: None})

    def test_missing_mistyped_or_contradictory_fields_fail_closed(self):
        cases = (
            (lambda n, m, s: n.pop('relayfee'), 'FEE_POLICY_UNVERIFIED'),
            (lambda n, m, s: m.pop('mempoolminfee'), 'FEE_POLICY_UNVERIFIED'),
            (lambda n, m, s: n.update(version='113'), 'FEE_POLICY_UNVERIFIED'),
            (lambda n, m, s: n.update(relayfee=0.00001), 'FEE_POLICY_RATE_TYPE'),
            (lambda n, m, s: m.update(loaded=False), 'FEE_POLICY_MEMPOOL_NOT_LOADED'),
            (lambda n, m, s: m.update(minrelaytxfee=Decimal(0)), 'FEE_POLICY_FLOOR_MISSING'),
            (lambda n, m, s: m.update(mempoolminfee=Decimal('0.000005')), 'FEE_POLICY_CONTRADICTORY'),
            (lambda n, m, s: s.pop(25), 'FEE_POLICY_UNVERIFIED'),
            (lambda n, m, s: s[6].update(errors='bad'), 'FEE_POLICY_UNVERIFIED'),
            (lambda n, m, s: s[6].update(blocks='2'), 'FEE_POLICY_UNVERIFIED'),
        )
        for mutate, code in cases:
            with self.subTest(code=code):
                with self.assertRaisesRegex(fp.FeePolicyError, code):
                    self._parse(mutate)

    def test_wrong_or_missing_network_identity_is_refused(self):
        with self.assertRaisesRegex(fp.FeePolicyError, 'FEE_POLICY_NETWORK'):
            fp.parse_policy_inputs('', ACTUAL['getnetworkinfo'], ACTUAL['getmempoolinfo'], {}, {})


class Limits(unittest.TestCase):
    def setUp(self):
        self.quote = fp.quote(actual_inputs())  # floor 1000 atoms/kvB

    def test_floor_fee_is_accepted(self):
        fp.check_fee_limits(154, 100_000, 154, self.quote)
        # The network minimum is never "disproportionate", even for a small amount.
        fp.check_fee_limits(154, 330, 154, self.quote)
        fp.check_fee_limits(10_000, 100_000, 154, self.quote)

    def test_below_floor_absolute_and_disproportionate_fees_are_refused(self):
        for fee, amount, code in ((153, 100_000, 'FEE_BELOW_NETWORK_FLOOR'),
                                  (1_000_001, 10**12, 'FEE_ABSOLUTE_LIMIT'),
                                  (0, 100_000, 'FEE_ABSOLUTE_LIMIT'),
                                  (331, 330, 'FEE_EXCEEDS_AMOUNT'),
                                  (155, 1000, 'FEE_DISPROPORTIONATE'),        # > max(100, 154)
                                  (10_001, 100_000, 'FEE_DISPROPORTIONATE')):  # > max(10000, 154)
            with self.subTest(fee=fee, amount=amount):
                with self.assertRaisesRegex(fp.FeePolicyError, code):
                    fp.check_fee_limits(fee, amount, 154, self.quote)


class ReadOnlyAdapter(unittest.TestCase):
    class _Rpc:
        def __init__(self, fail=(), raw_fail=False):
            self.calls, self.fail, self.raw_fail = [], set(fail), raw_fail

        def call(self, method, params):
            self.calls.append(method)
            if method in self.fail or (self.raw_fail and method == 'estimaterawfee'):
                raise RuntimeError('transport')
            if method == 'getnetworkinfo':
                return ACTUAL['getnetworkinfo']
            if method == 'getmempoolinfo':
                return ACTUAL['getmempoolinfo']
            if method == 'estimatesmartfee':
                return ACTUAL['estimatesmartfee_%d_conservative' % params[0]]
            if method == 'estimaterawfee':
                return ACTUAL['estimaterawfee_6']
            raise AssertionError('unexpected ' + method)

    def test_reads_only_and_quotes_the_floor(self):
        from wam_regtest.infrastructure.fee_rpc import READ_ONLY_METHODS, read_policy_inputs
        rpc = self._Rpc()
        quote = fp.quote(read_policy_inputs(rpc, 'regtest'))
        self.assertEqual(quote.rate_atoms_per_kvb, 1000)
        self.assertTrue(set(rpc.calls) <= READ_ONLY_METHODS)
        self.assertNotIn('sendrawtransaction', rpc.calls)

    def test_transport_failure_fails_closed_but_raw_diagnostic_failure_only_weakens(self):
        from wam_regtest.infrastructure.fee_rpc import read_policy_inputs
        with self.assertRaisesRegex(fp.FeePolicyError, 'FEE_POLICY_UNVERIFIED'):
            read_policy_inputs(self._Rpc(fail={'getmempoolinfo'}), 'regtest')
        inputs = read_policy_inputs(self._Rpc(raw_fail=True), 'regtest')
        self.assertEqual(dict(inputs.raw)[6], ())


class ExactSize(unittest.TestCase):
    def test_taproot_keypath_vsize_matches_the_weight_formula(self):
        from wam_regtest.infrastructure.tx_size import taproot_keypath_vsize
        from wam_sp.psbt import Tx
        out = (1000, b'\x51\x20' + bytes(32))
        # 65-byte SIGHASH_ALL signatures (every WSP silent payment), Codex PEER-098.
        for inputs, outputs, expected in ((1, 2, 155), (3, 1, 227), (128, 2, 7489), (1, 1, 112)):
            tx = Tx(tuple(('ab' * 32, i) for i in range(inputs)), (out,) * outputs)
            weight = 4 * (10 + 41 * inputs + 43 * outputs) + 2 + 67 * inputs
            with self.subTest(inputs=inputs, outputs=outputs):
                self.assertEqual(taproot_keypath_vsize(tx, (65,) * inputs), expected)
                self.assertEqual(expected, (weight + 3) // 4)
        tx = Tx((('ab' * 32, 0),), (out, out))
        self.assertEqual(taproot_keypath_vsize(tx, (64,)), 154)   # SIGHASH_DEFAULT
        with self.assertRaises(ValueError):
            taproot_keypath_vsize(tx, (66,))

    def test_signature_size_follows_wsps_signer_rule(self):
        from types import SimpleNamespace
        from wam_regtest.infrastructure.tx_size import signature_sizes
        tx = SimpleNamespace(inputs=(0, 1))
        sp = SimpleNamespace(tx=tx, output_extra=({b'\x09': b'x'},), input_extra=({}, {}))
        self.assertEqual(signature_sizes(sp), (65, 65))     # silent payment -> SIGHASH_ALL
        plain = SimpleNamespace(tx=tx, output_extra=({},), input_extra=({}, {}))
        self.assertEqual(signature_sizes(plain), (64, 64))  # SIGHASH_DEFAULT
        explicit = SimpleNamespace(tx=tx, output_extra=({},),
                                   input_extra=({b'\x03': (1).to_bytes(4, 'little')},
                                                {b'\x03': (0).to_bytes(4, 'little')}))
        self.assertEqual(signature_sizes(explicit), (65, 64))


if __name__ == '__main__':
    unittest.main()


class CodexPeer099Regressions(unittest.TestCase):
    """Reproductions from Codex PEER-099, each now a typed refusal or exact."""

    def test_conversion_is_exact_and_independent_of_the_decimal_context(self):
        import decimal
        cases = ((Decimal('1.0000000000000000000000000001'), 'FEE_POLICY_RATE_PRECISION'),  # fractional atoms
                 (Decimal('0.000010000000000000000000000000000001'), 'FEE_POLICY_RATE_PRECISION'),
                 (Decimal('-1E-999999999'), 'FEE_POLICY_RATE_RANGE'),
                 (Decimal('sNaN'), 'FEE_POLICY_RATE_PRECISION'),
                 (Decimal('Infinity'), 'FEE_POLICY_RATE_PRECISION'),
                 (Decimal('1E+999999999'), 'FEE_POLICY_RATE_RANGE'),
                 (Decimal('1.00000001'), 'FEE_POLICY_RATE_RANGE'),
                 (-1, 'FEE_POLICY_RATE_RANGE'), (2, 'FEE_POLICY_RATE_RANGE'))
        with decimal.localcontext() as context:
            context.prec = 3
            context.traps[decimal.Inexact] = True
            self.assertEqual(fp.coin_rate_to_atoms_per_kvb(Decimal('0.00001001')), 1001)
            self.assertEqual(fp.coin_rate_to_atoms_per_kvb(Decimal('0.123456780')), 12345678)
            for value, code in cases:
                with self.subTest(value=value):
                    with self.assertRaisesRegex(fp.FeePolicyError, code):
                        fp.coin_rate_to_atoms_per_kvb(value)
        for zero in (Decimal('0E-8'), Decimal('-0'), Decimal('0E-999999999'), 0):
            self.assertEqual(fp.coin_rate_to_atoms_per_kvb(zero), 0)
        self.assertEqual(fp.coin_rate_to_atoms_per_kvb(Decimal('1E-8')), 1)
        self.assertEqual(fp.coin_rate_to_atoms_per_kvb(1), 100_000_000)

    def test_digest_includes_the_raw_evidence_that_decides_the_quote(self):
        usable, weak = simulated_inputs(short_samples='500'), simulated_inputs(short_samples='0')
        self.assertEqual(fp.quote(usable).rate_atoms_per_kvb, 5000)
        self.assertEqual(fp.quote(weak).rate_atoms_per_kvb, 1000)
        self.assertNotEqual(usable.digest(), weak.digest())
        # A changed estimate alone does not invalidate an approved quote.
        approved = fp.quote(simulated_inputs(raw_errors=True))
        self.assertTrue(fp.quote_still_valid(approved, simulated_inputs(
            smart_rates=('0.00009000', '0.00007000', '0.00004000'), raw_errors=True)))

    def test_smart_blocks_are_required_and_bounded(self):
        for blocks in (None, -1, 1009, True, '2', Decimal(2)):
            smart = {t: {'feerate': Decimal(r), 'blocks': t} for t, r in
                     zip(fp.ESTIMATE_TARGETS, ('0.00008000', '0.00005000', '0.00003000'))}
            if blocks is None:
                smart[6].pop('blocks')
            else:
                smart[6]['blocks'] = blocks
            with self.subTest(blocks=blocks):
                with self.assertRaisesRegex(fp.FeePolicyError, 'FEE_POLICY_UNVERIFIED'):
                    fp.parse_policy_inputs('regtest', {'version': 113, 'relayfee': Decimal('0.00001')},
                                           {'loaded': True, 'mempoolminfee': Decimal('0.00001'),
                                            'minrelaytxfee': Decimal('0.00001')}, smart, {6: None})

    def test_malformed_raw_samples_only_weaken_never_count(self):
        for total in (Decimal('Infinity'), Decimal('NaN'), Decimal('sNaN'), Decimal('-1'),
                      Decimal('1E+13'), 'many', True, None):
            smart = {t: {'feerate': Decimal(r), 'blocks': t} for t, r in
                     zip(fp.ESTIMATE_TARGETS, ('0.00008000', '0.00005000', '0.00003000'))}
            raw = {6: {'short': {'feerate': Decimal('0.00005000'), 'pass': {'totalconfirmed': total}}}}
            with self.subTest(total=total):
                inputs = fp.parse_policy_inputs(
                    'regtest', {'version': 113, 'relayfee': Decimal('0.00001')},
                    {'loaded': True, 'mempoolminfee': Decimal('0.00001'),
                     'minrelaytxfee': Decimal('0.00001')}, smart, raw)
                classification, reasons = fp.classify_estimator(inputs)
                self.assertEqual(classification, fp.UNVALIDATED)
                self.assertIn('RAW_EVIDENCE_MALFORMED', reasons)
                self.assertEqual(fp.quote(inputs).source, fp.SOURCE_FLOOR)


class SupportedTransportBoundary(unittest.TestCase):
    """The fee reads pass the REAL validation boundaries, and nothing more."""

    def test_cli_rpc_admits_exactly_the_fee_reads_with_strict_params(self):
        from wam_regtest.cli_rpc import CliRpcError, validate
        for args in (['getmempoolinfo'], ['getnetworkinfo'],
                     ['estimatesmartfee', '6', 'conservative'], ['estimatesmartfee', '1008', 'economical'],
                     ['estimaterawfee', '1'], ['estimaterawfee', '25']):
            with self.subTest(args=args):
                self.assertEqual(validate(args)[0], args[0])
        for args in (['getmempoolinfo', 'x'], ['estimatesmartfee', '0', 'conservative'],
                     ['estimatesmartfee', '1009', 'conservative'], ['estimatesmartfee', '6'],
                     ['estimatesmartfee', '6', 'unset'], ['estimatesmartfee', '06', 'economical'],
                     ['estimaterawfee', '6', '0.95'], ['estimaterawfee', '-1'],
                     ['getmempoolinfo', '-rpcwallet=x'], ['settxfee', '0.001'], ['sendtoaddress', 'a', '1']):
            with self.subTest(args=args):
                with self.assertRaises(CliRpcError):
                    validate(args)

    def test_cli_rpc_decodes_fee_rates_as_decimal(self):
        from wam_regtest.cli_rpc import CliRpcError, decode
        text = b'{"loaded":true,"mempoolminfee":0.00001000,"minrelaytxfee":0.00001000}'
        value = decode(text, 'getmempoolinfo', [])
        self.assertIs(type(value['mempoolminfee']), Decimal)
        self.assertEqual(value['mempoolminfee'], Decimal('0.00001000'))
        smart = decode(b'{"feerate":0.00020064,"blocks":2}', 'estimatesmartfee', ['2', 'conservative'])
        self.assertEqual(fp.coin_rate_to_atoms_per_kvb(smart['feerate']), 20064)
        info = decode(b'{"version":113,"relayfee":0.00001000}', 'getnetworkinfo', [])
        self.assertIs(type(info['relayfee']), Decimal)
        with self.assertRaises(CliRpcError):
            decode(b'[1]', 'estimaterawfee', ['6'])
        with self.assertRaises(CliRpcError):
            decode(b'{"feerate":NaN}', 'estimatesmartfee', ['6', 'conservative'])

    def test_wallet_core_cli_validates_then_attests_then_reads(self):
        from wam_regtest.wallet_session import WalletCoreCli, WalletSessionError
        events = []
        cli = WalletCoreCli.__new__(WalletCoreCli)
        cli.attest = lambda: events.append('attest')
        cli._call = lambda method, args: events.append((method, args)) or {'ok': True}
        self.assertEqual(cli.call('estimatesmartfee', [6, 'conservative']), {'ok': True})
        self.assertEqual(events, ['attest', ('estimatesmartfee', ['6', 'conservative'])])
        for method, params in (('estimatesmartfee', [0, 'conservative']), ('estimatesmartfee', ['6', 'conservative']),
                               ('estimatesmartfee', [6]), ('estimaterawfee', [6, 0.95]),
                               ('getmempoolinfo', None), ('getnetworkinfo', ['x']), ('estimaterawfee', [True])):
            events.clear()
            with self.subTest(method=method, params=params):
                with self.assertRaisesRegex(WalletSessionError, 'WALLET_RPC_PARAMS_DENIED'):
                    cli.call(method, params)
                self.assertEqual(events, [])  # refused before attestation or any read
        cli._call = lambda method, args: [1]
        with self.assertRaisesRegex(WalletSessionError, 'WALLET_FEE_POLICY_REPLY_DENIED'):
            cli.call('getmempoolinfo', [])

    def test_adapter_works_through_the_wallet_core_cli_shape(self):
        from wam_regtest.infrastructure.fee_rpc import read_policy_inputs
        from wam_regtest.wallet_session import WalletCoreCli
        cli = WalletCoreCli.__new__(WalletCoreCli)
        cli.attest = lambda: None
        replies = {'getnetworkinfo': ACTUAL['getnetworkinfo'], 'getmempoolinfo': ACTUAL['getmempoolinfo'],
                   'estimaterawfee': ACTUAL['estimaterawfee_6']}
        cli._call = lambda method, args: (replies[method] if method in replies
                                          else ACTUAL['estimatesmartfee_%s_conservative' % args[0]])
        self.assertEqual(fp.quote(read_policy_inputs(cli, 'regtest')).rate_atoms_per_kvb, 1000)
