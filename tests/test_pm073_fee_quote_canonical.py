"""PM-073: persisted fee quote compared in canonical JSON shape (D-FEE2-3).

The recovered quote reaches the runner through plain(), so its FeeQuote
reasons are a list. Persisted and signed evidence reasons are a tuple.
review_evidence() must compare equal to both canonical representations,
while the strict oracle in fee_regtest_recovery stays unchanged.
"""
import copy
from dataclasses import asdict
from hashlib import sha256
import json
import unittest

from wam_regtest.domain.fee_policy import FeeQuote
from wam_regtest.qualification.fee_regtest_recovery import fee_metadata_holds
from wam_regtest.qualification.fee_regtest_runner import plain, review_evidence
from wam_regtest.wallet_session import PaymentReview


def _quote():
    return FeeQuote(
        network="regtest",
        rate_atoms_per_kvb=2000,
        floor_atoms_per_kvb=1000,
        source="NETWORK_FLOOR_2X",
        estimator="UNAVAILABLE",
        reasons=("NO_FEERATE_WITHOUT_ERRORS",),
        inputs_digest="ab" * 32,
    )


def _review(quote):
    return PaymentReview(
        code="wamrtsp1disposable",
        atoms=100000,
        fee=310,
        change_atoms=899690,
        input_count=1,
        commitment="7" * 64,
        vsize=155,
        available_after=0,
        fee_quote=quote,
    )


class FeeQuoteCanonical(unittest.TestCase):
    def test_recovered_plain_quote_matches_review_evidence(self):
        quote = _quote()
        review = _review(quote)
        self.assertIsInstance(quote.reasons, tuple)
        recovered = plain(asdict(quote))
        self.assertIsInstance(recovered["reasons"], list)
        review_quote = review_evidence(review)["fee_quote"]
        # PM-071 in-memory/persisted quotes keep reasons as a tuple.
        self.assertIsInstance(review_quote["reasons"], tuple)
        # The same reasons compare equal in the plain()/JSON list shape
        # and in the persisted tuple shape, in both directions.
        self.assertEqual(review_quote, recovered)
        self.assertEqual(recovered, review_quote)
        self.assertEqual(review_quote, asdict(quote))
        self.assertEqual(asdict(quote), review_quote)
        self.assertTrue(review_quote["reasons"] == ["NO_FEERATE_WITHOUT_ERRORS"])
        self.assertTrue(review_quote["reasons"] == ("NO_FEERATE_WITHOUT_ERRORS",))
        self.assertTrue(fee_metadata_holds(recovered, review_quote))
        self.assertTrue(fee_metadata_holds(asdict(quote), review_quote))

    def test_any_single_field_difference_fails(self):
        review = _review(_quote())
        original = review_evidence(review)["fee_quote"]
        recovered = plain(asdict(_quote()))
        self.assertTrue(fee_metadata_holds(recovered, original))
        mutations = {
            "rate_atoms_per_kvb": 2001,
            "floor_atoms_per_kvb": 1001,
            "network": "signet",
            "source": "ESTIMATOR",
            "estimator": "USABLE",
            "reasons": ["SOME_TARGETS_UNAVAILABLE"],
            "inputs_digest": "cd" * 32,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(recovered)
                changed[field] = value
                self.assertFalse(fee_metadata_holds(changed, original))
        with self.subTest(field="reasons_tuple_form"):
            changed = copy.deepcopy(recovered)
            changed["reasons"] = ("SOME_TARGETS_UNAVAILABLE",)
            self.assertFalse(fee_metadata_holds(changed, original))

    def test_none_or_empty_persisted_quote_fails(self):
        original = review_evidence(_review(_quote()))["fee_quote"]
        self.assertFalse(fee_metadata_holds(None, original))
        self.assertFalse(fee_metadata_holds({}, original))

    def test_review_json_byte_identical_to_asdict_shape(self):
        review = _review(_quote())
        old_values = asdict(review)
        old_values.pop("code")
        old_json = json.dumps(old_values, sort_keys=True)
        new_json = json.dumps(review_evidence(review), sort_keys=True)
        self.assertEqual(new_json, json.dumps(plain(old_values), sort_keys=True))
        self.assertEqual(new_json, old_json)
        self.assertEqual(new_json.encode(), old_json.encode())
        self.assertEqual(
            sha256(new_json.encode()).hexdigest(),
            sha256(old_json.encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()
