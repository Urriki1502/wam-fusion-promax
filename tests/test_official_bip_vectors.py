"""PM-076: pinned, hashed, DATA-ONLY official BIP352/374/375 conformance vectors.

Corpus: bitcoin/bips @ b34d9f7 (2026-11-10), copied verbatim under BSD-2-Clause
(see NOTICE.txt and SHA256SUMS in ``tests/vectors_official/``). No network use,
no WSP modifications, no product source changes.

Version-aware assessment recorded here (evidence: evidence/MAINNET-REF-STUDY-20261115/):

* BIP352  - pinned WSP (``wam_sp.core``) implements all 29 current official
  send-and-receive vectors. The pinned ``wsp-upstream/tests/vectors/bip352.json``
  carries 28 of 29; the missing case "Single recipient: taproot key-path spend
  with annex" is included in the official file below and passes on pinned WSP
  through the unchanged WSP harness (``wsp-upstream/tests/test_vectors.vector_check``,
  imported here so the semantics cannot drift or be weakened).

* BIP374  - official spec version at b34d9f7 is 0.3.1 (2026-10-26: adds scalar
  boundary test vectors). Pinned ``wam_sp.adapters.dleq`` documents BIP374
  v0.3.0 semantics but passes every current CSV vector including the 0.3.1
  additions: 14/14 generate rows (including the INVALID generation boundary
  cases a=0, a=N, a=N+1, B=INFINITY) and 17/17 verify rows (including
  e >= N and s >= N rejections and empty-message success).

* BIP375  - official corpus JSON version is 1.1.1 (spec 0.1.4, 2026-11-10);
  WSP's pinned corpus JSON is version 1.1 and its PSBT validation predates the
  current same-scan-key output ordering rule (bip-0375.mediawiki:238-242).
  Recorded known interop gap WSP-BIP375-ORD-01: the officially VALID fixture
  "can finalize: three sp outputs (same scan key) - output 0 uses label=1,
  outputs 1 and 2 uses label=2 (same spend key)" is rejected by pinned WSP's
  public validator with SP_OUTPUT_MISMATCH, because WSP assigns per-group
  counters (k) in recipient/output traversal order instead of the specified
  label-aware ordering. That is a PSBT-interoperability/spec-version drift, not
  a fund-safety defect. Do NOT modify WSP; any fix is a WSP upstream proposal.

Invocation note (verified in the study): the corpus is run through the public
validator ``wam_sp.adapters.psbt_document.Document.validate(strict_inputs=False)``.
The ``strict_inputs`` binding of BIP32-derivation pubkeys to prevout digests is
a WAM-signer-side policy, not a current BIP375 corpus requirement; the official
generator emits synthetic derivation entries that do not hash-bind to the
P2WPKH/P2PKH witness-utxo scripts, so strict binding would reject 17 otherwise
officially-valid fixtures for a reason outside BIP375 conformance. All 24
official INVALID fixtures are still rejected with ``strict_inputs=False``.

Run: PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:wsp-upstream/src:tests
     python -m unittest test_official_bip_vectors -v
"""

import base64
import csv
import hashlib
import json
import sys
import unittest
from pathlib import Path

# Install the native WSP authentication guard (src/wam_regtest/__init__.py)
# BEFORE the pinned WSP harness or any wam_sp module is imported. The harness
# (wsp-upstream/tests/test_vectors.py) imports wam_sp.core at module level;
# importing wam_sp first would leave an unauthenticated module in sys.modules
# and wam_regtest.wsp_import.install_native_wsp_guard would then refuse it
# (WSP_PREIMPORTED_RUNTIME_DENIED) when test_contracts runs after this file.
import wam_regtest  # noqa: F401

HERE = Path(__file__).resolve().parent
VECDIR = HERE / "vectors_official"
WSP_TESTS = HERE.parent / "wsp-upstream" / "tests"

# Reuse the pinned WSP BIP352 harness verbatim (import, not re-implementation)
# so output-set equality and receiving matches/tweaks semantics are identical.
sys.path.insert(0, str(WSP_TESTS))
from test_vectors import vector_check  # noqa: E402  (wsp-upstream/tests)

from wam_sp.adapters import dleq  # noqa: E402
from wam_sp.adapters.psbt_document import Document  # noqa: E402
from wam_sp.crypto import shared_point  # noqa: E402

BIP352_FILE = "bip352_send_and_receive_test_vectors.json"
BIP375_FILE = "bip375_test_vectors.json"
BIP374_GENERATE_FILE = "test_vectors_generate_proof.csv"
BIP374_VERIFY_FILE = "test_vectors_verify_proof.csv"
NOTICE_FILE = "NOTICE.txt"
SHA256SUMS_FILE = "SHA256SUMS"

# Corpus provenance (recorded, not re-fetched; data-only).
CORPUS_COMMIT = "b34d9f7"
CORPUS_DATE = "2026-11-10"

# Known interop gap: officially-valid BIP375 fixture rejected by pinned WSP.
WSP_BIP375_ORD_01_DESC = (
    "can finalize: three sp outputs (same scan key) - output 0 uses label=1, "
    "outputs 1 and 2 uses label=2 (same spend key)"
)
WSP_BIP375_ORD_01_ERROR = "SP_OUTPUT_MISMATCH"


def _assert_exact_sp_output_mismatch(test_case, invoke):
    """Assert invoke() raises ValueError exactly 'SP_OUTPUT_MISMATCH'.

    Exact equality only: prefixed/suffixed or otherwise decorated messages
    fail, and so does invoke() returning without raising (a future WSP that
    accepts the fixture).
    """
    with test_case.assertRaises(ValueError) as caught:
        invoke()
    test_case.assertEqual(str(caught.exception), 'SP_OUTPUT_MISMATCH')
    test_case.assertEqual(str(caught.exception), WSP_BIP375_ORD_01_ERROR)


def _load_json(name):
    return json.loads((VECDIR / name).read_text())


def _load_csv(name):
    with (VECDIR / name).open() as handle:
        return list(csv.DictReader(handle))


def _bip352_annex_case():
    """The one official case absent from WSP's pinned 28-vector corpus."""
    cases = [c for c in _load_json(BIP352_FILE)
             if c.get("comment") == "Single recipient: taproot key-path spend with annex"]
    assert len(cases) == 1, "official annex case missing or duplicated"
    return cases[0]


class TestCorpusIntegrity(unittest.TestCase):
    """Tamper guard: every listed file must match the pinned SHA256SUMS."""

    def test_sha256_against_pinned_manifest(self):
        entries = []
        for line in (VECDIR / SHA256SUMS_FILE).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            digest, name = line.split(None, 1)
            entries.append((name.strip(), digest))
        self.assertEqual(
            sorted(name for name, _ in entries),
            sorted([BIP352_FILE, BIP375_FILE, BIP374_GENERATE_FILE, BIP374_VERIFY_FILE]),
            "SHA256SUMS must cover exactly the four official data files",
        )
        for name, digest in entries:
            with (VECDIR / name).open("rb") as handle:
                actual = hashlib.sha256(handle.read()).hexdigest()
            self.assertEqual(actual, digest, f"tamper guard failed for {name}")

    def test_notice_records_verbatim_source(self):
        notice = (VECDIR / NOTICE_FILE).read_text()
        self.assertIn(CORPUS_COMMIT, notice)
        self.assertIn("BSD-2-Clause", notice)
        self.assertIn("copied verbatim", notice)


class TestBIP352Official(unittest.TestCase):
    """All 29 official BIP352 send-and-receive cases on pinned wam_sp.core.

    Semantics: imported unchanged from wsp-upstream/tests/test_vectors.py
    (output-set equality for sending; receiving addresses, input_pub_key_sum,
    tweak, shared_secret and output match/tweak/signature equality exactly as
    the WSP harness checks them).
    """

    ANNEX_COMMENT = "Single recipient: taproot key-path spend with annex"

    def test_corpus_is_the_full_29_case_official_set(self):
        cases = _load_json(BIP352_FILE)
        self.assertEqual(len(cases), 29)
        comments = [c.get("comment", "") for c in cases]
        self.assertEqual(len(set(comments)), len(comments), "duplicate official cases")
        self.assertIn(self.ANNEX_COMMENT, comments)

    def test_case_absent_from_pinned_wsp_corpus_passes(self):
        # 28 of these 29 cases are in wsp-upstream/tests/vectors/bip352.json;
        # the annex case is the one official addition. It must pass on pinned
        # WSP through the unchanged WSP harness.
        vector_check(self, _bip352_annex_case())

    def test_all_29_cases_through_wsp_harness(self):
        cases = _load_json(BIP352_FILE)
        for case in cases:
            with self.subTest(comment=case.get("comment", "")):
                vector_check(self, case)


class TestBIP374Official(unittest.TestCase):
    """Official BIP374 0.3.1 proof CSVs against pinned wam_sp.adapters.dleq.

    The pinned API supports the current corpus: prove(secret, B, auxiliary,
    message, generator) -> (C, proof) and verify(A, B, C, proof, message,
    generator), including empty messages and per-row generator points.
    """

    def test_generate_vectors(self):
        rows = _load_csv(BIP374_GENERATE_FILE)
        self.assertEqual(len(rows), 14)
        checked = 0
        for row in rows:
            with self.subTest(index=row["index"], comment=row["comment"]):
                generator = bytes.fromhex(row["point_G"])
                secret = bytes.fromhex(row["scalar_a"])
                expected = row["result_proof"]
                message = bytes.fromhex(row["message"]) if row["message"] else None
                if expected == "INVALID":
                    # Generation boundary failures (a=0, a=N, a=N+1, B=INFINITY).
                    with self.assertRaises(ValueError):
                        dleq.prove(secret, bytes.fromhex(row["point_B"]),
                                   bytes.fromhex(row["auxrand_r"]), message, generator)
                else:
                    B = bytes.fromhex(row["point_B"])
                    C, proof = dleq.prove(
                        secret, B,
                        bytes.fromhex(row["auxrand_r"]), message, generator,
                    )
                    self.assertEqual(proof.hex(), expected)
                    # Round-trip with the same pinned implementation: C must be
                    # the secret-scaled point a*B, and the produced proof must
                    # verify against A = a*generator.
                    self.assertEqual(C, shared_point(secret, B))
                    A = shared_point(secret, generator)
                    self.assertTrue(dleq.verify(A, B, C, proof, message, generator))
                checked += 1
        self.assertEqual(checked, 14)

    def test_verify_vectors(self):
        rows = _load_csv(BIP374_VERIFY_FILE)
        self.assertEqual(len(rows), 17)
        checked = 0
        for row in rows:
            with self.subTest(index=row["index"], comment=row["comment"]):
                generator = bytes.fromhex(row["point_G"])
                A = bytes.fromhex(row["point_A"])
                B = bytes.fromhex(row["point_B"])
                C = bytes.fromhex(row["point_C"])
                proof = bytes.fromhex(row["proof"])
                message = bytes.fromhex(row["message"]) if row["message"] else None
                expected = row["result_success"] == "TRUE"
                self.assertEqual(dleq.verify(A, B, C, proof, message, generator), expected)
                checked += 1
        self.assertEqual(checked, 17)


class TestBIP375Official(unittest.TestCase):
    """Official BIP375 1.1.1 PSBT corpus against pinned WSP's public validator.

    Public validator: wam_sp.adapters.psbt_document.Document (built on
    adapters/sp_psbt.py field/eligibility checks). Corpus is run with
    strict_inputs=False as verified in the study; see module docstring.
    """

    @classmethod
    def setUpClass(cls):
        cls.corpus = _load_json(BIP375_FILE)
        cls.valid = cls.corpus["valid"]
        cls.invalid = cls.corpus["invalid"]

    def _validate(self, item):
        doc = Document.decode(base64.b64decode(item["psbt"]))
        checks = item.get("checks")
        if checks:
            return doc.validate(checks=checks, strict_inputs=False)
        return doc.validate(strict_inputs=False)

    def test_corpus_counts(self):
        # Version pin: if the corpus file changes, the tamper guard fails
        # first; this additionally pins the semantic version actually assessed.
        self.assertEqual(self.corpus.get("version"), "1.1.1")
        self.assertEqual(len(self.valid), 20)
        self.assertEqual(len(self.invalid), 24)

    def test_valid_fixtures_accepted(self):
        # All officially valid fixtures except the recorded ordering gap
        # (WSP-BIP375-ORD-01) must validate without raising.
        accepted = 0
        for index, item in enumerate(self.valid):
            if item["description"] == WSP_BIP375_ORD_01_DESC:
                continue
            with self.subTest(index=index, description=item["description"]):
                self._validate(item)  # must not raise
            accepted += 1
        self.assertEqual(accepted, 19)

    def test_invalid_fixtures_rejected(self):
        # Every officially invalid fixture must be rejected (ValueError); the
        # official corpus does not pin specific error codes, so the rejection
        # outcome itself is the conformance check.
        rejected = 0
        for index, item in enumerate(self.invalid):
            with self.subTest(index=index, description=item["description"]):
                with self.assertRaises(ValueError):
                    self._validate(item)
            rejected += 1
        self.assertEqual(rejected, 24)

    def test_known_interop_gap_wsp_bip375_ord_01(self):
        # WSP-BIP375-ORD-01: an officially VALID fixture (current BIP375 label-
        # aware k ordering, bip-0375.mediawiki:238-242) is rejected by the
        # pinned WSP validator. Asserted explicitly as a recorded rejection so
        # the gap stays visible; if WSP's ordering is fixed upstream, this test
        # fails loudly and must be updated (the fixture would then belong to
        # test_valid_fixtures_accepted).
        _assert_exact_sp_output_mismatch(
            self,
            lambda: self._validate({"psbt": self._gap_psbt(), "checks": None}),
        )

    def test_exact_error_helper_rejects_affixed_messages(self):
        # The exact-match helper above must not let decorated messages pass:
        # an unanchored regex would accept e.g.
        # 'UNRELATED_SP_OUTPUT_MISMATCH_SUFFIX', assertEqual must not.
        for message in (
            "UNRELATED_SP_OUTPUT_MISMATCH_SUFFIX",
            "PREFIX_SP_OUTPUT_MISMATCH",
            "SP_OUTPUT_MISMATCH_SUFFIX",
            " SP_OUTPUT_MISMATCH",
            "SP_OUTPUT_MISMATCH ",
        ):
            with self.subTest(message=message):

                def _raise(message=message):
                    raise ValueError(message)

                with self.assertRaises(AssertionError):
                    _assert_exact_sp_output_mismatch(self, _raise)
        # The exact message passes, and accepting (not raising) fails.
        def _raise_exact():
            raise ValueError(WSP_BIP375_ORD_01_ERROR)

        _assert_exact_sp_output_mismatch(self, _raise_exact)
        with self.assertRaises(AssertionError):
            _assert_exact_sp_output_mismatch(self, lambda: None)

    def _gap_psbt(self):
        for item in self.valid:
            if item["description"] == WSP_BIP375_ORD_01_DESC:
                return item["psbt"]
        self.fail("ordering-gap fixture missing from corpus")


if __name__ == "__main__":
    unittest.main()
