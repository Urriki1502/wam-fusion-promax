"""Create-only encrypted payment evidence (format v2; v1 read-only legacy).

Directory name, ``<token>-<stage>.enc`` filenames, sealed JSON, seal purpose
and create-only publication are the historical Q06 format. Callers decide
when to write or read and own every fault latch. A second publish of the
same name still fails in custody storage; this module does not replace or
retry it.

Format v2 adds ``fee_basis`` as an evidence-only record of how the fee was
determined (``quote``, ``explicit``, or ``legacy-unrecorded``). The fee basis
is provenance only and NEVER affects signing authority, broadcast decisions,
UTXO locking, or fund release.

Reader accepts version 1 and 2 ONLY (`Q06_PAYMENT_EVIDENCE_INVALID` otherwise):
- v1 records are NEVER modified, rewritten, re-sealed, renamed, or migrated;
  the store stays strictly create-only. Reading a v1 record returns its body
  with an in-memory annotation ``fee_basis = {"kind": "legacy-unrecorded"}``.
- A legacy v1 intent's later stages (``uncertain`` / ``broadcast``) are new
  create-only files and are written as version 2 with ``fee_basis`` kind
  ``legacy-unrecorded``, never ``explicit``.
- v2 records are strictly validated against recorded values only (never reading
  or comparing against any current network floor).
"""
import json
import os
import re

from wam_regtest import custody


DIRECTORY_NAME = 'q06-payment-evidence'
SEAL_PURPOSE = b'recovery'
EVIDENCE_NETWORK = 'regtest'
MAX_RATE_ATOMS_PER_KVB = 100_000_000
_V1_KEYS = frozenset((
    'version', 'owner_binding', 'account_id', 'commitment', 'token', 'stage',
    'recipient', 'atoms', 'fee', 'signed_psbt', 'txid',
))
_V2_KEYS = _V1_KEYS | frozenset(('fee_basis',))
_FEE_BASIS_KINDS = frozenset(('quote', 'explicit', 'legacy-unrecorded'))
_QUOTE_KEYS = frozenset((
    'network', 'rate_atoms_per_kvb', 'floor_atoms_per_kvb', 'source',
    'estimator', 'reasons', 'inputs_digest',
))


def _is_fee_quote(value):
    cls = type(value)
    return cls.__name__ == 'FeeQuote' and cls.__module__ == 'wam_regtest.domain.fee_policy'


def _psbt_vsize(psbt):
    try:
        raw = psbt.finalize()
        base = psbt.tx.serialize()
    except (ValueError, TypeError):
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID') from None
    weight = 3 * len(base) + len(raw)
    vsize = (weight + 3) // 4
    if vsize <= 0:
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    return vsize


def _fee_for_vsize(vsize, rate_atoms_per_kvb):
    return (vsize * rate_atoms_per_kvb + 999) // 1000


def _validate_quote(quote, psbt, fee_atoms):
    if type(quote) is not dict or set(quote.keys()) != _QUOTE_KEYS:
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    network = quote['network']
    floor = quote['floor_atoms_per_kvb']
    rate = quote['rate_atoms_per_kvb']
    source = quote['source']
    estimator = quote['estimator']
    reasons = quote['reasons']
    inputs_digest = quote['inputs_digest']
    if type(network) is not str or network != EVIDENCE_NETWORK:
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    if type(floor) is not int or floor < 1 or floor > MAX_RATE_ATOMS_PER_KVB:
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    if type(rate) is not int or rate < floor or rate > MAX_RATE_ATOMS_PER_KVB:
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    if type(source) is not str or not source:
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    if type(estimator) is not str or not estimator:
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    if type(inputs_digest) is not str or not inputs_digest:
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    if type(reasons) is not list or any(type(item) is not str for item in reasons):
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    vsize = _psbt_vsize(psbt)
    if type(fee_atoms) is not int or fee_atoms < _fee_for_vsize(vsize, rate):
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')


def _fee_basis_for_write(review, psbt, legacy_unrecorded):
    if type(legacy_unrecorded) is not bool:
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    fee_quote = getattr(review, 'fee_quote', None)
    if legacy_unrecorded:
        if fee_quote is not None:
            raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
        return {'kind': 'legacy-unrecorded'}
    if fee_quote is None:
        return {'kind': 'explicit'}
    if not _is_fee_quote(fee_quote):
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    if type(fee_quote.reasons) is not tuple or any(type(item) is not str for item in fee_quote.reasons):
        raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
    quote_dict = {
        'network': fee_quote.network,
        'rate_atoms_per_kvb': fee_quote.rate_atoms_per_kvb,
        'floor_atoms_per_kvb': fee_quote.floor_atoms_per_kvb,
        'source': fee_quote.source,
        'estimator': fee_quote.estimator,
        'reasons': list(fee_quote.reasons),
        'inputs_digest': fee_quote.inputs_digest,
    }
    _validate_quote(quote_dict, psbt, review.fee)
    return {'kind': 'quote', 'quote': quote_dict}


class PaymentEvidenceStore:
    """Seal and read one owner directory's payment-evidence files.

    ``directory`` is the owner profile directory. ``storage`` is the custody
    module (``create_directory`` and ``storage().publish`` / ``storage().read``).
    Omitted storage uses ``wam_regtest.custody``. The seal password is an
    argument of each call. This object does not keep it.
    """

    def __init__(self, directory, storage=None):
        self.directory = directory
        self._storage = custody if storage is None else storage

    def _folder(self):
        return self.directory / DIRECTORY_NAME

    def write(self, stage, *, signed, review, token, owner_binding, account_id,
              password, txid=None, legacy_unrecorded=False):
        from wam_sp.keystore import seal
        from wam_sp.psbt import PSBT
        psbt = PSBT.decode(signed)
        expected_txid = psbt.txid()
        if txid is not None and txid != expected_txid:
            raise ValueError
        fee_basis = _fee_basis_for_write(review, psbt, legacy_unrecorded)
        if password is None:
            raise ValueError('PASSPHRASE_LENGTH')
        directory = self._folder()
        if not directory.exists():
            self._storage.create_directory(directory)
        body = dict(version=2, owner_binding=owner_binding(),
                    account_id=account_id(),
                    commitment=review.commitment, token=token, stage=stage,
                    recipient=review.code, atoms=review.atoms, fee=review.fee,
                    signed_psbt=signed.hex(), txid=expected_txid,
                    fee_basis=fee_basis)
        encrypted = seal(json.dumps(body, sort_keys=True).encode(),
                         password, SEAL_PURPOSE)
        self._storage.storage().publish(directory, token+'-'+stage+'.enc', encrypted)

    def read(self, token, stage, *, owner_binding, account_id, password):
        from wam_sp.keystore import unseal
        from wam_sp.psbt import PSBT
        directory = self._folder()
        name = token + '-' + stage + '.enc'
        if not os.path.lexists(directory / name):
            return None
        if password is None:
            raise ValueError('PASSPHRASE_LENGTH')
        body = json.loads(unseal(self._storage.storage().read(directory, name),
                                 password, SEAL_PURPOSE))
        if type(body) is not dict:
            raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
        version = body.get('version')
        if type(version) is not int or version not in (1, 2):
            raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
        expected_keys = _V1_KEYS if version == 1 else _V2_KEYS
        if set(body.keys()) != expected_keys:
            raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
        if (body.get('owner_binding') != owner_binding()
                or body.get('account_id') != account_id()
                or body.get('token') != token
                or body.get('stage') != stage
                or type(body.get('recipient')) is not str or not body['recipient']
                or type(body.get('atoms')) is not int or body['atoms'] <= 0
                or type(body.get('fee')) is not int or body['fee'] <= 0
                or type(body.get('signed_psbt')) is not str
                or type(body.get('txid')) is not str
                or re.fullmatch('[0-9a-f]{64}', body['txid']) is None
                or type(body.get('commitment')) is not str
                or re.fullmatch('[0-9a-f]{64}', body['commitment']) is None):
            raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
        try:
            psbt = PSBT.decode(bytes.fromhex(body['signed_psbt']))
        except (ValueError, TypeError):
            raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID') from None
        if psbt.txid() != body['txid']:
            raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
        if version == 1:
            body['fee_basis'] = {'kind': 'legacy-unrecorded'}
            return body
        fee_basis = body['fee_basis']
        if type(fee_basis) is not dict:
            raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
        kind = fee_basis.get('kind')
        if type(kind) is not str or kind not in _FEE_BASIS_KINDS:
            raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
        if kind in ('explicit', 'legacy-unrecorded'):
            if set(fee_basis.keys()) != {'kind'}:
                raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
            return body
        if set(fee_basis.keys()) != {'kind', 'quote'}:
            raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
        quote = fee_basis['quote']
        _validate_quote(quote, psbt, body['fee'])
        quote['reasons'] = tuple(quote['reasons'])
        return body
