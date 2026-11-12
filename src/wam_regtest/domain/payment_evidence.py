"""Create-only encrypted payment evidence.

Directory name, ``<token>-<stage>.enc`` filenames, sealed JSON, seal purpose
and create-only publication are the historical Q06 format. Callers decide
when to write or read and own every fault latch. A second publish of the
same name still fails in custody storage; this module does not replace or
retry it.
"""
import json
import os
import re

from wam_regtest import custody


DIRECTORY_NAME = 'q06-payment-evidence'
SEAL_PURPOSE = b'recovery'


class PaymentEvidenceStore:
    """Seal and read one owner directory's payment-evidence files.

    ``directory`` is the owner profile directory. ``password`` is the seal
    password. ``storage`` is the custody module (``create_directory`` and
    ``storage().publish`` / ``storage().read``). Omitted storage uses
    ``wam_regtest.custody``.
    """

    def __init__(self, directory, password, storage=None):
        self.directory = directory
        self.password = password
        self._storage = custody if storage is None else storage

    def _folder(self):
        return self.directory / DIRECTORY_NAME

    def write(self, stage, *, signed, review, token, owner_binding, account_id, txid=None):
        from wam_sp.keystore import seal
        from wam_sp.psbt import PSBT
        psbt = PSBT.decode(signed)
        expected_txid = psbt.txid()
        if txid is not None and txid != expected_txid:
            raise ValueError
        directory = self._folder()
        if not directory.exists():
            self._storage.create_directory(directory)
        body = dict(version=1, owner_binding=owner_binding(),
                    account_id=account_id(),
                    commitment=review.commitment, token=token, stage=stage,
                    recipient=review.code, atoms=review.atoms, fee=review.fee,
                    signed_psbt=signed.hex(), txid=expected_txid)
        encrypted = seal(json.dumps(body, sort_keys=True).encode(),
                         self.password, SEAL_PURPOSE)
        self._storage.storage().publish(directory, token+'-'+stage+'.enc', encrypted)

    def read(self, token, stage, *, owner_binding, account_id):
        from wam_sp.keystore import unseal
        from wam_sp.psbt import PSBT
        directory = self._folder()
        name = token + '-' + stage + '.enc'
        if not os.path.lexists(directory / name):
            return None
        body = json.loads(unseal(self._storage.storage().read(directory, name),
                                 self.password, SEAL_PURPOSE))
        if (type(body) is not dict or body.get('version') != 1
                or body.get('owner_binding') != owner_binding()
                or body.get('account_id') != account_id()
                or body.get('token') != token or body.get('stage') != stage
                or type(body.get('signed_psbt')) is not str
                or type(body.get('commitment')) is not str
                or re.fullmatch('[0-9a-f]{64}', body['commitment']) is None
                or PSBT.decode(bytes.fromhex(body['signed_psbt'])).txid() != body.get('txid')):
            raise ValueError('Q06_PAYMENT_EVIDENCE_INVALID')
        return body
