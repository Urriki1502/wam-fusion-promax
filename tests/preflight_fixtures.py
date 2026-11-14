"""Strict synthetic admission replies for tests with real pinned-WSP PSBTs."""
from decimal import Decimal
from wam_regtest.infrastructure.tx_size import serialized_vsize
from wam_sp.psbt import PSBT


def accepted_reply(signed, fee=1000):
    psbt = PSBT.decode(signed)
    vsize = serialized_vsize(psbt.finalize())
    return [{'allowed': True, 'txid': psbt.txid(), 'vsize': vsize,
             'fees': {'base': Decimal(fee).scaleb(-8),
                      'effective-feerate': Decimal(fee * 1000 // vsize).scaleb(-8),
                      'effective-includes': [psbt.txid()]}}]
