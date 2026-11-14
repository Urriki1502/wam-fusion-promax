"""Core v0.1.13-shaped admission replies for tests with real pinned-WSP PSBTs."""
from decimal import Decimal
from hashlib import sha256
from wam_regtest.infrastructure.tx_size import serialized_vsize
from wam_sp.psbt import PSBT


def accepted_reply(signed, fee=1000):
    psbt = PSBT.decode(signed)
    raw = psbt.finalize()
    vsize = serialized_vsize(raw)
    wtxid = sha256(sha256(raw).digest()).digest()[::-1].hex()
    return [{'allowed': True, 'txid': psbt.txid(), 'wtxid': wtxid, 'vsize': vsize,
             'fees': {'base': Decimal(fee).scaleb(-8),
                      'effective-feerate': Decimal(fee * 1000 // vsize).scaleb(-8),
                      'effective-includes': [wtxid]}}]
