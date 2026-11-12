"""Exact virtual size of a WSP transaction before signing (FEE-1).

Signature length per input follows WSP's own signer (wam_sp psbt.py sign):
the input's PSBT_IN_SIGHASH_TYPE field (0x03) if present, otherwise
SIGHASH_ALL whenever any output carries silent-payment data (0x09), else
SIGHASH_DEFAULT. A BIP340 signature is 64 bytes with SIGHASH_DEFAULT and 65
with any explicit sighash byte (WSP appends 0x01 for SIGHASH_ALL). Every WSP
payment is a silent payment, so in practice each input carries 65 bytes
(Codex PEER-098: the earlier 64-byte assumption under-quoted by up to one vB
per four inputs). Every input is a P2TR key-path spend: witness =
[signature] only.
    weight = 3 * len(serialize(no witness)) + len(serialize(with witness))
    vsize  = ceil(weight / 4)
Read-only use of WSP's existing PSBT/Tx serialization; no WSP behaviour change.
"""
from __future__ import annotations

SIGHASH_DEFAULT_SIGNATURE_BYTES = 64
EXPLICIT_SIGHASH_SIGNATURE_BYTES = 65


def taproot_keypath_vsize(tx, signature_bytes):
    """vsize of `tx` once input i carries one signature of signature_bytes[i] bytes."""
    count = len(tx.inputs)
    if count <= 0 or len(signature_bytes) != count or any(
            size not in (SIGHASH_DEFAULT_SIGNATURE_BYTES, EXPLICIT_SIGHASH_SIGNATURE_BYTES)
            for size in signature_bytes):
        raise ValueError('FEE_POLICY_VSIZE')
    base = len(tx.serialize())
    total = len(tx.serialize(witness=[(bytes(size),) for size in signature_bytes]))
    weight = 3 * base + total
    return (weight + 3) // 4


def signature_sizes(psbt):
    """Per-input final signature length, decided exactly as WSP's signer decides."""
    silent_payment = any(b'\x09' in fields for fields in psbt.output_extra)
    sizes = []
    inputs = psbt.input_extra or ({},) * len(psbt.tx.inputs)
    for fields in inputs:
        if b'\x03' in fields:
            value = fields[b'\x03']
            if type(value) is not bytes or len(value) != 4:
                raise ValueError('FEE_POLICY_VSIZE')
            sighash = int.from_bytes(value, 'little')
        else:
            sighash = 1 if silent_payment else 0
        sizes.append(SIGHASH_DEFAULT_SIGNATURE_BYTES if sighash == 0
                     else EXPLICIT_SIGHASH_SIGNATURE_BYTES)
    return tuple(sizes)


def psbt_vsize(psbt_bytes):
    """vsize of a prepared (unsigned) WSP PSBT, as it will be once signed."""
    from wam_sp.psbt import PSBT
    psbt = PSBT.decode(psbt_bytes)
    return taproot_keypath_vsize(psbt.tx, signature_sizes(psbt))
