"""Exact virtual size of a WSP transaction before signing (FEE-1).

Signature length per input follows WSP's own signer (wam_sp psbt.py sign):
the input's PSBT_IN_SIGHASH_TYPE field (0x03) if present, otherwise
SIGHASH_ALL whenever any output carries silent-payment data (0x09), else
SIGHASH_DEFAULT. A BIP340 signature is 64 bytes with SIGHASH_DEFAULT and 65
with any explicit sighash byte (WSP appends 0x01 for SIGHASH_ALL). Every WSP
payment is a silent payment, so in practice each input carries 65 bytes
(PEER-098: the earlier 64-byte assumption under-quoted by up to one vB
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


def estimated_one_input_vsize():
    """vsize of the usual first guess: one input, recipient and change.

    Both outputs are P2TR and each input carries the 65-byte SIGHASH_ALL
    signature this pinned sender path finalizes. The real vsize is measured
    from the prepared PSBT; this value only chooses the first fee. A payment
    that drops change is smaller, and the monotone loop keeps the higher fee.
    """
    from wam_sp.psbt import Tx
    script = b'\x51\x20' + bytes(32)
    tx = Tx((('11' * 32, 0),), ((330, script), (330, script)))
    return taproot_keypath_vsize(tx, (EXPLICIT_SIGHASH_SIGNATURE_BYTES,))


def serialized_vsize(raw):
    """vsize of a consensus-serialized transaction, witness bytes included.

    base excludes the witness marker, flag and witness stack. weight =
    3 * base + len(raw), vsize = ceil(weight / 4). Fail closed on a shape
    this wallet does not produce.
    """
    from wam_sp.psbt import Reader
    if type(raw) is not bytes or not 10 <= len(raw) <= 1_000_000:
        raise ValueError('FEE_POLICY_VSIZE')
    reader = Reader(raw)
    reader.take(4)
    witness = raw[4:6] == b'\x00\x01'
    if witness:
        reader.take(2)
    n_in = reader.size(128)
    if n_in < 1:
        raise ValueError('FEE_POLICY_VSIZE')
    for _ in range(n_in):
        reader.take(36)
        reader.blob(10_000)
        reader.take(4)
    n_out = reader.size(256)
    if n_out < 1:
        raise ValueError('FEE_POLICY_VSIZE')
    for _ in range(n_out):
        reader.take(8)
        reader.blob(10_000)
    if not witness:
        reader.take(4)
        reader.finish()
        return len(raw)
    witness_start = reader.pos
    for _ in range(n_in):
        n_stack = reader.size(16)
        if n_stack < 1:
            raise ValueError('FEE_POLICY_VSIZE')
        for _ in range(n_stack):
            item = reader.blob(80)
            if len(item) not in (SIGHASH_DEFAULT_SIGNATURE_BYTES, EXPLICIT_SIGHASH_SIGNATURE_BYTES):
                raise ValueError('FEE_POLICY_VSIZE')
    witness_len = reader.pos - witness_start
    reader.take(4)
    reader.finish()
    base = len(raw) - 2 - witness_len
    if base <= 0:
        raise ValueError('FEE_POLICY_VSIZE')
    return (3 * base + len(raw) + 3) // 4
