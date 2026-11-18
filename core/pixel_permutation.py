from __future__ import annotations

from collections.abc import Iterator

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PERMUTATION_ROUNDS = 8
DEFAULT_BATCH_SIZE = 65_536


def _permutation_keys(key: bytes) -> list[bytes]:
    return [
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"StegoVault/DPLE/v1/pixel-permutation/round-{round_number}".encode(),
        ).derive(key)
        for round_number in range(PERMUTATION_ROUNDS)
    ]


def _feistel(values: np.ndarray, half_bits: int, round_keys: list[bytes]) -> np.ndarray:
    half_mask = (1 << half_bits) - 1
    left = values >> half_bits
    right = values & half_mask
    encryptors = [
        Cipher(algorithms.AES(round_key), modes.ECB()).encryptor()
        for round_key in round_keys
    ]
    for round_number, encryptor in enumerate(encryptors):
        blocks = np.zeros((len(right), 16), dtype=np.uint8)
        blocks[:, 0:8] = np.frombuffer(b"SVLT-PRP", dtype=np.uint8)
        blocks[:, 8] = round_number
        blocks[:, 12:16] = right.astype(">u4", copy=False).view(np.uint8).reshape(-1, 4)
        random_values = np.frombuffer(
            encryptor.update(blocks.tobytes()), dtype=">u4"
        ).reshape(-1, 4)[:, 0].astype(np.uint64)
        left, right = right, (left ^ random_values) & half_mask
    return (left << half_bits) | right


def iter_permuted_positions(
    position_count: int,
    key: bytes,
    item_count: int,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> Iterator[np.ndarray]:
    """Yield a prefix of a keyed AES-Feistel permutation over channel positions.

    The Feistel network only permutes indices. It is not used to encrypt user
    data. Cycle walking restricts its power-of-two domain to the exact carrier
    range without storing an image-sized permutation array.
    """
    if position_count < 1:
        raise ValueError("At least one carrier position is required.")
    if not 0 <= item_count <= position_count:
        raise ValueError("Requested permutation length exceeds available positions.")
    if batch_size < 1:
        raise ValueError("Batch size must be positive.")
    if item_count == 0:
        return

    half_bits = max(1, ((position_count - 1).bit_length() + 1) // 2)
    if half_bits > 32:
        raise ValueError("Image has too many carrier positions.")
    round_keys = _permutation_keys(key)
    for start in range(0, item_count, batch_size):
        stop = min(start + batch_size, item_count)
        values = np.arange(start, stop, dtype=np.uint64)
        pending = np.ones(len(values), dtype=bool)
        for _ in range(128):
            if not pending.any():
                break
            values[pending] = _feistel(values[pending], half_bits, round_keys)
            pending = values >= position_count
        if pending.any():
            raise RuntimeError("Pixel permutation cycle-walk limit exceeded.")
        yield values.astype(np.int64)
