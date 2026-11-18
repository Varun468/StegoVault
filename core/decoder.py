from __future__ import annotations

import io
import struct

import numpy as np
from PIL import Image, UnidentifiedImageError

from core.encryption import HEADER as ENCRYPTED_HEADER
from core.encryption import decrypt_bytes
from core.encoder import (
    MAX_ENCRYPTED_BYTES,
    PERMUTATION_BATCH_SIZE,
    STEGO_HEADER,
    STEGO_HEADER_BITS,
    STEGO_MAGIC,
    STEGO_VERSION,
)
from core.pixel_permutation import iter_permuted_positions
from core.payload_manager import Payload, unpack_payload
from security.integrity import verify_header_mac
from security.password import derive_keys
from security.validation import MAX_IMAGE_PIXELS


def _load_stego_rgb(image_bytes: bytes) -> Image.Image:
    try:
        with Image.open(io.BytesIO(image_bytes)) as source:
            if source.format not in {"PNG", "BMP"}:
                raise ValueError("Stego image must be a lossless PNG or BMP.")
            if source.width * source.height > MAX_IMAGE_PIXELS:
                raise ValueError("Image exceeds the 40-megapixel processing limit.")
            source.load()
            return source.convert("RGB")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Image is malformed or cannot be decoded.") from exc


def extract_encrypted(stego_image: bytes, password: str) -> bytes:
    image = _load_stego_rgb(stego_image)
    flat = np.asarray(image, dtype=np.uint8).reshape(-1)
    if len(flat) < STEGO_HEADER_BITS:
        raise ValueError("No valid StegoVault payload was found.")
    header = np.packbits(flat[:STEGO_HEADER_BITS] & 1).tobytes()
    prefix_size = STEGO_HEADER.size
    try:
        magic, version, salt, payload_length = STEGO_HEADER.unpack_from(header)
    except struct.error as exc:
        raise ValueError("No valid StegoVault payload was found.") from exc
    authenticated_header = header[:prefix_size]
    tag = header[prefix_size : prefix_size + 32]
    if magic != STEGO_MAGIC or version != STEGO_VERSION:
        raise ValueError("No valid StegoVault payload was found.")

    _, embedding_key, header_key = derive_keys(password, salt)
    if not verify_header_mac(header_key, authenticated_header, tag):
        raise ValueError("Header authentication failed; check the image and password.")
    if (
        payload_length < ENCRYPTED_HEADER.size + 16
        or payload_length > MAX_ENCRYPTED_BYTES
        or payload_length * 8 > len(flat) - STEGO_HEADER_BITS
    ):
        raise ValueError("Authenticated payload length is outside image capacity.")

    payload = bytearray(payload_length)
    cursor = 0
    for positions in iter_permuted_positions(
        len(flat) - STEGO_HEADER_BITS,
        embedding_key,
        payload_length * 8,
        PERMUTATION_BATCH_SIZE,
    ):
        bits = flat[positions + STEGO_HEADER_BITS] & 1
        start = cursor // 8
        packed = np.packbits(bits).tobytes()
        payload[start : start + len(packed)] = packed
        cursor += len(positions)
    encrypted = bytes(payload)
    try:
        embedded_magic, embedded_version, embedded_salt, _, embedded_length = (
            ENCRYPTED_HEADER.unpack_from(encrypted)
        )
    except struct.error as exc:
        raise ValueError("Encrypted payload is malformed.") from exc
    if (
        embedded_magic != b"SVLT"
        or embedded_version != 1
        or embedded_salt != salt
        or embedded_length != len(encrypted) - ENCRYPTED_HEADER.size
    ):
        raise ValueError("Encrypted payload is malformed.")
    return encrypted


def reveal_data(stego_image: bytes, password: str) -> Payload:
    encrypted = extract_encrypted(stego_image, password)
    return unpack_payload(decrypt_bytes(encrypted, password))
