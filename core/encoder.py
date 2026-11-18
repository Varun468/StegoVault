from __future__ import annotations

import io
import struct
from dataclasses import dataclass

import numpy as np
from PIL import Image, UnidentifiedImageError

from core.encryption import HEADER as ENCRYPTED_HEADER, MAGIC as ENCRYPTED_MAGIC
from core.encryption import VERSION as ENCRYPTED_VERSION, encrypt_bytes
from core.pixel_permutation import iter_permuted_positions
from core.payload_manager import PayloadKind, pack_payload
from security.integrity import header_mac
from security.password import derive_keys
from security.validation import MAX_IMAGE_PIXELS, MAX_PAYLOAD_BYTES, validate_payload_size

STEGO_MAGIC = b"SVHD"
STEGO_VERSION = 1
STEGO_HEADER = struct.Struct(">4sB16sQ")
STEGO_HEADER_BYTES = STEGO_HEADER.size + 32
STEGO_HEADER_BITS = STEGO_HEADER_BYTES * 8
MAX_ENCRYPTED_BYTES = MAX_PAYLOAD_BYTES + 1024
SUPPORTED_CARRIER_FORMATS = {"PNG", "BMP", "JPEG", "WEBP"}
PERMUTATION_BATCH_SIZE = 65_536


@dataclass(frozen=True)
class EmbeddingStats:
    width: int
    height: int
    capacity_bytes: int
    payload_bytes: int
    utilization: float


def _load_rgb(image_bytes: bytes, allowed_formats: set[str]) -> Image.Image:
    try:
        with Image.open(io.BytesIO(image_bytes)) as source:
            if source.format not in allowed_formats:
                raise ValueError("Unsupported image format.")
            if source.width * source.height > MAX_IMAGE_PIXELS:
                raise ValueError("Image exceeds the 40-megapixel processing limit.")
            source.load()
            return source.convert("RGB")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Image is malformed or cannot be decoded.") from exc


def embedding_capacity(image_bytes: bytes) -> EmbeddingStats:
    image = _load_rgb(image_bytes, SUPPORTED_CARRIER_FORMATS)
    available_bits = image.width * image.height * 3 - STEGO_HEADER_BITS
    capacity = max(0, available_bits // 8)
    return EmbeddingStats(
        width=image.width,
        height=image.height,
        capacity_bytes=capacity,
        payload_bytes=0,
        utilization=0.0,
    )


def embed_encrypted(
    carrier_image: bytes, encrypted_payload: bytes, password: str
) -> tuple[bytes, EmbeddingStats]:
    validate_payload_size(len(encrypted_payload), MAX_ENCRYPTED_BYTES)
    if len(encrypted_payload) < ENCRYPTED_HEADER.size + 16:
        raise ValueError("Encrypted payload is malformed.")
    try:
        magic, version, salt, _, ciphertext_length = ENCRYPTED_HEADER.unpack_from(
            encrypted_payload
        )
    except struct.error as exc:
        raise ValueError("Encrypted payload is malformed.") from exc
    if (
        magic != ENCRYPTED_MAGIC
        or version != ENCRYPTED_VERSION
        or ciphertext_length != len(encrypted_payload) - ENCRYPTED_HEADER.size
    ):
        raise ValueError("Encrypted payload is malformed.")

    image = _load_rgb(carrier_image, SUPPORTED_CARRIER_FORMATS)
    pixels = np.asarray(image, dtype=np.uint8).copy()
    flat = pixels.reshape(-1)
    available_positions = len(flat) - STEGO_HEADER_BITS
    payload_bits = len(encrypted_payload) * 8
    if payload_bits > available_positions:
        required = (payload_bits + STEGO_HEADER_BITS + 7) // 8
        raise ValueError(
            f"Image capacity is insufficient: payload requires {required:,} "
            f"RGB bytes of capacity; available capacity is "
            f"{max(0, available_positions // 8):,} bytes."
        )

    _, embedding_key, header_key = derive_keys(password, salt)
    authenticated_header = STEGO_HEADER.pack(
        STEGO_MAGIC, STEGO_VERSION, salt, len(encrypted_payload)
    )
    header = authenticated_header + header_mac(header_key, authenticated_header)
    header_bits = np.unpackbits(np.frombuffer(header, dtype=np.uint8))
    flat[:STEGO_HEADER_BITS] = (flat[:STEGO_HEADER_BITS] & 0xFE) | header_bits

    position_count = available_positions
    cursor = 0
    for positions in iter_permuted_positions(
        position_count, embedding_key, payload_bits, PERMUTATION_BATCH_SIZE
    ):
        stop = cursor + len(positions)
        first_byte = cursor // 8
        last_byte = (stop + 7) // 8
        bits = np.unpackbits(np.frombuffer(encrypted_payload[first_byte:last_byte], dtype=np.uint8))
        bits = bits[cursor % 8 : cursor % 8 + len(positions)]
        channel_positions = positions + STEGO_HEADER_BITS
        flat[channel_positions] = (flat[channel_positions] & 0xFE) | bits
        cursor = stop

    output = io.BytesIO()
    Image.fromarray(pixels, mode="RGB").save(output, format="PNG", optimize=False)
    stats = EmbeddingStats(
        width=image.width,
        height=image.height,
        capacity_bytes=position_count // 8,
        payload_bytes=len(encrypted_payload),
        utilization=payload_bits / position_count if position_count else 0.0,
    )
    return output.getvalue(), stats


def hide_data(
    carrier_image: bytes,
    data: bytes,
    password: str,
    kind: PayloadKind,
    filename: str | None = None,
) -> tuple[bytes, EmbeddingStats]:
    if kind == PayloadKind.IMAGE:
        try:
            with Image.open(io.BytesIO(data)) as hidden_image:
                if hidden_image.format not in {"PNG", "BMP"}:
                    raise ValueError("Hidden images must be PNG or BMP files.")
                if hidden_image.width * hidden_image.height > MAX_IMAGE_PIXELS:
                    raise ValueError("Hidden image exceeds the 40-megapixel limit.")
                hidden_image.verify()
        except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
            raise ValueError("The hidden image is malformed or cannot be decoded.") from exc
    packed = pack_payload(kind, data, filename)
    encrypted = encrypt_bytes(packed, password)
    return embed_encrypted(carrier_image, encrypted, password)
