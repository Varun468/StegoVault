from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from security.validation import MAX_PAYLOAD_BYTES, sanitize_filename, validate_payload_size

PAYLOAD_HEADER = struct.Struct(">4sBBH")
PAYLOAD_MAGIC = b"SVPD"
PAYLOAD_VERSION = 1
MAX_FILENAME_BYTES = 720


class PayloadKind(IntEnum):
    TEXT = 1
    FILE = 2
    IMAGE = 3


@dataclass(frozen=True)
class Payload:
    kind: PayloadKind
    data: bytes
    filename: str | None = None


def pack_payload(kind: PayloadKind, data: bytes, filename: str | None = None) -> bytes:
    validate_payload_size(len(data))
    if kind == PayloadKind.TEXT and filename is not None:
        raise ValueError("Text payloads cannot have a filename.")
    if kind in {PayloadKind.FILE, PayloadKind.IMAGE}:
        if not filename:
            raise ValueError("A filename is required for file payloads.")
        filename_bytes = sanitize_filename(filename).encode("utf-8")
    else:
        filename_bytes = b""
    if len(filename_bytes) > MAX_FILENAME_BYTES:
        raise ValueError("Filename is too long.")
    return (
        PAYLOAD_HEADER.pack(PAYLOAD_MAGIC, PAYLOAD_VERSION, int(kind), len(filename_bytes))
        + filename_bytes
        + data
    )


def unpack_payload(raw: bytes) -> Payload:
    if len(raw) < PAYLOAD_HEADER.size:
        raise ValueError("Decrypted payload is malformed.")
    magic, version, kind_value, filename_length = PAYLOAD_HEADER.unpack_from(raw)
    if (
        magic != PAYLOAD_MAGIC
        or version != PAYLOAD_VERSION
        or filename_length > MAX_FILENAME_BYTES
        or len(raw) < PAYLOAD_HEADER.size + filename_length
    ):
        raise ValueError("Decrypted payload is malformed.")
    try:
        kind = PayloadKind(kind_value)
        filename_text = raw[PAYLOAD_HEADER.size : PAYLOAD_HEADER.size + filename_length].decode(
            "utf-8"
        )
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Decrypted payload is malformed.") from exc
    data = raw[PAYLOAD_HEADER.size + filename_length :]
    validate_payload_size(len(data), MAX_PAYLOAD_BYTES)
    if kind == PayloadKind.TEXT:
        if filename_text:
            raise ValueError("Decrypted payload is malformed.")
        data.decode("utf-8")
        filename = None
    else:
        if not filename_text or sanitize_filename(filename_text) != filename_text:
            raise ValueError("Decrypted payload is malformed.")
        filename = filename_text
    return Payload(kind=kind, data=data, filename=filename)
