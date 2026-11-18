from __future__ import annotations

import secrets
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from security.password import SALT_LENGTH, derive_keys, new_salt
from security.validation import validate_payload_size, validate_password

MAGIC = b"SVLT"
VERSION = 1
NONCE_LENGTH = 12
HEADER = struct.Struct(">4sB16s12sQ")
AAD_PREFIX = b"StegoVault encrypted payload v1"
MAX_CONTAINER_BYTES = 32 * 1024 * 1024 + 1024


class DecryptionError(ValueError):
    """Raised when an encrypted container is invalid or cannot be authenticated."""


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    validate_password(password)
    validate_payload_size(len(plaintext), MAX_CONTAINER_BYTES - HEADER.size - 16)
    salt = new_salt()
    encryption_key, _, _ = derive_keys(password, salt)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    aad = AAD_PREFIX + bytes([VERSION]) + salt
    ciphertext = AESGCM(encryption_key).encrypt(nonce, plaintext, aad)
    header = HEADER.pack(MAGIC, VERSION, salt, nonce, len(ciphertext))
    return header + ciphertext


def decrypt_bytes(container: bytes, password: str) -> bytes:
    validate_password(password)
    if len(container) < HEADER.size + 16 or len(container) > MAX_CONTAINER_BYTES:
        raise DecryptionError("Encrypted payload is invalid or authentication failed.")
    try:
        magic, version, salt, nonce, ciphertext_length = HEADER.unpack_from(container)
    except struct.error as exc:
        raise DecryptionError(
            "Encrypted payload is invalid or authentication failed."
        ) from exc
    ciphertext = container[HEADER.size:]
    if (
        magic != MAGIC
        or version != VERSION
        or len(salt) != SALT_LENGTH
        or ciphertext_length != len(ciphertext)
    ):
        raise DecryptionError("Encrypted payload is invalid or authentication failed.")

    encryption_key, _, _ = derive_keys(password, salt)
    aad = AAD_PREFIX + bytes([VERSION]) + salt
    try:
        return AESGCM(encryption_key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "Encrypted payload is invalid or authentication failed."
        ) from exc
