from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LENGTH = 16
KEY_LENGTH = 32
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


def new_salt() -> bytes:
    return secrets.token_bytes(SALT_LENGTH)


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes, bytes]:
    """Derive independent encryption, embedding, and header-authentication keys."""
    if not isinstance(password, str) or not password:
        raise ValueError("A non-empty password is required.")
    if len(password.encode("utf-8")) > 1024:
        raise ValueError("Password exceeds the 1024-byte limit.")
    if len(salt) != SALT_LENGTH:
        raise ValueError("Invalid salt length.")

    root_key = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    ).derive(password.encode("utf-8"))

    def expand(info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=None,
            info=b"StegoVault/DPLE/v1/" + info,
        ).derive(root_key)

    return expand(b"encryption"), expand(b"embedding"), expand(b"header-auth")
