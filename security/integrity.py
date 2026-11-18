from __future__ import annotations

import hashlib
import hmac


def header_mac(key: bytes, authenticated_header: bytes) -> bytes:
    return hmac.new(key, authenticated_header, hashlib.sha256).digest()


def verify_header_mac(key: bytes, authenticated_header: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(header_mac(key, authenticated_header), tag)
