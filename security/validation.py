from __future__ import annotations

import re
from pathlib import PurePath

MAX_PASSWORD_BYTES = 1024
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
_INVALID_FILENAME_CHARACTERS = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')


def validate_password(password: str) -> None:
    if not isinstance(password, str) or not password:
        raise ValueError("A non-empty password is required.")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError("Password exceeds the 1024-byte limit.")


def validate_payload_size(size: int, maximum: int = MAX_PAYLOAD_BYTES) -> None:
    if size < 0:
        raise ValueError("Payload size cannot be negative.")
    if size > maximum:
        raise ValueError(f"Payload exceeds the {maximum // (1024 * 1024)} MiB limit.")


def sanitize_filename(filename: str) -> str:
    """Return a single safe filename component, never a path."""
    name = PurePath(filename.replace("\\", "/")).name
    name = _INVALID_FILENAME_CHARACTERS.sub("_", name).strip(" .")
    if not name or name in {".", ".."}:
        return "extracted_file"
    if name.split(".", maxsplit=1)[0].upper() in {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }:
        name = f"_{name}"
    return name[:180]
