import io
import unittest

import numpy as np
from PIL import Image

from core.decoder import extract_encrypted, reveal_data
from core.encryption import HEADER as ENCRYPTED_HEADER
from core.encoder import STEGO_HEADER_BITS, hide_data
from core.payload_manager import PayloadKind
from security.password import derive_keys


def make_carrier(size: tuple[int, int] = (320, 320)) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", size, (112, 145, 180)).save(output, format="PNG")
    return output.getvalue()


class SteganographyTests(unittest.TestCase):
    def test_unicode_text_round_trip(self) -> None:
        message = "秘密 🌍 — Καλημέρα — नमस्ते"
        image, stats = hide_data(
            make_carrier(), message.encode("utf-8"), "passphrase", PayloadKind.TEXT
        )
        self.assertEqual(reveal_data(image, "passphrase").data.decode("utf-8"), message)
        self.assertGreater(stats.utilization, 0)

    def test_empty_text_round_trip(self) -> None:
        image, _ = hide_data(make_carrier(), b"", "passphrase", PayloadKind.TEXT)
        self.assertEqual(reveal_data(image, "passphrase").data, b"")

    def test_special_characters_round_trip(self) -> None:
        message = "line 1\nline 2\t<>&\"'\\\x00"
        image, _ = hide_data(
            make_carrier(), message.encode(), "passphrase", PayloadKind.TEXT
        )
        self.assertEqual(reveal_data(image, "passphrase").data, message.encode())

    def test_file_round_trip_is_byte_identical(self) -> None:
        original = bytes(range(256)) * 100
        image, _ = hide_data(
            make_carrier(), original, "passphrase", PayloadKind.FILE, "report.pdf"
        )
        payload = reveal_data(image, "passphrase")
        self.assertEqual(payload.filename, "report.pdf")
        self.assertEqual(payload.data, original)

    def test_image_payload_round_trip(self) -> None:
        original = make_carrier((32, 24))
        image, _ = hide_data(
            make_carrier(), original, "passphrase", PayloadKind.IMAGE, "hidden.png"
        )
        payload = reveal_data(image, "passphrase")
        self.assertEqual(payload.filename, "hidden.png")
        self.assertEqual(payload.data, original)

    def test_image_payload_rejects_non_png_bmp(self) -> None:
        output = io.BytesIO()
        Image.new("RGB", (16, 16)).save(output, format="JPEG")
        with self.assertRaisesRegex(ValueError, "PNG or BMP"):
            hide_data(
                make_carrier(),
                output.getvalue(),
                "passphrase",
                PayloadKind.IMAGE,
                "hidden.jpg",
            )

    def test_wrong_password_is_rejected(self) -> None:
        image, _ = hide_data(
            make_carrier(), b"secret", "correct", PayloadKind.TEXT
        )
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            reveal_data(image, "incorrect")

    def test_tampered_header_is_rejected(self) -> None:
        image, _ = hide_data(
            make_carrier(), b"secret", "correct", PayloadKind.TEXT
        )
        with Image.open(io.BytesIO(image)) as decoded:
            pixels = np.asarray(decoded.convert("RGB")).copy()
        pixels.reshape(-1)[0] ^= 1
        changed = io.BytesIO()
        Image.fromarray(pixels).save(changed, format="PNG")
        with self.assertRaises(ValueError):
            reveal_data(changed.getvalue(), "correct")

    def test_tampered_payload_is_rejected(self) -> None:
        image, _ = hide_data(
            make_carrier(), b"secret", "correct", PayloadKind.TEXT
        )
        encrypted = extract_encrypted(image, "correct")
        _, embedding_key, _ = derive_keys("correct", encrypted[5:21])
        from core.pixel_permutation import iter_permuted_positions

        payload_position = next(
            iter_permuted_positions(
                320 * 320 * 3 - STEGO_HEADER_BITS,
                embedding_key,
                (ENCRYPTED_HEADER.size + 1) * 8,
            )
        )[ENCRYPTED_HEADER.size * 8]
        with Image.open(io.BytesIO(image)) as decoded:
            pixels = np.asarray(decoded.convert("RGB")).copy()
        pixels.reshape(-1)[STEGO_HEADER_BITS + payload_position] ^= 1
        changed = io.BytesIO()
        Image.fromarray(pixels).save(changed, format="PNG")
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            reveal_data(changed.getvalue(), "correct")

    def test_insufficient_capacity_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "capacity is insufficient"):
            hide_data(make_carrier((10, 10)), b"payload", "passphrase", PayloadKind.TEXT)

    def test_invalid_image_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "malformed"):
            reveal_data(b"not an image", "passphrase")

    def test_multiple_encryption_operations_round_trip_independently(self) -> None:
        images = [
            hide_data(
                make_carrier(), f"item {index}".encode(), "password", PayloadKind.TEXT
            )[0]
            for index in range(3)
        ]
        self.assertEqual(
            [reveal_data(image, "password").data for image in images],
            [b"item 0", b"item 1", b"item 2"],
        )

    def test_large_file_round_trip(self) -> None:
        original = bytes(range(251)) * 3000
        image, _ = hide_data(
            make_carrier((2500, 1500)),
            original,
            "large-file-password",
            PayloadKind.FILE,
            "large.zip",
        )
        self.assertEqual(reveal_data(image, "large-file-password").data, original)


if __name__ == "__main__":
    unittest.main()
