import unittest

from core.encryption import DecryptionError, decrypt_bytes, encrypt_bytes


class EncryptionTests(unittest.TestCase):
    def test_round_trip_binary_payload(self) -> None:
        message = b"secret\x00data"
        self.assertEqual(decrypt_bytes(encrypt_bytes(message, "correct horse"), "correct horse"), message)

    def test_empty_plaintext_round_trip(self) -> None:
        self.assertEqual(decrypt_bytes(encrypt_bytes(b"", "passphrase"), "passphrase"), b"")

    def test_wrong_password_is_rejected(self) -> None:
        encrypted = encrypt_bytes(b"secret", "correct")
        with self.assertRaises(DecryptionError):
            decrypt_bytes(encrypted, "incorrect")

    def test_tampering_is_rejected(self) -> None:
        encrypted = bytearray(encrypt_bytes(b"secret", "correct"))
        encrypted[-1] ^= 1
        with self.assertRaises(DecryptionError):
            decrypt_bytes(bytes(encrypted), "correct")

    def test_each_encryption_uses_a_fresh_salt_and_nonce(self) -> None:
        first = encrypt_bytes(b"same", "password")
        second = encrypt_bytes(b"same", "password")
        self.assertNotEqual(first[:33], second[:33])
        self.assertNotEqual(first, second)

    def test_malformed_container_is_rejected(self) -> None:
        with self.assertRaises(DecryptionError):
            decrypt_bytes(b"not a container", "password")


if __name__ == "__main__":
    unittest.main()
