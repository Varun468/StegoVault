import unittest

from security.integrity import header_mac, verify_header_mac


class IntegrityTests(unittest.TestCase):
    def test_header_authentication_detects_changes(self) -> None:
        key = b"k" * 32
        header = b"authenticated header"
        tag = header_mac(key, header)

        self.assertTrue(verify_header_mac(key, header, tag))
        self.assertFalse(verify_header_mac(key, header + b"!", tag))
        self.assertFalse(verify_header_mac(b"x" * 32, header, tag))


if __name__ == "__main__":
    unittest.main()
