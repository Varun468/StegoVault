import unittest

from security.validation import sanitize_filename


class FilenameValidationTests(unittest.TestCase):
    def test_removes_paths_without_losing_unicode_names(self) -> None:
        self.assertEqual(
            sanitize_filename(r"..\秘密\résumé.pdf"),
            "résumé.pdf",
        )

    def test_removes_windows_path_characters_and_reserved_names(self) -> None:
        self.assertEqual(sanitize_filename("../../CON.txt"), "_CON.txt")
        self.assertNotIn("/", sanitize_filename(r"C:\temp\file?.txt"))
        self.assertEqual(sanitize_filename("..."), "extracted_file")


if __name__ == "__main__":
    unittest.main()
