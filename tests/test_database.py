import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from database import storage


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        storage.DB_PATH = Path(self.temp_dir.name) / "history.sqlite3"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_records_only_operation_metadata(self) -> None:
        storage.record_operation("hide", "text", 20, 100, 100)
        storage.record_security_event("payload_hidden")

        self.assertEqual(
            storage.get_dashboard_stats(),
            {
                "total_operations": 1,
                "total_files_processed": 0,
                "total_messages_hidden": 1,
            },
        )
        with closing(sqlite3.connect(storage.DB_PATH)) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            self.assertNotIn("passwords", tables)
            self.assertNotIn("payloads", tables)

    def test_history_can_be_disabled(self) -> None:
        storage.set_history_enabled(False)
        storage.record_operation("hide", "file", 100, 100, 100)
        storage.record_security_event("payload_hidden")

        self.assertEqual(storage.get_dashboard_stats()["total_operations"], 0)
        self.assertEqual(storage.recent_security_events(), [])

    def test_invalid_security_event_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            storage.record_security_event("contains secret text")


if __name__ == "__main__":
    unittest.main()
