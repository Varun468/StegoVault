import tempfile
import unittest
from pathlib import Path

from database import storage
from streamlit.testing.v1 import AppTest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class UserInterfaceTests(unittest.TestCase):
    def test_all_navigation_pages_render_without_exceptions(self) -> None:
        original_db_path = storage.DB_PATH
        with tempfile.TemporaryDirectory() as temporary:
            storage.DB_PATH = Path(temporary) / "history.sqlite3"
            try:
                app = AppTest.from_file(
                    str(PROJECT_ROOT / "app.py"), default_timeout=15
                ).run()
                self.assertFalse(app.exception)
                self.assertEqual(app.sidebar.radio[0].value, "Dashboard")
                for page in (
                    "Hide Information",
                    "Extract Information",
                    "Image Analysis",
                    "Security Center",
                    "Settings",
                    "Dashboard",
                ):
                    app.sidebar.radio[0].set_value(page).run()
                    self.assertFalse(app.exception, f"{page} raised a Streamlit exception")
            finally:
                storage.DB_PATH = original_db_path


if __name__ == "__main__":
    unittest.main()
