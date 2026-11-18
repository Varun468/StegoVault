import tomllib
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PhaseOneSetupTests(unittest.TestCase):
    def test_streamlit_is_configured_for_localhost_only(self) -> None:
        with (PROJECT_ROOT / ".streamlit" / "config.toml").open("rb") as file:
            config = tomllib.load(file)

        self.assertEqual(config["server"]["address"], "127.0.0.1")
        self.assertEqual(config["server"]["port"], 8501)

    def test_streamlit_usage_stats_are_disabled(self) -> None:
        with (PROJECT_ROOT / ".streamlit" / "config.toml").open("rb") as file:
            config = tomllib.load(file)

        self.assertFalse(config["browser"]["gatherUsageStats"])

    def test_required_dependencies_are_declared(self) -> None:
        requirements = (PROJECT_ROOT / "requirements.txt").read_text(
            encoding="utf-8"
        )
        declared = {
            line.split(">=")[0].strip().lower()
            for line in requirements.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }

        self.assertTrue(
            {
                "streamlit",
                "pillow",
                "numpy",
                "cryptography",
                "opencv-python-headless",
                "scikit-image",
                "pytest",
            }.issubset(declared)
        )


if __name__ == "__main__":
    unittest.main()
