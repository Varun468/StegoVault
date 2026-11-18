import ast
import tomllib
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NETWORK_MODULES = {"requests", "httpx", "socket", "urllib.request"}


class OfflineConfigurationTests(unittest.TestCase):
    def test_streamlit_is_local_and_telemetry_is_disabled(self) -> None:
        with (PROJECT_ROOT / ".streamlit" / "config.toml").open("rb") as file:
            config = tomllib.load(file)

        self.assertEqual(config["server"]["address"], "127.0.0.1")
        self.assertEqual(config["server"]["port"], 8501)
        self.assertFalse(config["browser"]["gatherUsageStats"])

    def test_application_modules_do_not_import_network_clients(self) -> None:
        for path in PROJECT_ROOT.rglob("*.py"):
            if ".venv" in path.parts or "tests" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = {alias.name for alias in node.names}
                elif isinstance(node, ast.ImportFrom):
                    imported = {node.module or ""}
                else:
                    continue
                self.assertTrue(
                    imported.isdisjoint(NETWORK_MODULES),
                    f"Unexpected network client import in {path}",
                )


if __name__ == "__main__":
    unittest.main()
