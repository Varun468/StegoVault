from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from collections.abc import Generator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIRECTORY = PROJECT_ROOT / "data"
DB_PATH = DATA_DIRECTORY / "stegovault.db"
HISTORY_SETTING = "history_enabled"
_SECURITY_EVENTS = {
    "payload_hidden",
    "payload_extracted",
    "authentication_failed",
}


@contextmanager
def _connection() -> Generator[sqlite3.Connection, None, None]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY,
                occurred_at TEXT NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('hide', 'extract')),
                payload_kind TEXT NOT NULL CHECK (payload_kind IN ('text', 'file', 'image')),
                payload_bytes INTEGER NOT NULL CHECK (payload_bytes >= 0),
                carrier_width INTEGER NOT NULL CHECK (carrier_width > 0),
                carrier_height INTEGER NOT NULL CHECK (carrier_height > 0)
            );
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY,
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL CHECK (
                    event_type IN (
                        'payload_hidden', 'payload_extracted',
                        'authentication_failed'
                    )
                )
            );
            CREATE TABLE IF NOT EXISTS settings (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO settings (name, value)
            VALUES ('history_enabled', '1');
            """
        )
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def is_history_enabled() -> bool:
    with _connection() as connection:
        row = connection.execute(
            "SELECT value FROM settings WHERE name = ?", (HISTORY_SETTING,)
        ).fetchone()
        return row is not None and row["value"] == "1"


def set_history_enabled(enabled: bool) -> None:
    with _connection() as connection:
        connection.execute(
            "INSERT INTO settings (name, value) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            (HISTORY_SETTING, "1" if enabled else "0"),
        )


def record_operation(
    action: str,
    payload_kind: str,
    payload_bytes: int,
    carrier_width: int,
    carrier_height: int,
) -> None:
    with _connection() as connection:
        enabled = connection.execute(
            "SELECT value FROM settings WHERE name = ?", (HISTORY_SETTING,)
        ).fetchone()
        if enabled is None or enabled["value"] != "1":
            return
        connection.execute(
            """
            INSERT INTO operations (
                occurred_at, action, payload_kind, payload_bytes,
                carrier_width, carrier_height
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (_utc_now(), action, payload_kind, payload_bytes, carrier_width, carrier_height),
        )


def record_security_event(event_type: str) -> None:
    if event_type not in _SECURITY_EVENTS:
        raise ValueError("Unsupported security event.")
    with _connection() as connection:
        enabled = connection.execute(
            "SELECT value FROM settings WHERE name = ?", (HISTORY_SETTING,)
        ).fetchone()
        if enabled is None or enabled["value"] != "1":
            return
        connection.execute(
            "INSERT INTO security_events (occurred_at, event_type) VALUES (?, ?)",
            (_utc_now(), event_type),
        )


def get_dashboard_stats() -> dict[str, int]:
    with _connection() as connection:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total_operations,
                COALESCE(SUM(payload_kind IN ('file', 'image')), 0)
                    AS total_files_processed,
                COALESCE(SUM(action = 'hide' AND payload_kind = 'text'), 0)
                    AS total_messages_hidden
            FROM operations
            """
        ).fetchone()
        return {key: int(row[key]) for key in row.keys()}


def recent_operations(limit: int = 20) -> list[dict[str, object]]:
    if not 1 <= limit <= 100:
        raise ValueError("History limit must be between 1 and 100.")
    with _connection() as connection:
        rows = connection.execute(
            """
            SELECT occurred_at, action, payload_kind, payload_bytes,
                   carrier_width, carrier_height
            FROM operations ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def recent_security_events(limit: int = 50) -> list[dict[str, str]]:
    if not 1 <= limit <= 100:
        raise ValueError("Event limit must be between 1 and 100.")
    with _connection() as connection:
        rows = connection.execute(
            "SELECT occurred_at, event_type FROM security_events "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def storage_info() -> dict[str, int | str | bool]:
    with _connection() as connection:
        operations = int(
            connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        )
        events = int(
            connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        )
        enabled = connection.execute(
            "SELECT value FROM settings WHERE name = ?", (HISTORY_SETTING,)
        ).fetchone()["value"] == "1"
    return {
        "path": str(DB_PATH),
        "bytes": DB_PATH.stat().st_size if DB_PATH.exists() else 0,
        "operations": operations,
        "security_events": events,
        "history_enabled": enabled,
    }


def clear_history() -> None:
    with _connection() as connection:
        connection.execute("DELETE FROM operations")
        connection.execute("DELETE FROM security_events")


def cleanup_temporary_files() -> int:
    """Remove only app-owned, direct-child temporary files."""
    removed = 0
    for folder in (PROJECT_ROOT / "uploads", PROJECT_ROOT / "outputs"):
        if not folder.exists():
            continue
        if folder.is_symlink() or not folder.is_dir():
            raise OSError("Temporary storage directory is not a regular directory.")
        for path in folder.iterdir():
            if (
                path.name.startswith("stegovault_tmp_")
                and path.is_file()
                and not path.is_symlink()
            ):
                path.unlink()
                removed += 1
    return removed
