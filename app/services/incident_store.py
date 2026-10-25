import sqlite3
from pathlib import Path
from typing import Any


class IncidentStore:
    """Persistent local SQLite storage for VONKA SENTINEL-X incidents."""

    def __init__(self, database_path: str | Path = "data/sentinel.db"):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_key TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    observed_value TEXT,
                    threshold TEXT,
                    status TEXT NOT NULL DEFAULT 'New',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT
                        (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                )
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_timestamp
                ON incidents(timestamp)
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_severity
                ON incidents(severity)
            """)

    @staticmethod
    def _value(value: Any) -> str | None:
        return None if value is None else str(value)

    def save_alert(self, alert, incident_key: str) -> bool:
        """Save an alert once. Returns True for a new record."""
        with self._connect() as connection:
            cursor = connection.execute("""
                INSERT OR IGNORE INTO incidents (
                    incident_key, timestamp, rule_id, severity,
                    title, reason, observed_value, threshold
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_key,
                str(getattr(alert, "timestamp", "")),
                str(getattr(alert, "rule_id", "UNKNOWN")),
                str(getattr(alert, "severity", "INFO")),
                str(getattr(alert, "title", "Untitled alert")),
                str(getattr(alert, "reason", "")),
                self._value(getattr(alert, "observed_value", None)),
                self._value(getattr(alert, "threshold", None)),
            ))
            return cursor.rowcount == 1

    def update_metadata(
        self, incident_key: str, status: str, notes: str
    ) -> bool:
        if status not in {"New", "Investigating", "Resolved"}:
            raise ValueError("Unsupported incident status.")

        with self._connect() as connection:
            cursor = connection.execute("""
                UPDATE incidents
                SET status = ?, notes = ?
                WHERE incident_key = ?
            """, (status, notes, incident_key))
            return cursor.rowcount == 1

    def get_recent(self, limit: int = 100) -> list[dict]:
        """Return the newest incidents first."""
        if limit < 1:
            raise ValueError("limit must be at least 1")

        with self._connect() as connection:
            rows = connection.execute("""
                SELECT incident_key, timestamp, rule_id, severity,
                       title, reason, observed_value, threshold,
                       status, notes, created_at
                FROM incidents
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(row) for row in rows]

    def count(self) -> int:
        with self._connect() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM incidents"
                ).fetchone()[0]
            )
