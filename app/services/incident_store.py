import sqlite3
from contextlib import closing
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
        with closing(self._connect()) as connection, connection:
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
            connection.execute("""
                CREATE TABLE IF NOT EXISTS incident_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_key TEXT NOT NULL,
                    action TEXT NOT NULL,
                    old_status TEXT,
                    new_status TEXT,
                    details TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT
                        (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    FOREIGN KEY (incident_key)
                        REFERENCES incidents(incident_key)
                )
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_incident_audit_key
                ON incident_audit(incident_key, id DESC)
            """)

    @staticmethod
    def _value(value: Any) -> str | None:
        return None if value is None else str(value)

    def save_alert(self, alert, incident_key: str) -> bool:
        """Save an alert once. Returns True for a new record."""
        with closing(self._connect()) as connection, connection:
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
            if cursor.rowcount == 1:
                connection.execute("""
                    INSERT INTO incident_audit (
                        incident_key, action, new_status, details
                    ) VALUES (?, 'Incident created', 'New', 'Alert persisted')
                """, (incident_key,))
                return True
            return False

    def update_metadata(
        self, incident_key: str, status: str, notes: str
    ) -> bool:
        """Update investigation metadata and audit actual changes."""
        if status not in {"New", "Investigating", "Resolved"}:
            raise ValueError("Unsupported incident status.")

        notes = str(notes)
        with closing(self._connect()) as connection, connection:
            row = connection.execute("""
                SELECT status, notes
                FROM incidents
                WHERE incident_key = ?
            """, (incident_key,)).fetchone()

            if row is None:
                return False

            old_status = row["status"]
            old_notes = row["notes"]

            if old_status == status and old_notes == notes:
                return True

            connection.execute("""
                UPDATE incidents
                SET status = ?, notes = ?
                WHERE incident_key = ?
            """, (status, notes, incident_key))

            changes = []
            if old_status != status:
                changes.append(f"Status changed: {old_status} -> {status}")
            if old_notes != notes:
                changes.append("Investigation notes updated")

            connection.execute("""
                INSERT INTO incident_audit (
                    incident_key, action, old_status, new_status, details
                ) VALUES (?, 'Investigation updated', ?, ?, ?)
            """, (incident_key, old_status, status, "; ".join(changes)))

            return True

    def get_audit_history(
        self, incident_key: str, limit: int = 100
    ) -> list[dict]:
        """Return recent audit entries for one incident."""
        if limit < 1:
            raise ValueError("limit must be at least 1")

        with closing(self._connect()) as connection, connection:
            rows = connection.execute("""
                SELECT id, incident_key, action, old_status, new_status,
                       details, created_at
                FROM incident_audit
                WHERE incident_key = ?
                ORDER BY id DESC
                LIMIT ?
            """, (incident_key, limit)).fetchall()
            return [dict(row) for row in rows]

    def get_recent(self, limit: int = 100) -> list[dict]:
        """Return the newest incidents first."""
        if limit < 1:
            raise ValueError("limit must be at least 1")

        with closing(self._connect()) as connection, connection:
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
        with closing(self._connect()) as connection, connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM incidents"
                ).fetchone()[0]
            )
