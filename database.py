"""SQLite storage back-end for threatScout IoC records."""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from models import IoCRecord, IoCType, RiskLevel

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path("threat_intel.db")

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS iocs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    value      TEXT    NOT NULL,
    type       TEXT    NOT NULL,
    source     TEXT    NOT NULL,
    timestamp  TEXT    NOT NULL,
    risk_level TEXT    NOT NULL,
    UNIQUE(value, type)
);
"""


class DatabaseManager:
    """Manages SQLite persistence for Indicators of Compromise.

    Args:
        db_path: Filesystem path to the SQLite database file.
    """

    def __init__(self, db_path: Path = _DEFAULT_DB_PATH) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    # lifecycle

    def connect(self) -> None:
        """Open (or create) the database and ensure the schema exists."""
        logger.info("Connecting to database: %s", self._db_path)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute(_CREATE_TABLE_SQL)
        self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            logger.info("Database connection closed.")

    # write

    def insert(self, record: IoCRecord) -> bool:
        """Insert a single IoC record, skipping duplicates.

        Args:
            record: Validated ``IoCRecord`` to persist.

        Returns:
            ``True`` if the record was inserted, ``False`` if it already existed.
        """
        conn = self._ensure_connection()
        try:
            conn.execute(
                "INSERT INTO iocs (value, type, source, timestamp, risk_level) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    record.value,
                    record.type.value,
                    record.source,
                    record.timestamp.isoformat(),
                    record.risk_level.value,
                ),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Duplicate (value, type) — silently skip
            return False

    def insert_many(self, records: list[IoCRecord]) -> int:
        """Bulk-insert records with deduplication.

        Args:
            records: List of validated ``IoCRecord`` objects.

        Returns:
            Number of newly inserted records.
        """
        inserted = 0
        for record in records:
            if self.insert(record):
                inserted += 1
        logger.info("Inserted %d / %d records (duplicates skipped).", inserted, len(records))
        return inserted

    # read

    def fetch_all(self) -> list[IoCRecord]:
        """Return every IoC record currently stored in the database."""
        conn = self._ensure_connection()
        cursor = conn.execute(
            "SELECT value, type, source, timestamp, risk_level FROM iocs ORDER BY id"
        )
        results: list[IoCRecord] = []
        for row in cursor.fetchall():
            results.append(
                IoCRecord(
                    value=row[0],
                    type=IoCType(row[1]),
                    source=row[2],
                    timestamp=datetime.fromisoformat(row[3]).replace(tzinfo=timezone.utc),
                    risk_level=RiskLevel(row[4]),
                )
            )
        return results

    def count(self) -> int:
        """Return the total number of stored IoC records."""
        conn = self._ensure_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM iocs")
        return cursor.fetchone()[0]

    # private helpers

    def _ensure_connection(self) -> sqlite3.Connection:
        """Return the active connection or raise if not connected."""
        if self._conn is None:
            raise RuntimeError("Database is not connected. Call connect() first.")
        return self._conn
