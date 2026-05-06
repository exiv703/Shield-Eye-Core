import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


class HistoryStore:
    """Thread-safe history storage using SQLite."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialize history store.

        Args:
            db_path: Path to SQLite database.
                Defaults to ``backend/data/history.db``.
        """
        if db_path is None:
            db_path = str(Path(__file__).parent / "data" / "history.db")
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Create the database schema if needed."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    target TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_history(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_target ON scan_history(target)")
            conn.commit()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a SQLite connection with lock timeout.

        Yields:
            An open SQLite connection with row access by column name.
        """
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def save_entry(self, entry: Dict[str, Any]) -> None:
        """Atomically save a history entry.

        Args:
            entry: Entry payload with keys ``timestamp``, ``target``, and ``result``.
        """
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO scan_history (timestamp, target, result_json) VALUES (?, ?, ?)",
                (
                    str(entry["timestamp"]),
                    str(entry["target"]),
                    json.dumps(entry["result"]),
                ),
            )
            conn.commit()

    def load_entries(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Load history entries ordered by most recent first.

        Args:
            limit: Maximum number of entries to return. ``None`` means no limit.

        Returns:
            List of entries containing ``timestamp``, ``target``, and ``result``.
        """
        query = "SELECT timestamp, target, result_json FROM scan_history ORDER BY timestamp DESC"
        params: tuple = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (int(limit),)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [
                {
                    "timestamp": row["timestamp"],
                    "target": row["target"],
                    "result": json.loads(row["result_json"]),
                }
                for row in rows
            ]

    def import_json_legacy(self, json_path: str) -> int:
        """Import entries from legacy JSON history.

        Args:
            json_path: Path to the legacy ``scan_history.json`` file.

        Returns:
            Number of successfully imported entries.
        """
        if not os.path.exists(json_path):
            return 0

        with open(json_path, "r", encoding="utf-8") as file:
            legacy_entries = json.load(file)

        if not isinstance(legacy_entries, list):
            return 0

        imported = 0
        for raw_entry in legacy_entries:
            if not isinstance(raw_entry, dict):
                continue
            try:
                if {"timestamp", "target", "result"}.issubset(raw_entry.keys()):
                    normalized = {
                        "timestamp": raw_entry["timestamp"],
                        "target": raw_entry["target"],
                        "result": raw_entry["result"],
                    }
                else:
                    timestamp = raw_entry.get("timestamp") or raw_entry.get("date")
                    target = raw_entry.get("target") or "Unknown"
                    if not timestamp:
                        continue
                    normalized = {
                        "timestamp": timestamp,
                        "target": target,
                        "result": raw_entry,
                    }
                self.save_entry(normalized)
                imported += 1
            except Exception:
                continue

        return imported
