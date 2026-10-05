import json
import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    timestamp  TEXT NOT NULL,
    event_type TEXT NOT NULL,
    action     TEXT,
    path       TEXT,
    dest_path  TEXT,
    severity   TEXT,
    risk_score INTEGER,
    payload    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
"""
class SqliteSink:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)

    def emit(self, record: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO events "
                "(event_id, timestamp, event_type, action, path, dest_path, "
                "severity, risk_score, payload) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    record["event_id"],
                    record["timestamp"],
                    record["event_type"],
                    record.get("action"),
                    record.get("path"),
                    record.get("dest_path"),
                    record.get("severity"),
                    record.get("risk_score"),
                    json.dumps(record, ensure_ascii=False),
                ),
            )
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()