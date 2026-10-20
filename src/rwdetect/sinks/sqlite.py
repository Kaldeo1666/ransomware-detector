import json
import sqlite3
import threading
import time
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

INSERT_SQL = (
    "INSERT OR IGNORE INTO events "
    "(event_id, timestamp, event_type, action, path, dest_path, "
    "severity, risk_score, payload) VALUES (?,?,?,?,?,?,?,?,?)"
)


class SqliteSink:
    """Stores records in SQLite, committing in batches for speed.

    A batch is written when it reaches `batch_size`, when `flush_interval` seconds have
    passed, when an alert arrives (alerts are never delayed), when flush() is called
    (the worker does that whenever it is idle), or on close().
    """

    def __init__(self, path: str | Path, batch_size: int = 100, flush_interval: float = 0.5):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._lock = threading.Lock()
        self._pending: list[tuple] = []
        self._last_flush = time.monotonic()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)

    def emit(self, record: dict) -> None:
        row = (
            record["event_id"],
            record["timestamp"],
            record["event_type"],
            record.get("action"),
            record.get("path"),
            record.get("dest_path"),
            record.get("severity"),
            record.get("risk_score"),
            json.dumps(record, ensure_ascii=False),
        )
        with self._lock:
            self._pending.append(row)
            due = time.monotonic() - self._last_flush >= self.flush_interval
            if record["event_type"] == "alert" or len(self._pending) >= self.batch_size or due:
                self._flush_locked()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if self._pending:
            self._db.executemany(INSERT_SQL, self._pending)
            self._db.commit()
            self._pending.clear()
        self._last_flush = time.monotonic()

    def close(self) -> None:
        with self._lock:
            self._flush_locked()
            self._db.close()