import sqlite3

from rwdetect.models import FileEvent
from rwdetect.sinks.sqlite import SqliteSink


def count(path):
    db = sqlite3.connect(path)
    n = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    db.close()
    return n


def test_records_are_batched_until_flush(tmp_path):
    path = tmp_path / "b.db"
    sink = SqliteSink(path, batch_size=100, flush_interval=60)
    for i in range(5):
        sink.emit(FileEvent("created", f"f{i}").to_dict())
    assert count(path) == 0          # still in the in-memory batch
    sink.flush()
    assert count(path) == 5
    sink.close()


def test_full_batch_is_written_automatically(tmp_path):
    path = tmp_path / "b.db"
    sink = SqliteSink(path, batch_size=3, flush_interval=60)
    for i in range(3):
        sink.emit(FileEvent("created", f"f{i}").to_dict())
    assert count(path) == 3
    sink.close()


def test_alerts_are_never_delayed(tmp_path):
    path = tmp_path / "b.db"
    sink = SqliteSink(path, batch_size=100, flush_interval=60)
    sink.emit(FileEvent("created", "a").to_dict())
    alert = {"event_id": "x1", "timestamp": "2026-01-01T00:00:00.000Z", "event_type": "alert",
             "severity": "high", "risk_score": 70}
    sink.emit(alert)
    assert count(path) == 2          # the alert flushed the whole batch
    sink.close()


def test_close_writes_the_remaining_batch(tmp_path):
    path = tmp_path / "b.db"
    sink = SqliteSink(path, batch_size=100, flush_interval=60)
    sink.emit(FileEvent("created", "a").to_dict())
    sink.close()
    assert count(path) == 1