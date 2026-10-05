import sqlite3

from rwdetect.models import FileEvent
from rwdetect.sinks.sqlite import SqliteSink


def test_emit_stores_event_and_ignores_duplicates(tmp_path):
    db_path = tmp_path / "t.db"
    sink = SqliteSink(db_path)
    evil = FileEvent("created", "x'); DROP TABLE events;--").to_dict()

    sink.emit(evil)
    sink.emit(evil)  # same event_id twice
    sink.close()

    db = sqlite3.connect(db_path)
    rows = db.execute("SELECT path FROM events").fetchall()
    assert rows == [("x'); DROP TABLE events;--",)]