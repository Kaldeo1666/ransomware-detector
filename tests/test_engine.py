import os

from rwdetect.baseline import BaselineIndex
from rwdetect.config import Config
from rwdetect.engine import Engine
from rwdetect.models import FileEvent

TEXT = b"invoice report budget meeting project alpha beta " * 100


def make_engine(tmp_path, n_files, ext=".txt"):
    for i in range(n_files):
        (tmp_path / f"f{i}{ext}").write_bytes(TEXT)
    baseline = BaselineIndex()
    baseline.scan(tmp_path)
    config = Config(watch_dir=tmp_path, recursive=True, ignore_patterns=[],
                    queue_size=100, sinks={})
    return Engine(config, baseline)


def alerts_of(records):
    return [r for r in records if r["event_type"] == "alert"]


def test_in_place_attack_raises_critical_alert(tmp_path):
    engine = make_engine(tmp_path, 20)
    out, t = [], 1000.0
    for i in range(20):
        f = tmp_path / f"f{i}.txt"
        f.write_bytes(os.urandom(4000))
        locked = tmp_path / f"f{i}.txt.locked"
        f.rename(locked)
        out += engine.handle(FileEvent("modified", str(f), epoch=t))
        out += engine.handle(FileEvent("moved", str(f), str(locked), epoch=t + 0.001))
        t += 0.01
    alerts = alerts_of(out)
    assert alerts, "expected at least one alert"
    assert alerts[-1]["severity"] == "critical"
    assert alerts[0]["mitre"]["technique"] == "T1486"
    assert alerts[0]["status"] == "open"


def test_copy_delete_attack_is_also_caught(tmp_path):
    engine = make_engine(tmp_path, 20)
    out, t = [], 1000.0
    for i in range(20):
        f = tmp_path / f"f{i}.txt"
        locked = tmp_path / f"f{i}.txt.locked"
        locked.write_bytes(os.urandom(4000))
        f.unlink()
        out += engine.handle(FileEvent("created", str(locked), epoch=t))
        out += engine.handle(FileEvent("deleted", str(f), epoch=t + 0.001))
        t += 0.01
    assert any(a["severity"] in ("high", "critical") for a in alerts_of(out))


def test_bulk_text_copy_does_not_alert(tmp_path):
    engine = make_engine(tmp_path, 0)
    out, t = [], 1000.0
    for i in range(80):
        f = tmp_path / f"new{i}.txt"
        f.write_bytes(TEXT)
        out += engine.handle(FileEvent("created", str(f), epoch=t))
        t += 0.01
    assert alerts_of(out) == []
    assert engine.last_result.score == 25


def test_incident_resolves_after_quiet_period(tmp_path):
    engine = make_engine(tmp_path, 20)
    t = 1000.0
    for i in range(20):
        f = tmp_path / f"f{i}.txt"
        f.write_bytes(os.urandom(4000))
        locked = tmp_path / f"f{i}.txt.locked"
        f.rename(locked)
        engine.handle(FileEvent("moved", str(f), str(locked), epoch=t))
        t += 0.01
    assert engine.alerts.open
    engine.tick(t + 15)                 # window has emptied -> level info, quiet starts
    resolved = engine.tick(t + 15 + 31)  # cooldown (30s) passed
    assert [a["status"] for a in alerts_of(resolved)] == ["resolved"]


def test_event_record_contains_entropy_fields(tmp_path):
    engine = make_engine(tmp_path, 1)
    f = tmp_path / "f0.txt"
    f.write_bytes(os.urandom(4000))
    record = engine.handle(FileEvent("modified", str(f)))[0]
    assert record["entropy"] > 7.5 and record["entropy_delta"] > 3
    assert "epoch" not in record