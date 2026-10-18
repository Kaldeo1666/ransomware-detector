import os

from rwdetect.baseline import BaselineIndex
from rwdetect.enrich import Enricher
from rwdetect.models import FileEvent

TEXT = (b"invoice report budget meeting project alpha beta " * 100)


def make_dir(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(TEXT)
    return f


def test_scan_records_files(tmp_path):
    make_dir(tmp_path)
    index = BaselineIndex()
    assert index.scan(tmp_path) == 1
    assert index.get(tmp_path / "a.txt").entropy < 5
    assert ".txt" in index.known_extensions()


def test_modified_event_gets_entropy_jump(tmp_path):
    f = make_dir(tmp_path)
    index = BaselineIndex()
    index.scan(tmp_path)
    f.write_bytes(os.urandom(5000))
    event = Enricher(index).process(FileEvent("modified", str(f)))
    assert event.entropy > 7.5
    assert event.entropy_delta > 3


def test_moved_event_carries_baseline_to_new_name(tmp_path):
    f = make_dir(tmp_path)
    index = BaselineIndex()
    index.scan(tmp_path)
    f.write_bytes(os.urandom(5000))
    dest = tmp_path / "a.txt.locked"
    f.rename(dest)
    event = Enricher(index).process(FileEvent("moved", str(f), str(dest)))
    assert event.entropy_delta > 3
    assert index.get(f) is None
    assert index.get(dest) is not None


def test_vanished_file_does_not_crash(tmp_path):
    f = make_dir(tmp_path)
    index = BaselineIndex()
    index.scan(tmp_path)
    f.unlink()
    event = Enricher(index).process(FileEvent("modified", str(f)))
    assert event.entropy is None and event.entropy_delta is None


def test_deleted_removes_from_baseline(tmp_path):
    f = make_dir(tmp_path)
    index = BaselineIndex()
    index.scan(tmp_path)
    f.unlink()
    Enricher(index).process(FileEvent("deleted", str(f)))
    assert index.get(f) is None