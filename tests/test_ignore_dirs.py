import os
import queue

from watchdog.events import FileCreatedEvent, FileMovedEvent

from rwdetect.baseline import BaselineIndex
from rwdetect.monitor import QueueHandler

TEXT = b"invoice report budget meeting project alpha beta " * 100


def make(dirs=(".git", "node_modules")):
    q = queue.Queue()
    return q, QueueHandler(q, [], list(dirs))


def test_events_inside_ignored_dirs_are_dropped():
    q, h = make()
    h.on_created(FileCreatedEvent("/proj/.git/objects/ab/cdef"))
    h.on_created(FileCreatedEvent("/proj/node_modules/x/index.js"))
    h.on_created(FileCreatedEvent("/proj/src/main.py"))
    assert q.qsize() == 1
    assert q.get_nowait().path == "/proj/src/main.py"


def test_ignore_dirs_is_case_insensitive():
    q, h = make()
    h.on_created(FileCreatedEvent("/proj/.GIT/config"))
    assert q.qsize() == 0


def test_move_out_of_an_ignored_dir_is_kept():
    q, h = make()
    h.on_moved(FileMovedEvent("/proj/.git/tmp_obj", "/proj/src/a.txt"))
    assert q.qsize() == 1


def test_file_named_like_an_ignored_dir_is_not_ignored():
    q, h = make()
    h.on_created(FileCreatedEvent("/proj/src/.git"))   # a FILE called .git, not a folder
    assert q.qsize() == 1


def test_baseline_scan_skips_ignored_dirs(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "obj").write_bytes(os.urandom(2000))
    (tmp_path / "a.txt").write_bytes(TEXT)
    index = BaselineIndex()
    assert index.scan(tmp_path, ignore_dirs=[".git"]) == 1