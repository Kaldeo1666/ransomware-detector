import queue

from watchdog.events import DirCreatedEvent, FileCreatedEvent, FileMovedEvent

from rwdetect.monitor import QueueHandler


def make(maxsize=0, patterns=("*.tmp", "~$*")):
    q = queue.Queue(maxsize=maxsize)
    return q, QueueHandler(q, list(patterns))


def test_ignores_directories_and_ignored_names():
    q, h = make()
    h.on_created(DirCreatedEvent("sandbox/sub"))
    h.on_created(FileCreatedEvent("sandbox/x.tmp"))
    h.on_created(FileCreatedEvent("sandbox/a.txt"))
    assert q.qsize() == 1
    assert q.get_nowait().path == "sandbox/a.txt"


def test_move_from_temp_name_is_kept():
    q, h = make()
    h.on_moved(FileMovedEvent("sandbox/~$a.docx", "sandbox/a.docx"))
    ev = q.get_nowait()
    assert ev.action == "moved" and ev.dest_path == "sandbox/a.docx"


def test_full_queue_counts_drops():
    q, h = make(maxsize=1, patterns=())
    h.on_created(FileCreatedEvent("a"))
    h.on_created(FileCreatedEvent("b"))
    assert h.dropped == 1