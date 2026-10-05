import queue

from rwdetect.models import FileEvent
from rwdetect.pipeline import Worker


class Boom:
    def emit(self, record):
        raise RuntimeError("boom")

    def close(self):
        pass


class Collect:
    def __init__(self):
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def close(self):
        pass


def test_failing_sink_does_not_block_others():
    q = queue.Queue()
    good = Collect()
    w = Worker(q, [Boom(), good])
    w.start()
    q.put(FileEvent("created", "a.txt"))
    w.stop()
    assert len(good.records) == 1