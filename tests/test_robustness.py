import os
import queue
import time

from watchdog.events import FileCreatedEvent

from rwdetect.entropy import SAMPLE_CHUNK, file_entropy, read_sample
from rwdetect.monitor import QueueHandler
from rwdetect.pipeline import Worker


class SlowSink:
    def __init__(self):
        self.count = 0

    def emit(self, record):
        time.sleep(0.01)
        self.count += 1

    def close(self):
        pass


def test_directory_instead_of_file_returns_none(tmp_path):
    assert file_entropy(tmp_path) is None


def test_big_files_are_sampled_not_fully_read(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(os.urandom(2_000_000))
    assert len(read_sample(f)) == 2 * SAMPLE_CHUNK


def test_partial_encryption_in_the_middle_is_still_visible(tmp_path):
    f = tmp_path / "partial.bin"
    text = b"invoice report budget meeting " * 10_000          # 300 KB of text
    f.write_bytes(text + os.urandom(400_000))                    # random block from 300 KB on
    whole_text = tmp_path / "text.bin"
    whole_text.write_bytes(text + text)
    assert file_entropy(f) > file_entropy(whole_text) + 1.0


def test_overflow_is_counted_and_nothing_is_lost_silently():
    q = queue.Queue(maxsize=5)
    handler = QueueHandler(q, [])
    sink = SlowSink()
    worker = Worker(q, [sink])
    worker.start()
    for i in range(200):
        handler.on_created(FileCreatedEvent(f"f{i}"))
    worker.stop()
    assert handler.dropped > 0
    assert sink.count + handler.dropped == 200