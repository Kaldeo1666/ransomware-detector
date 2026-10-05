import fnmatch
import queue
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from rwdetect.models import FileEvent


class QueueHandler(FileSystemEventHandler):
    def __init__(self, out_queue: queue.Queue, ignore_patterns: list[str]):
        super().__init__()
        self.queue = out_queue
        self.ignore_patterns = ignore_patterns
        self.dropped = 0

    def _is_ignored(self, path: str) -> bool:
        name = Path(path).name
        return any(fnmatch.fnmatch(name, pat) for pat in self.ignore_patterns)

    def _push(self, action: str, event) -> None:
        if event.is_directory:
            return
        dest = event.dest_path or None
        paths = [event.src_path] + ([dest] if dest else [])
        if all(self._is_ignored(p) for p in paths):
            return
        try:
            self.queue.put_nowait(FileEvent(action, event.src_path, dest))
        except queue.Full:
            self.dropped += 1

    def on_created(self, event): self._push("created", event)
    def on_modified(self, event): self._push("modified", event)
    def on_deleted(self, event): self._push("deleted", event)
    def on_moved(self, event): self._push("moved", event)
class Monitor:
    def __init__(self, config, out_queue: queue.Queue):
        self.handler = QueueHandler(out_queue, config.ignore_patterns)
        self.observer = Observer()
        self.observer.schedule(
            self.handler, str(config.watch_dir), recursive=config.recursive
        )

    def start(self) -> None:
        self.observer.start()

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join()