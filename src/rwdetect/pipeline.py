import logging
import queue
import threading

from rwdetect.sinks.console import ConsoleSink
from rwdetect.sinks.jsonl import JsonlSink
from rwdetect.sinks.sqlite import SqliteSink

log = logging.getLogger("rwdetect")


class Worker(threading.Thread):
    def __init__(self, in_queue: queue.Queue, sinks: list):
        super().__init__(name="rwdetect-worker", daemon=True)
        self.queue = in_queue
        self.sinks = sinks
        self._stop_event = threading.Event()

    def run(self) -> None:
        while not self._stop_event.is_set() or not self.queue.empty():
            try:
                event = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            record = event.to_dict()
            for sink in self.sinks:
                try:
                    sink.emit(record)
                except Exception:
                    log.exception("sink %s failed", type(sink).__name__)

    def stop(self) -> None:
        self._stop_event.set()
        self.join()
        for sink in self.sinks:
            try:
                sink.close()
            except Exception:
                log.exception("closing %s failed", type(sink).__name__)


def build_sinks(config) -> list:
    cfg = config.sinks
    sinks = []
    if cfg.get("console", {}).get("enabled"):
        sinks.append(ConsoleSink())
    if cfg.get("jsonl", {}).get("enabled"):
        sinks.append(JsonlSink(cfg["jsonl"]["path"]))
    if cfg.get("sqlite", {}).get("enabled"):
        sinks.append(SqliteSink(cfg["sqlite"]["path"]))
    return sinks