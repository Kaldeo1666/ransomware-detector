import logging
import queue
import threading

from rwdetect.baseline import BaselineIndex
from rwdetect.engine import Engine
from rwdetect.sinks.console import ConsoleSink
from rwdetect.sinks.jsonl import JsonlSink
from rwdetect.sinks.sqlite import SqliteSink

log = logging.getLogger("rwdetect")


class Worker(threading.Thread):
    def __init__(self, in_queue: queue.Queue, sinks: list, engine=None):
        super().__init__(name="rwdetect-worker", daemon=True)
        self.queue = in_queue
        self.sinks = sinks
        self.engine = engine
        self._stop_event = threading.Event()

    def _emit(self, records: list[dict]) -> None:
        for record in records:
            for sink in self.sinks:
                try:
                    sink.emit(record)
                except Exception:
                    log.exception("sink %s failed", type(sink).__name__)

    def run(self) -> None:
        while not self._stop_event.is_set() or not self.queue.empty():
            try:
                event = self.queue.get(timeout=0.5)
            except queue.Empty:
                if self.engine is not None:
                    try:
                        self._emit(self.engine.tick())
                    except Exception:
                        log.exception("engine tick failed")
                continue
            if self.engine is None:
                records = [event.to_dict()]
            else:
                try:
                    records = self.engine.handle(event)
                except Exception:
                    log.exception("engine failed on %s", event.path)
                    records = [event.to_dict()]
            self._emit(records)

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


def build_engine(config) -> Engine:
    baseline = BaselineIndex()
    count = baseline.scan(config.watch_dir, config.ignore_patterns)
    log.info("baseline built: %d files", count)
    return Engine(config, baseline)