"""Day 4 scratch tool: watch the sandbox and print the entropy of every event."""
import queue

from rwdetect.baseline import BaselineIndex
from rwdetect.config import load_config
from rwdetect.enrich import Enricher
from rwdetect.monitor import Monitor


def main() -> None:
    config = load_config()
    baseline = BaselineIndex()
    count = baseline.scan(config.watch_dir, config.ignore_patterns)
    print(f"Baseline: {count} files")
    enricher = Enricher(baseline)
    q = queue.Queue(maxsize=config.queue_size)
    monitor = Monitor(config, q)
    monitor.start()
    print(f"Watching {config.watch_dir}  (Ctrl+C to stop)")
    try:
        while True:
            try:
                event = q.get(timeout=0.5)
            except queue.Empty:
                continue
            enricher.process(event)
            line = f"{event.action.upper():9} {event.path}"
            if event.dest_path:
                line += f" -> {event.dest_path}"
            if event.entropy is not None:
                line += f"   H={event.entropy:.2f}"
            if event.entropy_delta is not None:
                line += f"  delta={event.entropy_delta:+.2f}"
            print(line, flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()