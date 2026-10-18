"""Day 5 scratch tool: watch the sandbox and print the five signals live (0.0 to 1.0)."""
import queue
import time

from rwdetect.baseline import BaselineIndex
from rwdetect.config import load_config
from rwdetect.detectors.entropy_jump import EntropyJumpDetector
from rwdetect.detectors.extension import ExtensionDetector
from rwdetect.detectors.note import RansomNoteDetector
from rwdetect.detectors.rate import RateDetector
from rwdetect.detectors.rename import RenameDetector
from rwdetect.enrich import Enricher
from rwdetect.monitor import Monitor


def main() -> None:
    config = load_config()
    settings = config.detection
    baseline = BaselineIndex()
    baseline.scan(config.watch_dir, config.ignore_patterns)
    enricher = Enricher(baseline)
    detectors = [
        RateDetector(settings),
        RenameDetector(settings),
        ExtensionDetector(settings, baseline.known_extensions()),
        EntropyJumpDetector(settings),
        RansomNoteDetector(settings),
    ]
    q = queue.Queue(maxsize=config.queue_size)
    monitor = Monitor(config, q)
    monitor.start()
    print(f"Watching {config.watch_dir}  (Ctrl+C to stop)")
    last_print = 0.0
    try:
        while True:
            try:
                event = q.get(timeout=0.2)
                enricher.process(event)
                for detector in detectors:
                    detector.observe(event)
            except queue.Empty:
                pass
            now = time.time()
            if now - last_print >= 0.5:
                last_print = now
                signals = [d.signal(now) for d in detectors]
                if any(s.normalized > 0 for s in signals):
                    print("  ".join(f"{s.name}={s.normalized:.2f}" for s in signals), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()