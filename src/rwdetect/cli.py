import argparse
import logging
import queue
import time

from rwdetect.config import load_config
from rwdetect.monitor import Monitor
from rwdetect.pipeline import Worker, build_sinks


def cmd_start(args) -> None:
    config = load_config(args.config)
    q = queue.Queue(maxsize=config.queue_size)
    worker = Worker(q, build_sinks(config))
    monitor = Monitor(config, q)

    worker.start()
    monitor.start()
    print(f"Watching {config.watch_dir}  (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        worker.stop()
        print(f"Stopped. Dropped events: {monitor.handler.dropped}")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(prog="rwdetect")
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start", help="start monitoring")
    start.add_argument("--config", default="config/default.yaml")
    start.set_defaults(func=cmd_start)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()