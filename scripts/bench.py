"""How many events per second can the engine process?  (Measure before you optimise.)"""
import dataclasses
import random
import shutil
import tempfile
import time
from pathlib import Path

from rwdetect.config import load_config
from rwdetect.models import FileEvent
from rwdetect.pipeline import build_engine

WORDS = "invoice report budget meeting project alpha beta quarterly".split()


def make_text(n: int) -> bytes:
    return " ".join(random.choice(WORDS) for _ in range(n // 7)).encode()


def run(label: str, engine, events: list) -> None:
    start = time.perf_counter()
    for event in events:
        engine.handle(event)
    seconds = time.perf_counter() - start
    print(f"{label:42} {len(events) / seconds:>10,.0f} events/s   ({seconds * 1000 / len(events):.2f} ms each)")


def main() -> None:
    config = load_config()
    tmp = Path(tempfile.mkdtemp(prefix="rwbench_"))
    try:
        for size_kb, count in ((4, 300), (64, 200), (512, 60)):
            folder = tmp / f"{size_kb}kb"
            folder.mkdir()
            for i in range(count):
                (folder / f"f{i}.txt").write_bytes(make_text(size_kb * 1024))
        engine = build_engine(dataclasses.replace(config, watch_dir=tmp))

        missing = [FileEvent("modified", str(tmp / f"nope_{i}.txt")) for i in range(5000)]
        run("events for files that no longer exist", engine, missing)
        for size_kb, count in ((4, 300), (64, 200), (512, 60)):
            events = [FileEvent("modified", str(tmp / f"{size_kb}kb" / f"f{i}.txt")) for i in range(count)]
            run(f"modified events, {size_kb} KB files", engine, events)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()