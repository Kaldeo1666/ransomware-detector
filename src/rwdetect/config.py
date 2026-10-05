from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class Config:
    watch_dir: Path
    recursive: bool
    ignore_patterns: list[str]
    queue_size: int
    sinks: dict


def load_config(path: str | Path = "config/default.yaml") -> Config:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    watch = raw["watch"]
    watch_dir = Path(watch["directory"]).resolve()
    if not watch_dir.is_dir():
        raise ValueError(f"watch.directory is not a folder: {watch_dir}")

    queue_size = int(raw["pipeline"]["queue_size"])
    if queue_size <= 0:
        raise ValueError("pipeline.queue_size must be positive")

    return Config(
        watch_dir=watch_dir,
        recursive=bool(watch.get("recursive", True)),
        ignore_patterns=list(watch.get("ignore_patterns", [])),
        queue_size=queue_size,
        sinks=raw.get("sinks", {}),
    )