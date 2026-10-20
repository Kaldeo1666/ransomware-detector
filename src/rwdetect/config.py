import copy
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SIGNAL_NAMES = {"mod_rate", "rename_burst", "ext_change", "entropy_jump", "ransom_note"}

DEFAULT_DETECTION = {
    "window_seconds": 10,
    "min_file_size": 512,
    "rate": {"files_for_max": 30},
    "rename": {"renames_for_max": 15},
    "extension": {"files_for_max": 10},
    "entropy": {"high": 7.5, "jump_delta": 2.0, "files_for_max": 10},
    "ransom_note": {
        "notes_for_max": 3,
        "patterns": ["*readme*restore*", "*decrypt*", "how_to_*", "*recover*files*"],
    },
    "weights": {
        "mod_rate": 0.25,
        "rename_burst": 0.20,
        "ext_change": 0.20,
        "entropy_jump": 0.30,
        "ransom_note": 0.05,
    },
    "gate_signals": [],
    "combo_bonus": 10,
    "combo_min_signals": 3,
    "active_threshold": 0.3,
    "levels": {"medium": 30, "high": 60, "critical": 80},
}

DEFAULT_ALERTING = {"cooldown_seconds": 30}


def deep_merge(base: dict, override: dict | None) -> dict:
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def validate_detection(d: dict) -> None:
    weights = d["weights"]
    if set(weights) != SIGNAL_NAMES:
        raise ValueError(f"detection.weights must have exactly these keys: {sorted(SIGNAL_NAMES)}")
    if any(w < 0 for w in weights.values()):
        raise ValueError("detection.weights must not be negative")
    total = sum(weights.values())
    if abs(total - 1.0) > 0.01:
        raise ValueError(f"detection.weights must sum to 1.0 (got {total:.2f})")
    lv = d["levels"]
    if not (0 < lv["medium"] < lv["high"] < lv["critical"] <= 100):
        raise ValueError("detection.levels must satisfy 0 < medium < high < critical <= 100")
    if d["window_seconds"] <= 0:
        raise ValueError("detection.window_seconds must be positive")
    unknown = set(d["gate_signals"]) - SIGNAL_NAMES
    if unknown:
        raise ValueError(f"detection.gate_signals has unknown names: {sorted(unknown)}")


@dataclass
class Config:
    watch_dir: Path
    recursive: bool
    ignore_patterns: list[str]
    queue_size: int
    sinks: dict
    ignore_dirs: list[str] = field(default_factory=list)
    detection: dict = field(default_factory=lambda: copy.deepcopy(DEFAULT_DETECTION))
    alerting: dict = field(default_factory=lambda: copy.deepcopy(DEFAULT_ALERTING))


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

    detection = deep_merge(DEFAULT_DETECTION, raw.get("detection"))
    validate_detection(detection)

    return Config(
        watch_dir=watch_dir,
        recursive=bool(watch.get("recursive", True)),
        ignore_patterns=list(watch.get("ignore_patterns", [])),
        ignore_dirs=list(watch.get("ignore_dirs", [])),
        queue_size=queue_size,
        sinks=raw.get("sinks", {}),
        detection=detection,
        alerting=deep_merge(DEFAULT_ALERTING, raw.get("alerting")),
    )