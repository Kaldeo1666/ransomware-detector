import os

from rwdetect.detectors.base import Signal, SlidingWindow, normalize

# Formats that are ALREADY compressed, so high entropy is normal for them.
HIGH_ENTROPY_EXTENSIONS = {
    ".zip", ".gz", ".7z", ".rar", ".bz2", ".xz", ".jpg", ".jpeg", ".png", ".gif",
    ".webp", ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".pdf", ".docx", ".xlsx", ".pptx",
}


def classify(event, settings: dict) -> str | None:
    """Return 'jump', 'new_high' or None for one enriched event."""
    cfg = settings["entropy"]
    if event.is_directory or event.entropy is None:
        return None
    if event.size is not None and event.size < settings["min_file_size"]:
        return None
    if event.entropy < cfg["high"]:
        return None
    if event.entropy_delta is not None:
        return "jump" if event.entropy_delta >= cfg["jump_delta"] else None
    if event.action in ("created", "moved"):
        target = event.dest_path or event.path
        if os.path.splitext(target)[1].lower() not in HIGH_ENTROPY_EXTENSIONS:
            return "new_high"
    return None


class EntropyJumpDetector:
    """Are many files becoming random-looking?"""

    name = "entropy_jump"

    def __init__(self, settings: dict):
        self.settings = settings
        self.seconds = settings["window_seconds"]
        self.maximum = settings["entropy"]["files_for_max"]
        self.window = SlidingWindow(self.seconds)

    def observe(self, event) -> None:
        if classify(event, self.settings) is None:
            return
        self.window.add(event.epoch, event.dest_path or event.path, event.entropy_delta or 0.0)

    def signal(self, now: float) -> Signal:
        n = self.window.unique(now)
        deltas = [d for d in self.window.values(now) if d > 0]
        avg = round(sum(deltas) / len(deltas), 2) if deltas else 0.0
        return Signal(
            self.name, n, normalize(n, self.maximum),
            {"files": n, "avg_delta": avg, "sample_paths": self.window.sample(now)},
        )