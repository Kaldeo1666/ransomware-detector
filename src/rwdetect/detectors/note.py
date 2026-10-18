import fnmatch
import os

from rwdetect.detectors.base import Signal, SlidingWindow, normalize


class RansomNoteDetector:
    """Are files with ransom-note-like names appearing?"""

    name = "ransom_note"

    def __init__(self, settings: dict):
        self.seconds = settings["window_seconds"]
        self.maximum = settings["ransom_note"]["notes_for_max"]
        self.patterns = [p.lower() for p in settings["ransom_note"]["patterns"]]
        self.window = SlidingWindow(self.seconds)

    def observe(self, event) -> None:
        if event.action != "created" or event.is_directory:
            return
        name = os.path.basename(event.path).lower()
        if any(fnmatch.fnmatch(name, pat) for pat in self.patterns):
            self.window.add(event.epoch, event.path)

    def signal(self, now: float) -> Signal:
        n = self.window.unique(now)
        return Signal(
            self.name, n, normalize(n, self.maximum),
            {"notes": n, "sample_paths": self.window.sample(now)},
        )