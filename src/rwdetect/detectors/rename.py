from rwdetect.detectors.base import Signal, SlidingWindow, normalize


class RenameDetector:
    """How many files were renamed recently?"""

    name = "rename_burst"

    def __init__(self, settings: dict):
        self.seconds = settings["window_seconds"]
        self.maximum = settings["rename"]["renames_for_max"]
        self.window = SlidingWindow(self.seconds)

    def observe(self, event) -> None:
        if event.action == "moved" and not event.is_directory:
            self.window.add(event.epoch, event.path)

    def signal(self, now: float) -> Signal:
        n = self.window.unique(now)
        return Signal(
            self.name, n, normalize(n, self.maximum),
            {"renames": n, "window_seconds": self.seconds,
             "sample_paths": self.window.sample(now)},
        )