from rwdetect.detectors.base import Signal, SlidingWindow, normalize


class RateDetector:
    """How many different files were touched recently?"""

    name = "mod_rate"

    def __init__(self, settings: dict):
        self.seconds = settings["window_seconds"]
        self.maximum = settings["rate"]["files_for_max"]
        self.window = SlidingWindow(self.seconds)

    def observe(self, event) -> None:
        if event.is_directory:
            return
        self.window.add(event.epoch, event.dest_path or event.path)

    def signal(self, now: float) -> Signal:
        n = self.window.unique(now)
        return Signal(
            self.name,
            round(n / self.seconds, 2),
            normalize(n, self.maximum),
            {"unique_files": n, "window_seconds": self.seconds,
             "sample_paths": self.window.sample(now)},
        )