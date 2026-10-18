import os

from rwdetect.detectors.base import Signal, SlidingWindow, normalize

COMMON_EXTENSIONS = {
    ".txt", ".md", ".csv", ".log", ".json", ".yaml", ".yml", ".xml", ".html", ".css",
    ".js", ".py", ".c", ".cpp", ".h", ".java", ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".zip", ".gz",
    ".7z", ".rar", ".mp3", ".mp4", ".mkv", ".avi", ".wav", ".exe", ".dll", ".tmp",
}


class ExtensionDetector:
    """Are many files suddenly getting the same NEW, never-seen extension?"""

    name = "ext_change"

    def __init__(self, settings: dict, known_extensions=()):
        self.seconds = settings["window_seconds"]
        self.maximum = settings["extension"]["files_for_max"]
        self.known = COMMON_EXTENSIONS | set(known_extensions)
        self.windows: dict[str, SlidingWindow] = {}

    def observe(self, event) -> None:
        if event.is_directory:
            return
        if event.action == "moved":
            target = event.dest_path
        elif event.action == "created":
            target = event.path
        else:
            return
        ext = os.path.splitext(target)[1].lower()
        if not ext or ext in self.known:
            return
        self.windows.setdefault(ext, SlidingWindow(self.seconds)).add(event.epoch, target)

    def signal(self, now: float) -> Signal:
        best_ext, best = "", 0
        for ext, window in list(self.windows.items()):
            n = window.unique(now)
            if n == 0:
                del self.windows[ext]
            elif n > best:
                best_ext, best = ext, n
        evidence = {"new_extension": best_ext, "files": best}
        if best_ext:
            evidence["sample_paths"] = self.windows[best_ext].sample(now)
        return Signal(self.name, best, normalize(best, self.maximum), evidence)