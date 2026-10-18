from rwdetect.baseline import BaselineIndex, measure
from rwdetect.models import FileEvent


class Enricher:
    """Adds size, entropy and entropy_delta to an event, and keeps the baseline current."""

    def __init__(self, baseline: BaselineIndex):
        self.baseline = baseline

    def process(self, event: FileEvent) -> FileEvent:
        if event.is_directory:
            return event
        if event.action == "deleted":
            self.baseline.remove(event.path)
            return event

        target = event.dest_path or event.path
        previous = self.baseline.get(event.path)
        current = measure(target)

        if event.action == "moved":
            self.baseline.remove(event.path)

        if current is not None:
            event.size = current.size
            event.entropy = round(current.entropy, 3)
            if previous is not None:
                event.entropy_delta = round(current.entropy - previous.entropy, 3)
            self.baseline.put(target, current)
        elif previous is not None and event.action == "moved":
            self.baseline.put(target, previous)  # file vanished: carry the old record
        return event