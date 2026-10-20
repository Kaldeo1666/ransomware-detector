import time

from rwdetect.alerting import AlertManager
from rwdetect.baseline import BaselineIndex
from rwdetect.detectors.entropy_jump import EntropyJumpDetector
from rwdetect.detectors.extension import ExtensionDetector
from rwdetect.detectors.note import RansomNoteDetector
from rwdetect.detectors.rate import RateDetector
from rwdetect.detectors.rename import RenameDetector
from rwdetect.enrich import Enricher
from rwdetect.models import Alert, FileEvent
from rwdetect.scoring import RiskScorer


class Engine:
    """Ties it together: enrich -> detectors -> score -> alert decision."""

    def __init__(self, config, baseline: BaselineIndex | None = None):
        self.config = config
        self.settings = config.detection
        self.baseline = baseline if baseline is not None else BaselineIndex()
        self.enricher = Enricher(self.baseline)
        self.detectors = [
            RateDetector(self.settings),
            RenameDetector(self.settings),
            ExtensionDetector(self.settings, self.baseline.known_extensions()),
            EntropyJumpDetector(self.settings),
            RansomNoteDetector(self.settings),
        ]
        self.scorer = RiskScorer(self.settings)
        self.alerts = AlertManager(config.alerting["cooldown_seconds"])
        self.last_result = None
        self.peak_score = 0

    def handle(self, event: FileEvent) -> list[dict]:
        """Process one event. Returns the records to send to the sinks."""
        self.enricher.process(event)
        for detector in self.detectors:
            detector.observe(event)
        return [event.to_dict()] + self._evaluate(event.epoch)

    def tick(self, now: float | None = None) -> list[dict]:
        """Called when the queue is idle so scores can decay and incidents can close."""
        return self._evaluate(time.time() if now is None else now)

    def _evaluate(self, now: float) -> list[dict]:
        signals = {d.name: d.signal(now) for d in self.detectors}
        result = self.scorer.score(signals)
        self.last_result = result
        self.peak_score = max(self.peak_score, result.score)
        status = self.alerts.update(result.level, now)
        if status is None:
            return []
        return [self._build_alert(status, result, signals).to_dict()]

    def _build_alert(self, status, result, signals) -> Alert:
        window = self.settings["window_seconds"]
        if status == "resolved":
            return Alert("info", result.score, "Activity returned to normal", status, {},
                         {"window_seconds": window, "watched_dir": str(self.config.watch_dir)})

        sample = []
        for sig in signals.values():
            for path in sig.evidence.get("sample_paths", []):
                if path not in sample:
                    sample.append(path)
        evidence = {"sample_paths": sample[:5], "window_seconds": window,
                    "watched_dir": str(self.config.watch_dir)}

        shown = {}
        for name, sig in signals.items():
            detail = {k: v for k, v in sig.evidence.items() if k != "sample_paths"}
            shown[name] = {"value": sig.value, "normalized": round(sig.normalized, 2),
                           "points": result.points[name], **detail}
        return Alert(result.level, result.score, self._message(result, signals, window),
                     status, shown, evidence)

    @staticmethod
    def _message(result, signals, window) -> str:
        ev = {name: sig.evidence for name, sig in signals.items()}
        parts = []
        if "mod_rate" in result.active:
            parts.append(f"{ev['mod_rate']['unique_files']} files touched")
        if "rename_burst" in result.active:
            parts.append(f"{ev['rename_burst']['renames']} renames")
        if "ext_change" in result.active:
            parts.append(f"{ev['ext_change']['files']} files got new extension "
                         f"{ev['ext_change']['new_extension']}")
        if "entropy_jump" in result.active:
            parts.append(f"{ev['entropy_jump']['files']} files became high-entropy")
        if "ransom_note" in result.active:
            parts.append("ransom-note-like files appeared")
        if not parts:
            return "Suspicious file activity"
        return "Ransomware-like behaviour: " + ", ".join(parts) + f" (last {window}s)"