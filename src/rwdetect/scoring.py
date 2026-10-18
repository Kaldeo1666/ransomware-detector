from dataclasses import dataclass

LEVEL_ORDER = ["info", "medium", "high", "critical"]
RANK = {name: i for i, name in enumerate(LEVEL_ORDER)}


@dataclass
class ScoreResult:
    score: int
    level: str
    points: dict          # signal name -> points it contributed (0-100 scale)
    active: list          # names of signals at or above the active threshold
    bonus: int            # combination bonus that was added (0 if none)


class RiskScorer:
    def __init__(self, settings: dict):
        self.weights = settings["weights"]
        self.bonus = settings["combo_bonus"]
        self.min_signals = settings["combo_min_signals"]
        self.active_threshold = settings["active_threshold"]
        self.levels = settings["levels"]

    def level_for(self, score: float) -> str:
        if score >= self.levels["critical"]:
            return "critical"
        if score >= self.levels["high"]:
            return "high"
        if score >= self.levels["medium"]:
            return "medium"
        return "info"

    def score(self, signals: dict) -> ScoreResult:
        points = {
            name: round(self.weights[name] * sig.normalized * 100, 1)
            for name, sig in signals.items()
        }
        active = [n for n, sig in signals.items() if sig.normalized >= self.active_threshold]
        bonus = self.bonus if len(active) >= self.min_signals else 0
        total = min(100.0, sum(points.values()) + bonus)
        score = int(round(total))
        return ScoreResult(score, self.level_for(score), points, active, bonus)