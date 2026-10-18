from rwdetect.scoring import RANK


class AlertManager:
    """Turns a stream of risk levels into a few meaningful alerts.

    - The first time the level reaches 'medium' or above: status 'open'.
    - If the level later goes HIGHER than any level seen so far: 'escalated'.
    - Same or lower level while the incident is open: suppressed (no new alert).
    - When the level has stayed at 'info' for `cooldown_seconds`: 'resolved'.
    """

    def __init__(self, cooldown_seconds: float):
        self.cooldown = cooldown_seconds
        self.open = False
        self.max_rank = 0
        self.quiet_since: float | None = None
        self.suppressed = 0

    def update(self, level: str, now: float) -> str | None:
        rank = RANK[level]
        if rank >= 1:
            self.quiet_since = None
            if not self.open:
                self.open = True
                self.max_rank = rank
                return "open"
            if rank > self.max_rank:
                self.max_rank = rank
                return "escalated"
            self.suppressed += 1
            return None

        if self.open:
            if self.quiet_since is None:
                self.quiet_since = now
            elif now - self.quiet_since >= self.cooldown:
                self.open = False
                self.max_rank = 0
                self.quiet_since = None
                return "resolved"
        return None