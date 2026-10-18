from collections import Counter, deque
from dataclasses import dataclass, field


@dataclass
class Signal:
    name: str
    value: float          # the raw measurement (a count, a rate, ...)
    normalized: float     # 0.0 (nothing) to 1.0 (maximum suspicion)
    evidence: dict = field(default_factory=dict)


def normalize(value: float, maximum: float) -> float:
    if maximum <= 0:
        return 0.0
    return max(0.0, min(1.0, value / maximum))


class SlidingWindow:
    """Remembers (time, key, value) items from the last `seconds` seconds.

    Time is always passed in, never read from the clock, so tests can use fake time.
    """

    def __init__(self, seconds: float):
        self.seconds = seconds
        self._items: deque = deque()
        self._counts: Counter = Counter()

    def add(self, ts: float, key: str, value: float = 0.0) -> None:
        self._items.append((ts, key, value))
        self._counts[key] += 1

    def _evict(self, now: float) -> None:
        cutoff = now - self.seconds
        while self._items and self._items[0][0] <= cutoff:
            _, key, _ = self._items.popleft()
            self._counts[key] -= 1
            if self._counts[key] == 0:
                del self._counts[key]

    def unique(self, now: float) -> int:
        self._evict(now)
        return len(self._counts)

    def total(self, now: float) -> int:
        self._evict(now)
        return len(self._items)

    def sample(self, now: float, n: int = 5) -> list[str]:
        self._evict(now)
        return list(self._counts)[:n]

    def values(self, now: float) -> list[float]:
        self._evict(now)
        return [value for _, _, value in self._items]