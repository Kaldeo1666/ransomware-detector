import copy

import pytest

from rwdetect.alerting import AlertManager
from rwdetect.config import DEFAULT_DETECTION, deep_merge, validate_detection
from rwdetect.detectors.base import Signal
from rwdetect.scoring import RiskScorer

S = DEFAULT_DETECTION
NAMES = ["mod_rate", "rename_burst", "ext_change", "entropy_jump", "ransom_note"]


def sigs(**values):
    return {n: Signal(n, 0, values.get(n, 0.0)) for n in NAMES}


def test_nothing_is_zero_info():
    r = RiskScorer(S).score(sigs())
    assert (r.score, r.level, r.bonus) == (0, "info", 0)


def test_everything_maxed_is_capped_at_100():
    r = RiskScorer(S).score(sigs(**{n: 1.0 for n in NAMES}))
    assert r.score == 100 and r.level == "critical"


def test_rate_alone_stays_info():
    r = RiskScorer(S).score(sigs(mod_rate=1.0))
    assert r.score == 25 and r.level == "info"


def test_combo_bonus_needs_three_active_signals():
    two = RiskScorer(S).score(sigs(mod_rate=1.0, rename_burst=1.0))
    three = RiskScorer(S).score(sigs(mod_rate=1.0, rename_burst=1.0, ext_change=1.0))
    assert two.bonus == 0 and two.score == 45
    assert three.bonus == 10 and three.score == 75


def test_level_boundaries():
    s = RiskScorer(S)
    assert [s.level_for(x) for x in (29, 30, 59, 60, 79, 80)] == [
        "info", "medium", "medium", "high", "high", "critical"]


def test_weights_must_sum_to_one():
    bad = copy.deepcopy(S)
    bad["weights"]["mod_rate"] = 0.9
    with pytest.raises(ValueError):
        validate_detection(bad)


def test_unknown_weight_name_rejected():
    bad = deep_merge(S, {})
    bad["weights"]["typo_signal"] = 0.0
    with pytest.raises(ValueError):
        validate_detection(bad)


def test_deep_merge_overrides_only_given_keys():
    merged = deep_merge(S, {"entropy": {"high": 7.0}})
    assert merged["entropy"]["high"] == 7.0
    assert merged["entropy"]["jump_delta"] == 2.0


def test_alert_lifecycle():
    m = AlertManager(cooldown_seconds=30)
    assert m.update("info", 0) is None
    assert m.update("medium", 1) == "open"
    assert m.update("medium", 2) is None          # same level: suppressed
    assert m.update("high", 3) == "escalated"
    assert m.update("medium", 4) is None          # dropping is not re-alerted
    assert m.update("info", 5) is None            # quiet period starts
    assert m.update("info", 20) is None           # still inside cooldown
    assert m.update("medium", 21) is None         # blip: same incident, no new alert
    assert m.update("info", 22) is None
    assert m.update("info", 60) == "resolved"
    assert m.update("medium", 61) == "open"       # a genuinely new incident