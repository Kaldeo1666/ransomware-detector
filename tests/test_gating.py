import pytest

from rwdetect.config import DEFAULT_DETECTION, deep_merge, validate_detection
from rwdetect.detectors.base import Signal
from rwdetect.scoring import RiskScorer

NAMES = ["mod_rate", "rename_burst", "ext_change", "entropy_jump", "ransom_note"]
GATED = deep_merge(DEFAULT_DETECTION, {"gate_signals": ["entropy_jump", "ransom_note"]})


def sigs(**values):
    return {n: Signal(n, 0, values.get(n, 0.0)) for n in NAMES}


def test_volume_signals_alone_are_capped_below_medium():
    r = RiskScorer(GATED).score(sigs(mod_rate=1.0, rename_burst=1.0))
    assert r.gated is True
    assert r.score == 29 and r.level == "info"


def test_without_gating_the_same_signals_reach_medium():
    r = RiskScorer(DEFAULT_DETECTION).score(sigs(mod_rate=1.0, rename_burst=1.0))
    assert r.gated is False
    assert r.score == 45 and r.level == "medium"


def test_a_new_extension_alone_does_not_open_the_gate():
    r = RiskScorer(GATED).score(sigs(mod_rate=1.0, rename_burst=1.0, ext_change=1.0))
    assert r.gated is True and r.level == "info"


def test_entropy_evidence_opens_the_gate():
    r = RiskScorer(GATED).score(sigs(mod_rate=1.0, rename_burst=1.0, entropy_jump=0.4))
    assert r.gated is False
    assert r.level in ("medium", "high")


def test_gate_never_lowers_a_score_that_is_already_low():
    r = RiskScorer(GATED).score(sigs(mod_rate=0.2))
    assert r.gated is False
    assert r.score == 5


def test_unknown_gate_name_is_rejected():
    bad = deep_merge(DEFAULT_DETECTION, {"gate_signals": ["entropy_jmp"]})
    with pytest.raises(ValueError):
        validate_detection(bad)