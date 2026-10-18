import pytest

from rwdetect.config import DEFAULT_DETECTION as S
from rwdetect.detectors.base import SlidingWindow, normalize
from rwdetect.detectors.entropy_jump import EntropyJumpDetector
from rwdetect.detectors.extension import ExtensionDetector
from rwdetect.detectors.note import RansomNoteDetector
from rwdetect.detectors.rate import RateDetector
from rwdetect.detectors.rename import RenameDetector
from rwdetect.models import FileEvent


def ev(action, path, t, dest=None, entropy=None, delta=None, size=2000):
    return FileEvent(action, path, dest, size=size, entropy=entropy,
                     entropy_delta=delta, epoch=t)


def test_normalize_clamps():
    assert normalize(5, 10) == 0.5
    assert normalize(50, 10) == 1.0
    assert normalize(-1, 10) == 0.0
    assert normalize(5, 0) == 0.0


def test_window_evicts_old_items():
    w = SlidingWindow(10)
    w.add(0, "a")
    assert w.unique(9.9) == 1
    assert w.unique(10) == 0


def test_window_counts_same_key_once():
    w = SlidingWindow(10)
    for t in (1, 2, 3):
        w.add(t, "same")
    assert w.unique(5) == 1
    assert w.total(5) == 3


def test_rate_counts_unique_files_not_events():
    d = RateDetector(S)
    for i in range(100):
        d.observe(ev("modified", "same.txt", 1 + i * 0.01))
    assert d.signal(3).normalized == pytest.approx(1 / 30)


def test_rate_reaches_max_with_many_files():
    d = RateDetector(S)
    for i in range(30):
        d.observe(ev("created", f"f{i}.txt", 1 + i * 0.01))
    assert d.signal(2).normalized == 1.0


def test_rate_signal_decays_as_window_slides():
    d = RateDetector(S)
    for i in range(30):
        d.observe(ev("created", f"f{i}.txt", 1.0))
    assert d.signal(2).normalized == 1.0
    assert d.signal(30).normalized == 0.0


def test_rename_counts_moved_events():
    d = RenameDetector(S)
    for i in range(15):
        d.observe(ev("moved", f"a{i}.txt", 1.0, dest=f"b{i}.txt"))
    d.observe(ev("created", "x.txt", 1.0))
    assert d.signal(2).value == 15
    assert d.signal(2).normalized == 1.0


def test_extension_flags_many_files_with_new_extension():
    d = ExtensionDetector(S)
    for i in range(10):
        d.observe(ev("moved", f"a{i}.txt", 1.0, dest=f"a{i}.txt.locked"))
    sig = d.signal(2)
    assert sig.evidence["new_extension"] == ".locked"
    assert sig.normalized == 1.0


def test_extension_catches_copy_delete_style_creates():
    d = ExtensionDetector(S)
    for i in range(10):
        d.observe(ev("created", f"a{i}.txt.locked", 1.0))
    assert d.signal(2).normalized == 1.0


def test_extension_ignores_known_extensions():
    d = ExtensionDetector(S)
    for i in range(20):
        d.observe(ev("moved", f"a{i}.txt", 1.0, dest=f"b{i}.md"))
    assert d.signal(2).normalized == 0.0


def test_extension_uses_baseline_extensions_as_known():
    d = ExtensionDetector(S, known_extensions={".weird"})
    for i in range(10):
        d.observe(ev("created", f"a{i}.weird", 1.0))
    assert d.signal(2).normalized == 0.0


def test_entropy_detector_counts_unique_files():
    d = EntropyJumpDetector(S)
    for i in range(10):
        d.observe(ev("modified", f"a{i}.txt", 1.0, entropy=7.9, delta=3.5))
    sig = d.signal(2)
    assert sig.normalized == 1.0
    assert sig.evidence["avg_delta"] == pytest.approx(3.5)


def test_ransom_note_detector():
    d = RansomNoteDetector(S)
    d.observe(ev("created", "docs/README_RESTORE_FILES.txt", 1.0))
    d.observe(ev("created", "photos/HOW_TO_DECRYPT.html", 1.0))
    d.observe(ev("created", "notes.txt", 1.0))
    assert d.signal(2).value == 2