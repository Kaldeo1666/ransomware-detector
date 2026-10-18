from rwdetect.config import DEFAULT_DETECTION as S
from rwdetect.detectors.entropy_jump import classify
from rwdetect.models import FileEvent


def ev(action, path, t, dest=None, entropy=None, delta=None, size=2000):
    return FileEvent(action, path, dest, size=size, entropy=entropy,
                     entropy_delta=delta, epoch=t)


def test_classify_jump_for_text_turned_random():
    assert classify(ev("modified", "a.txt", 1, entropy=7.9, delta=3.4), S) == "jump"


def test_classify_ignores_normal_text_edit():
    assert classify(ev("modified", "a.txt", 1, entropy=4.3, delta=0.1), S) is None


def test_classify_new_high_entropy_unknown_extension():
    assert classify(ev("created", "a.txt.locked", 1, entropy=7.9), S) == "new_high"


def test_classify_new_zip_is_not_suspicious_by_itself():
    assert classify(ev("created", "photos.zip", 1, entropy=7.9), S) is None


def test_classify_already_high_file_encrypted_has_small_jump():
    # the honest limitation: zip 7.7 -> encrypted 7.95 is only +0.25
    assert classify(ev("moved", "a.zip", 1, dest="a.zip.locked", entropy=7.95, delta=0.25), S) is None


def test_classify_ignores_tiny_files():
    assert classify(ev("modified", "a.txt", 1, entropy=7.9, delta=3.4, size=100), S) is None