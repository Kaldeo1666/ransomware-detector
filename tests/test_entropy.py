import base64
import os

import pytest

from rwdetect.entropy import file_entropy, shannon_entropy


def test_empty_and_constant():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0


def test_two_equal_symbols_is_one_bit():
    assert shannon_entropy(b"ab" * 500) == pytest.approx(1.0)


def test_hand_computed_example():
    # p(A)=5/8, p(B)=3/8 -> about 0.9544 bits per byte
    assert shannon_entropy(b"AAAAABBB") == pytest.approx(0.9544, abs=0.001)


def test_random_bytes_are_near_eight_bits():
    assert shannon_entropy(os.urandom(100_000)) > 7.99


def test_base64_caps_near_six_bits():
    h = shannon_entropy(base64.b64encode(os.urandom(100_000)))
    assert 5.9 < h < 6.01


def test_text_is_much_lower_than_random():
    text = ("the quick brown fox jumps over the lazy dog " * 200).encode()
    assert 3.0 < shannon_entropy(text) < 5.0


def test_missing_file_returns_none(tmp_path):
    assert file_entropy(tmp_path / "nope.bin") is None