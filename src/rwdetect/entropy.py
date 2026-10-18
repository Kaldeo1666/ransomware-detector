import math
import os
import sys
from collections import Counter
from pathlib import Path

SAMPLE_CHUNK = 64 * 1024


def shannon_entropy(data: bytes) -> float:
    """Bits of entropy per byte: 0.0 (all identical) to 8.0 (uniformly random)."""
    if not data:
        return 0.0
    n = len(data)
    return max(0.0, -sum((c / n) * math.log2(c / n) for c in Counter(data).values()))


def read_sample(path, chunk: int = SAMPLE_CHUNK) -> bytes:
    with open(path, "rb") as f:
        sample = f.read(chunk)
        size = os.fstat(f.fileno()).st_size
        if size > 3 * chunk:
            f.seek(size // 2)
            sample += f.read(chunk)
    return sample


def file_entropy(path) -> float | None:
    try:
        return shannon_entropy(read_sample(path))
    except OSError:
        return None


def main() -> None:
    for name in sys.argv[1:]:
        h = file_entropy(name)
        if h is None:
            print(f"{name:55} unreadable")
        else:
            print(f"{name:55} {Path(name).stat().st_size:>10} bytes   {h:.3f} bits/byte")


if __name__ == "__main__":
    main()