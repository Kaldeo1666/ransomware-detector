import fnmatch
import os
from dataclasses import dataclass

from rwdetect.entropy import file_entropy


@dataclass
class FileRecord:
    entropy: float
    size: int
    ext: str
    mtime: float


def norm(path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def measure(path) -> FileRecord | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    entropy = file_entropy(path)
    if entropy is None:
        return None
    ext = os.path.splitext(str(path))[1].lower()
    return FileRecord(entropy, st.st_size, ext, st.st_mtime)


class BaselineIndex:
    """Remembers what each file looked like BEFORE any suspicious activity."""

    def __init__(self):
        self._items: dict[str, FileRecord] = {}

    def __len__(self) -> int:
        return len(self._items)

    def get(self, path) -> FileRecord | None:
        return self._items.get(norm(path))

    def put(self, path, record: FileRecord) -> None:
        self._items[norm(path)] = record

    def remove(self, path) -> None:
        self._items.pop(norm(path), None)

    def known_extensions(self) -> set[str]:
        return {r.ext for r in self._items.values() if r.ext}

    def scan(self, root, ignore_patterns=(), ignore_dirs=()) -> int:
        skip = {d.lower() for d in ignore_dirs}
        count = 0
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d.lower() not in skip]
            for name in files:
                if any(fnmatch.fnmatch(name, pat) for pat in ignore_patterns):
                    continue
                full = os.path.join(dirpath, name)
                record = measure(full)
                if record is not None:
                    self._items[norm(full)] = record
                    count += 1
        return count