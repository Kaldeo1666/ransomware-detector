import json
from pathlib import Path


class JsonlSink:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.path, "a", encoding="utf-8")

    def emit(self, record: dict) -> None:
        self._file.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()