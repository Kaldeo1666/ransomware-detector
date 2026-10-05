import socket
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"
SOURCE = "ransomware-detector"
HOST = socket.gethostname()


def utc_now_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class FileEvent:
    action: str                       # created | modified | deleted | moved
    path: str
    dest_path: str | None = None      # only set for "moved"
    is_directory: bool = False
    size: int | None = None
    entropy: float | None = None      # filled in on Day 4
    timestamp: str = field(default_factory=utc_now_iso)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        record = asdict(self)
        record.update(
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            host=HOST,
            event_type="file_event",
        )
        return record