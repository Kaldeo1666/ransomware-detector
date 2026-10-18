import socket
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"
SOURCE = "ransomware-detector"
HOST = socket.gethostname()
MITRE = {"tactic": "Impact", "technique": "T1486", "name": "Data Encrypted for Impact"}


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
    entropy: float | None = None          # filled in by the Enricher
    entropy_delta: float | None = None    # entropy now minus baseline entropy
    timestamp: str = field(default_factory=utc_now_iso)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    epoch: float = field(default_factory=time.time, repr=False)  # numeric time for windows

    def to_dict(self) -> dict:
        record = asdict(self)
        record.pop("epoch", None)
        record.update(
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            host=HOST,
            event_type="file_event",
        )
        return record

@dataclass
class Alert:
    severity: str                     # info | medium | high | critical
    risk_score: int
    message: str
    status: str                       # open | escalated | resolved
    signals: dict
    evidence: dict
    rule_id: str = "RW-COMPOSITE-001"
    mitre: dict = field(default_factory=lambda: dict(MITRE))
    timestamp: str = field(default_factory=utc_now_iso)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        record = asdict(self)
        record.update(
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            host=HOST,
            event_type="alert",
        )
        return record