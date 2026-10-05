from typing import Protocol


class Sink(Protocol):
    def emit(self, record: dict) -> None:
        """Deliver one record. Must never crash the pipeline."""
        ...

    def close(self) -> None:
        """Release resources (files, connections)."""
        ...