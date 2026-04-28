from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EvidenceRecord:
    target: str
    transport: str
    service_hint: str
    payload: dict[str, Any]
    confidence: float


@dataclass(frozen=True)
class ServiceCandidate:
    service_name: str
    confidence: float
    evidence_count: int

    def is_promotable(self) -> bool:
        return self.confidence >= 0.8 and self.evidence_count >= 2

    def display_name(self) -> str:
        return self.service_name if self.is_promotable() else "unknown"
