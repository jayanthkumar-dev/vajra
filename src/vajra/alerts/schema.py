"""Validated, serializable alert contract for passive detections."""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from math import isfinite
from typing import Final

from vajra.flows.models import FlowKey

EvidenceValue = int | float | str
VALID_SEVERITIES: Final = frozenset({"low", "medium", "high", "critical"})


def severity_for_score(score: float) -> str:
    """Map a deterministic score to severity using fixed, documented score bands."""
    if not isfinite(score) or not 0 <= score <= 1:
        raise ValueError("score must be finite and between 0 and 1")
    if score < 0.5:
        return "low"
    if score < 0.75:
        return "medium"
    if score < 0.9:
        return "high"
    return "critical"


@dataclass(frozen=True, slots=True)
class Alert:
    """A validated alert with evidence and a deterministic score explanation."""

    timestamp: datetime
    flow: FlowKey
    threat_class: str
    score: float
    severity: str
    evidence: dict[str, int | float | str]
    explanation: str
    detection_method: str = "rule"
    alert_id: str = ""
    detector_source: str = "unspecified"
    feature_values: dict[str, int | float | str] | None = None
    score_method: str = "matched_signals_fraction"

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp, datetime) or self.timestamp.tzinfo is None:
            raise ValueError("alert timestamp must be timezone-aware")
        if not self.threat_class.strip():
            raise ValueError("threat_class must not be empty")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        if self.severity != severity_for_score(self.score):
            raise ValueError("severity does not match the configured score mapping")
        if not self.detector_source.strip():
            raise ValueError("detector_source must not be empty")
        if not self.detection_method.strip():
            raise ValueError("detection_method must not be empty")
        if not self.score_method.strip():
            raise ValueError("score_method must not be empty")
        if not self.explanation.strip():
            raise ValueError("explanation must not be empty")
        if not self.evidence:
            raise ValueError("supporting evidence is required")
        feature_values = self.feature_values or {}
        if not feature_values:
            raise ValueError("relevant feature values are required")
        object.__setattr__(self, "feature_values", dict(feature_values))
        if not self.alert_id:
            object.__setattr__(self, "alert_id", self._build_id())
        else:
            try:
                valid_id = len(self.alert_id) == 64 and int(self.alert_id, 16) >= 0
            except ValueError:
                valid_id = False
            if not valid_id:
                raise ValueError("alert_id must be a SHA-256 hexadecimal identifier")

    @property
    def flow_id(self) -> str:
        """Return the directional flow identifier associated with this alert."""
        return self.flow.flow_id

    def _build_id(self) -> str:
        identity = {
            "timestamp": self.timestamp.isoformat(),
            "flow_id": self.flow_id,
            "threat_class": self.threat_class,
            "detector_source": self.detector_source,
            "evidence": self.evidence,
            "feature_values": self.feature_values,
        }
        serialized = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible alert representation."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "alert_id": self.alert_id,
            "flow_id": self.flow_id,
            "flow": {
                "source_ip": self.flow.source_ip,
                "destination_ip": self.flow.destination_ip,
                "protocol": self.flow.protocol,
                "source_port": self.flow.source_port,
                "destination_port": self.flow.destination_port,
            },
            "threat_class": self.threat_class,
            "severity": self.severity,
            "score": self.score,
            "score_method": self.score_method,
            "detector_source": self.detector_source,
            "detection_method": self.detection_method,
            "evidence": self.evidence,
            "feature_values": self.feature_values,
            "explanation": self.explanation,
        }

    def to_json(self) -> str:
        """Serialize the alert deterministically as JSON."""
        return json.dumps(self.to_dict(), sort_keys=True)