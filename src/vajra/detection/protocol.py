"""Extension protocol for evidence-producing detectors."""

from typing import Protocol

from vajra.alerts.schema import Alert
from vajra.features.extractor import FeatureResult
from vajra.flows.models import FlowSnapshot


class Detector(Protocol):
    """Future detector contract; implementations must return evidence-backed alerts."""

    def evaluate(self, flow: FlowSnapshot, features: FeatureResult) -> tuple[Alert, ...]:
        """Evaluate approved passive features without requiring a handshake or return path."""