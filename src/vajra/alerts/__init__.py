"""Independent validated alert schema and cooldown handling."""

from vajra.alerts.deduplication import AlertDeduplicator
from vajra.alerts.schema import Alert, severity_for_score

__all__ = ["Alert", "AlertDeduplicator", "severity_for_score"]