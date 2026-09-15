"""Independent alert deduplication and cooldown handling."""

from datetime import datetime, timedelta

from vajra.alerts.schema import Alert


class AlertDeduplicator:
    """Suppress repeated alerts for the same directional detection during a cooldown."""

    def __init__(self, cooldown: timedelta = timedelta(minutes=5)) -> None:
        if cooldown < timedelta(0):
            raise ValueError("cooldown must not be negative")
        self.cooldown = cooldown
        self._last_emitted: dict[tuple[str, str, str], datetime] = {}

    def accept(self, alert: Alert) -> Alert | None:
        """Return an alert only when its detection key is outside the cooldown."""
        key = (alert.flow_id, alert.threat_class, alert.detector_source)
        previous = self._last_emitted.get(key)
        if previous is not None and alert.timestamp - previous < self.cooldown:
            return None
        self._last_emitted[key] = max(alert.timestamp, previous) if previous else alert.timestamp
        return alert

    def filter(self, alerts: list[Alert]) -> tuple[Alert, ...]:
        """Apply cooldown handling to an alert sequence in arrival order."""
        return tuple(accepted for alert in alerts if (accepted := self.accept(alert)) is not None)