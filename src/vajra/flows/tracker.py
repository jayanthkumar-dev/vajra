"""Incremental directional flow tracking."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address
from numbers import Real
from typing import Final

from vajra.flows.models import FlowKey, FlowSnapshot
from vajra.ingestion.models import PacketObservation


@dataclass(slots=True)
class _MutableFlow:
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 0
    byte_count: int = 0


class FlowTracker:
    """Maintain directional counters as observations arrive."""

    DEFAULT_INACTIVITY_TIMEOUT: Final = timedelta(minutes=5)
    DEFAULT_MAX_FLOWS: Final = 10_000

    def __init__(
        self,
        inactivity_timeout: timedelta | Real = DEFAULT_INACTIVITY_TIMEOUT,
        max_flows: int = DEFAULT_MAX_FLOWS,
    ) -> None:
        if isinstance(inactivity_timeout, Real):
            inactivity_timeout = timedelta(seconds=float(inactivity_timeout))
        if inactivity_timeout <= timedelta(0):
            raise ValueError("inactivity_timeout must be positive")
        if not isinstance(max_flows, int) or isinstance(max_flows, bool) or max_flows < 1:
            raise ValueError("max_flows must be a positive integer")
        self.inactivity_timeout = inactivity_timeout
        self.max_flows = max_flows
        self._flows: dict[FlowKey, _MutableFlow] = {}

    def observe(self, observation: PacketObservation) -> FlowSnapshot:
        """Add one observation and return the updated directional snapshot."""
        self._validate_observation(observation)
        self._evict_stale(observation.timestamp)
        key = FlowKey.from_observation(observation)
        flow = self._flows.setdefault(
            key,
            _MutableFlow(observation.timestamp, observation.timestamp),
        )
        flow.last_seen = max(flow.last_seen, observation.timestamp)
        flow.first_seen = min(flow.first_seen, observation.timestamp)
        flow.packet_count += 1
        flow.byte_count += observation.packet_length or 0
        self._enforce_capacity()
        return FlowSnapshot(
            key=key,
            first_seen=flow.first_seen,
            last_seen=flow.last_seen,
            packet_count=flow.packet_count,
            byte_count=flow.byte_count,
        )

    def snapshot(self) -> tuple[FlowSnapshot, ...]:
        """Return current flows without inferring reverse-direction traffic."""
        return tuple(
            FlowSnapshot(
                key=key,
                first_seen=flow.first_seen,
                last_seen=flow.last_seen,
                packet_count=flow.packet_count,
                byte_count=flow.byte_count,
            )
            for key, flow in self._flows.items()
        )

    def _evict_stale(self, observed_at: datetime) -> None:
        cutoff = observed_at - self.inactivity_timeout
        stale_keys = [key for key, flow in self._flows.items() if flow.last_seen < cutoff]
        for key in stale_keys:
            del self._flows[key]

    def _enforce_capacity(self) -> None:
        while len(self._flows) > self.max_flows:
            oldest_key = min(self._flows, key=lambda key: self._flows[key].last_seen)
            del self._flows[oldest_key]

    @staticmethod
    def _validate_observation(observation: PacketObservation) -> None:
        if not isinstance(observation, PacketObservation):
            raise ValueError("observation must be a PacketObservation")
        if not isinstance(observation.timestamp, datetime):
            raise ValueError("observation timestamp must be a datetime")
        if observation.timestamp.tzinfo is None:
            raise ValueError("observation timestamp must be timezone-aware")
        for field_name in ("source_ip", "destination_ip"):
            value = getattr(observation, field_name)
            try:
                ip_address(value)
            except (TypeError, ValueError) as error:
                raise ValueError(f"{field_name} must be a valid IP address") from error
        if not isinstance(observation.protocol, str) or not observation.protocol:
            raise ValueError("observation protocol must be a non-empty string")
        for field_name in ("source_port", "destination_port"):
            port = getattr(observation, field_name)
            if port is not None and (not isinstance(port, int) or not 0 <= port <= 65535):
                raise ValueError(f"{field_name} must be a port between 0 and 65535")
        if observation.packet_length is not None and (
            not isinstance(observation.packet_length, int) or observation.packet_length < 0
        ):
            raise ValueError("packet_length must be a non-negative integer")