"""Flow models that preserve observation direction."""

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256

from vajra.ingestion.models import PacketObservation


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Directional identity; reverse traffic is never inferred."""

    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | None
    destination_port: int | None

    @property
    def flow_id(self) -> str:
        """Return a stable identifier that retains the observed direction."""
        value = "|".join(
            (
                self.source_ip,
                self.destination_ip,
                self.protocol,
                str(self.source_port),
                str(self.destination_port),
            )
        )
        return sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def from_observation(cls, observation: PacketObservation) -> "FlowKey":
        return cls(
            observation.source_ip,
            observation.destination_ip,
            observation.protocol,
            observation.source_port,
            observation.destination_port,
        )


@dataclass(frozen=True, slots=True)
class FlowSnapshot:
    """Current counters for a directional flow."""

    key: FlowKey
    first_seen: datetime
    last_seen: datetime
    packet_count: int
    byte_count: int

    @property
    def flow_id(self) -> str:
        """Return the deterministic identifier for this flow."""
        return self.key.flow_id

    @property
    def duration(self):
        """Return the observed duration between the first and last packet."""
        return self.last_seen - self.first_seen