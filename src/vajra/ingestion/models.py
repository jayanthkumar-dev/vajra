"""Observation models containing metadata available from one-way traffic."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class PacketObservation:
    """One observed packet record; payload bytes are deliberately excluded."""

    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    ip_version: int = 0
    source_port: int | None = None
    destination_port: int | None = None
    packet_length: int | None = None
    tcp_flags: int | None = None
    dns_query: str | None = None
    dns_record_type: str | None = None
    tls_handshake_type: str | None = None
    tls_fingerprint: str | None = None
    quic_handshake_type: str | None = None
    quic_fingerprint: str | None = None
