"""Controlled synthetic/lab PCAP helpers for the SIH demonstration."""

import struct
from datetime import UTC, datetime
from pathlib import Path

_PCAP_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def write_udp_pcap(
    path: str | Path,
    *,
    packet_count: int,
    start_second: int = 1_700_000_000,
    interval_microseconds: int = 10_000,
    source_ip: bytes = b"\xc0\x00\x02\x10",
    destination_ip: bytes = b"\xc6\x33\x64\x20",
    source_port: int = 40000,
    destination_port: int = 53,
    payload_size: int = 200,
    flow_count: int = 1,
    intervals_microseconds: list[int] | None = None,
) -> Path:
    """Write a deterministic Ethernet/IPv4/UDP lab capture without sending traffic."""
    if packet_count < 1 or payload_size < 0 or flow_count < 1:
        raise ValueError(
            "packet_count and flow_count must be positive and payload_size must not be negative"
        )
    if intervals_microseconds is not None and len(intervals_microseconds) < packet_count:
        raise ValueError("intervals_microseconds must contain one interval per packet")
    def packet_for(index: int) -> bytes:
        transport = struct.pack(
            "!HHHH", source_port, destination_port + (index % flow_count), 8 + payload_size, 0
        )
        ip_total_length = 20 + len(transport) + payload_size
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_total_length,
            1,
            0,
            64,
            17,
            0,
            source_ip,
            destination_ip,
        )
        return (
            b"\x00" * 12
            + struct.pack("!H", 0x0800)
            + ip_header
            + transport
            + b"x" * payload_size
        )
    offsets: list[int] = []
    elapsed_microseconds = 0
    for index in range(packet_count):
        offsets.append(elapsed_microseconds)
        elapsed_microseconds += (
            intervals_microseconds[index]
            if intervals_microseconds is not None
            else interval_microseconds
        )
    records = b"".join(
        struct.pack(
            "<IIII",
            start_second + offsets[index] // 1_000_000,
            offsets[index] % 1_000_000,
            len(packet_for(index)),
            len(packet_for(index)),
        )
        + packet_for(index)
        for index in range(packet_count)
    )
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_PCAP_HEADER + records)
    return output


def write_tcp_pcap(
    path: str | Path,
    *,
    packet_count: int,
    start_second: int = 1_700_000_000,
    interval_microseconds: int = 10_000,
    source_ip: bytes = b"\xc0\x00\x02\x10",
    destination_ip: bytes = b"\xc6\x33\x64\x20",
    source_port: int = 40000,
    destination_port: int = 443,
    payload_size: int = 20,
) -> Path:
    """Write TCP-shaped lab records; handshake state is never required."""
    if packet_count < 1 or payload_size < 0:
        raise ValueError("packet_count must be positive and payload_size must not be negative")
    tcp_header = struct.pack("!HHIIHHHH", source_port, destination_port, 0, 0, 0x5010, 65535, 0, 0)
    ip_total_length = 20 + len(tcp_header) + payload_size
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_length,
        1,
        0,
        64,
        6,
        0,
        source_ip,
        destination_ip,
    )
    packet = b"\x00" * 12 + struct.pack("!H", 0x0800) + ip_header + tcp_header + b"t" * payload_size
    records = b"".join(
        struct.pack(
            "<IIII",
            start_second + (index * interval_microseconds) // 1_000_000,
            (index * interval_microseconds) % 1_000_000,
            len(packet),
            len(packet),
        )
        + packet
        for index in range(packet_count)
    )
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_PCAP_HEADER + records)
    return output


def iso_timestamp(second: int) -> str:
    """Format a lab capture timestamp for human-readable reports."""
    return datetime.fromtimestamp(second, tz=UTC).isoformat()