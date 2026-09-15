"""Incremental, read-only parsing of classic PCAP files."""

import ipaddress
import logging
import struct
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import BinaryIO

from vajra.ingestion.models import PacketObservation

LOGGER = logging.getLogger(__name__)

_GLOBAL_HEADER_LENGTH = 24
_RECORD_HEADER_LENGTH = 16
_ETHERNET_LINKTYPE = 1
_RAW_IPV4_LINKTYPE = 101
_MAX_PACKET_BYTES = 16 * 1024 * 1024
_ETHERNET_HEADER_LENGTH = 14
_VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
_IP_PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}
_IPV6_EXTENSION_HEADERS = {0, 43, 44, 51, 60}


def read_pcap(path: str | Path) -> Iterator[PacketObservation]:
    """Yield supported packet metadata from a classic PCAP one record at a time.

    Unsupported link-layer packets and malformed records are skipped with a warning.
    No packet bytes are transmitted, retained after parsing, or passed to detection.
    """
    with Path(path).open("rb") as capture:
        yield from _read_capture(capture)


def _read_capture(capture: BinaryIO) -> Iterator[PacketObservation]:
    header = capture.read(_GLOBAL_HEADER_LENGTH)
    if len(header) == 0:
        return
    if len(header) != _GLOBAL_HEADER_LENGTH:
        LOGGER.warning("Ignoring truncated PCAP global header")
        return

    byte_order, timestamp_scale, link_type = _parse_global_header(header)
    if byte_order is None:
        LOGGER.warning("Ignoring unsupported or malformed PCAP global header")
        return

    while True:
        record_header = capture.read(_RECORD_HEADER_LENGTH)
        if len(record_header) == 0:
            return
        if len(record_header) != _RECORD_HEADER_LENGTH:
            LOGGER.warning("Ignoring truncated PCAP record header")
            return

        timestamp_seconds, timestamp_fraction, captured_length, original_length = struct.unpack(
            f"{byte_order}IIII", record_header
        )
        if captured_length > _MAX_PACKET_BYTES:
            LOGGER.warning("Skipping oversized PCAP record: %d bytes", captured_length)
            capture.seek(captured_length, 1)
            continue

        packet = capture.read(captured_length)
        if len(packet) != captured_length:
            LOGGER.warning("Ignoring truncated PCAP packet")
            return

        try:
            observation = _parse_packet(
                packet,
                link_type=link_type,
                timestamp=_packet_timestamp(timestamp_seconds, timestamp_fraction, timestamp_scale),
                packet_length=original_length or captured_length,
            )
        except (ValueError, IndexError, struct.error) as error:
            LOGGER.warning("Skipping malformed PCAP packet: %s", error)
            continue
        if observation is not None:
            yield observation


def _parse_global_header(header: bytes) -> tuple[str | None, float, int]:
    magic = header[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
        b"\xa1\xb2\xc3\xd4": (">", 1e-6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
        b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    }
    format_info = formats.get(magic)
    if format_info is None:
        return None, 0.0, 0
    byte_order, timestamp_scale = format_info
    link_type = struct.unpack_from(f"{byte_order}I", header, 20)[0]
    return byte_order, timestamp_scale, link_type


def _packet_timestamp(seconds: int, fraction: int, scale: float) -> datetime:
    microseconds = int(fraction * scale * 1_000_000)
    return datetime.fromtimestamp(seconds, tz=UTC) + timedelta(microseconds=microseconds)


def _parse_packet(
    packet: bytes,
    *,
    link_type: int,
    timestamp: datetime,
    packet_length: int,
) -> PacketObservation | None:
    if link_type == _ETHERNET_LINKTYPE:
        ip_packet = _extract_ethernet_payload(packet)
    elif link_type == _RAW_IPV4_LINKTYPE:
        ip_packet = packet
    else:
        LOGGER.warning("Skipping unsupported link type: %d", link_type)
        return None

    if not ip_packet:
        return None
    version = ip_packet[0] >> 4
    if version == 4:
        source_ip, destination_ip, protocol_number, transport = _parse_ipv4(ip_packet)
    elif version == 6:
        source_ip, destination_ip, protocol_number, transport = _parse_ipv6(ip_packet)
    else:
        raise ValueError("unsupported IP version")

    source_port, destination_port = _extract_ports(protocol_number, transport)
    return PacketObservation(
        timestamp=timestamp,
        ip_version=version,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=_protocol_name(protocol_number),
        source_port=source_port,
        destination_port=destination_port,
        packet_length=packet_length,
    )


def _extract_ethernet_payload(packet: bytes) -> bytes:
    if len(packet) < _ETHERNET_HEADER_LENGTH:
        raise ValueError("truncated Ethernet header")
    ether_type = struct.unpack_from("!H", packet, 12)[0]
    offset = _ETHERNET_HEADER_LENGTH
    while ether_type in _VLAN_TYPES:
        if len(packet) < offset + 4:
            raise ValueError("truncated VLAN header")
        ether_type = struct.unpack_from("!H", packet, offset + 2)[0]
        offset += 4
    if ether_type not in (0x0800, 0x86DD):
        return b""
    return packet[offset:]


def _parse_ipv4(packet: bytes) -> tuple[str, str, int, bytes]:
    if len(packet) < 20:
        raise ValueError("truncated IPv4 header")
    version_and_length, _, _, _, _, _, protocol = struct.unpack_from("!BBHHHBB", packet, 0)
    header_length = (version_and_length & 0x0F) * 4
    if version_and_length >> 4 != 4 or header_length < 20 or len(packet) < header_length:
        raise ValueError("malformed IPv4 header")
    source = str(ipaddress.IPv4Address(packet[12:16]))
    destination = str(ipaddress.IPv4Address(packet[16:20]))
    return source, destination, protocol, packet[header_length:]


def _parse_ipv6(packet: bytes) -> tuple[str, str, int, bytes]:
    if len(packet) < 40 or packet[0] >> 4 != 6:
        raise ValueError("malformed IPv6 header")
    source = str(ipaddress.IPv6Address(packet[8:24]))
    destination = str(ipaddress.IPv6Address(packet[24:40]))
    protocol = packet[6]
    offset = 40
    while protocol in _IPV6_EXTENSION_HEADERS:
        if protocol == 44:
            if len(packet) < offset + 8:
                raise ValueError("truncated IPv6 fragment header")
            fragment_offset = struct.unpack_from("!H", packet, offset + 2)[0] >> 3
            protocol = packet[offset]
            offset += 8
            if fragment_offset:
                return source, destination, protocol, b""
            continue
        if len(packet) < offset + 2:
            raise ValueError("truncated IPv6 extension header")
        next_protocol = packet[offset]
        extension_length = (packet[offset + 1] + 1) * 8
        if protocol == 51:
            extension_length = (packet[offset + 1] + 2) * 4
        if len(packet) < offset + extension_length:
            raise ValueError("truncated IPv6 extension header")
        protocol = next_protocol
        offset += extension_length
    return source, destination, protocol, packet[offset:]


def _extract_ports(protocol: int, transport: bytes) -> tuple[int | None, int | None]:
    if protocol not in (6, 17) or len(transport) < 4:
        return None, None
    return struct.unpack_from("!HH", transport, 0)


def _protocol_name(protocol: int) -> str:
    return _IP_PROTOCOL_NAMES.get(protocol, f"IPPROTO_{protocol}")