import struct
from datetime import UTC, datetime

from vajra.ingestion import read_pcap


def _pcap(records: list[tuple[int, int, bytes, int | None]] = []) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = bytearray(header)
    for seconds, microseconds, packet, original_length in records:
        body.extend(
            struct.pack(
                "<IIII",
                seconds,
                microseconds,
                len(packet),
                original_length if original_length is not None else len(packet),
            )
        )
        body.extend(packet)
    return bytes(body)


def _ethernet(payload: bytes, ether_type: int = 0x0800) -> bytes:
    return b"\x00" * 12 + struct.pack("!H", ether_type) + payload


def _ipv4(protocol: int, source: bytes, destination: bytes, transport: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(transport),
        1,
        0,
        64,
        protocol,
        0,
        source,
        destination,
    )
    return header + transport


def _ipv6(protocol: int, source: bytes, destination: bytes, transport: bytes) -> bytes:
    header = struct.pack(
        "!IHBB16s16s",
        0x60000000,
        len(transport),
        protocol,
        64,
        source,
        destination,
    )
    return header + transport


def _tcp(source_port: int, destination_port: int, flags: int = 0) -> bytes:
    return struct.pack(
        "!HHIIHHHH", source_port, destination_port, 0, 0, 0x5000 | flags, 65535, 0, 0
    )


def _udp(source_port: int, destination_port: int) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8, 0)


def _write_capture(tmp_path, content: bytes):
    path = tmp_path / "controlled-lab.pcap"
    path.write_bytes(content)
    return path


def test_parses_ipv4_tcp_without_handshake_and_preserves_timestamp(tmp_path):
    packet = _ethernet(
        _ipv4(
            6,
            b"\xc0\x00\x02\x0a",
            b"\xc6\x33\x64\x14",
            _tcp(40000, 443),
        )
    )
    path = _write_capture(tmp_path, _pcap([(1700000000, 123456, packet, 99)]))

    observations = list(read_pcap(path))

    assert len(observations) == 1
    observation = observations[0]
    expected_timestamp = datetime.fromtimestamp(1700000000, UTC).replace(microsecond=123456)
    assert observation.timestamp == expected_timestamp
    assert observation.ip_version == 4
    assert observation.source_ip == "192.0.2.10"
    assert observation.destination_ip == "198.51.100.20"
    assert observation.protocol == "TCP"
    assert observation.source_port == 40000
    assert observation.destination_port == 443
    assert observation.packet_length == 99


def test_parses_ipv4_udp(tmp_path):
    packet = _ethernet(_ipv4(17, b"\xcb\x00\x71\x01", b"\xcb\x00\x71\x02", _udp(53000, 53)))
    path = _write_capture(tmp_path, _pcap([(1700000001, 0, packet, None)]))

    observation = next(read_pcap(path))

    assert observation.protocol == "UDP"
    assert observation.source_port == 53000
    assert observation.destination_port == 53
    assert observation.packet_length == len(packet)


def test_parses_ipv6_and_extracts_transport_ports(tmp_path):
    packet = _ethernet(
        _ipv6(
            17,
            bytes.fromhex("20010db8000000000000000000000001"),
            bytes.fromhex("20010db8000000000000000000000002"),
            _udp(5353, 5353),
        ),
        ether_type=0x86DD,
    )
    path = _write_capture(tmp_path, _pcap([(1700000002, 1, packet, None)]))

    observation = next(read_pcap(path))

    assert observation.ip_version == 6
    assert observation.source_ip == "2001:db8::1"
    assert observation.destination_ip == "2001:db8::2"
    assert observation.protocol == "UDP"


def test_skips_malformed_and_unsupported_packets(tmp_path):
    valid_packet = _ethernet(_ipv4(17, b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02", _udp(1, 2)))
    path = _write_capture(
        tmp_path,
        _pcap(
            [
                (1, 0, b"short", None),
                (2, 0, _ethernet(b"unsupported", ether_type=0x0806), None),
                (3, 0, valid_packet, None),
            ]
        ),
    )

    observations = list(read_pcap(path))

    assert len(observations) == 1
    assert observations[0].timestamp == datetime.fromtimestamp(3, UTC)


def test_empty_capture_yields_no_observations(tmp_path):
    path = _write_capture(tmp_path, _pcap())

    assert list(read_pcap(path)) == []