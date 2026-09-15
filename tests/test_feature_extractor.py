from datetime import UTC, datetime, timedelta

import pytest

from vajra.features import BasicFeatureExtractor
from vajra.ingestion import PacketObservation

START = datetime(2026, 1, 1, tzinfo=UTC)


def packet(
    offset: int,
    length: int | None,
    *,
    destination_ip: str = "198.51.100.20",
    destination_port: int | None = 443,
    protocol: str = "TCP",
    tcp_flags: int | None = None,
    dns_query: str | None = None,
    dns_record_type: str | None = None,
    tls_handshake_type: str | None = None,
    tls_fingerprint: str | None = None,
) -> PacketObservation:
    return PacketObservation(
        timestamp=START + timedelta(seconds=offset),
        source_ip="192.0.2.10",
        destination_ip=destination_ip,
        protocol=protocol,
        source_port=40000,
        destination_port=destination_port,
        packet_length=length,
        tcp_flags=tcp_flags,
        dns_query=dns_query,
        dns_record_type=dns_record_type,
        tls_handshake_type=tls_handshake_type,
        tls_fingerprint=tls_fingerprint,
    )


def test_traffic_and_timing_features_are_computed_from_observed_packets():
    result = BasicFeatureExtractor().extract([packet(0, 100), packet(1, 200), packet(3, 300)])

    assert result.values["packet_count"] == 3
    assert result.values["byte_count"] == 600
    assert result.values["packets_per_sec"] == 1
    assert result.values["bytes_per_sec"] == 200
    assert result.values["mean_packet_size"] == 200
    assert result.values["packet_size_variation"] == pytest.approx(81.6496580928)
    assert result.values["mean_inter_arrival_time"] == 1.5
    assert result.values["inter_arrival_variation"] == 0.5
    assert result.values["burst_count"] == 2
    assert result.values["max_burst_size"] == 2


def test_distribution_and_tcp_flag_features_use_only_available_values():
    observations = [
        packet(0, 100, destination_ip="198.51.100.20", destination_port=443, tcp_flags=0x12),
        packet(1, 100, destination_ip="198.51.100.21", destination_port=8443, tcp_flags=0x10),
        packet(2, 100, destination_ip="198.51.100.21", destination_port=8443, tcp_flags=0x01),
    ]

    result = BasicFeatureExtractor().extract(observations)

    assert result.values["destination_fan_out"] == 2
    assert result.values["destination_port_fan_out"] == 2
    assert result.values["source_frequency"] == {"192.0.2.10": 3}
    assert result.values["destination_frequency"] == {
        "198.51.100.20": 1,
        "198.51.100.21": 2,
    }
    assert result.values["protocol_distribution"] == {"TCP": 3}
    assert result.values["tcp_flag_packet_count"] == 3
    assert result.values["tcp_flag_distribution"] == {
        "FIN": 1,
        "SYN": 1,
        "RST": 0,
        "PSH": 0,
        "ACK": 2,
        "URG": 0,
        "ECE": 0,
        "CWR": 0,
    }


def test_dns_features_use_supplied_query_metadata_only():
    observations = [
        packet(
            0,
            70,
            protocol="UDP",
            destination_port=53,
            dns_query="www.example.com",
            dns_record_type="A",
        ),
        packet(
            1,
            75,
            protocol="UDP",
            destination_port=53,
            dns_query="api.example.com",
            dns_record_type="AAAA",
        ),
    ]

    result = BasicFeatureExtractor().extract(observations)

    assert result.values["dns_query_length_mean"] == 15
    assert result.values["dns_label_count_mean"] == 3
    assert result.values["dns_query_frequency"] == 2
    assert result.values["dns_record_type_distribution"] == {"A": 1, "AAAA": 1}
    assert result.values["dns_query_entropy_mean"] > 0


def test_tls_metadata_and_packet_sequence_features_are_observable_only():
    observations = [
        packet(0, 120, tls_handshake_type="client_hello", tls_fingerprint="ja3-a"),
        packet(1, 240, tls_handshake_type="server_hello", tls_fingerprint="ja3-a"),
    ]

    result = BasicFeatureExtractor().extract(observations)

    assert result.values["tls_handshake_distribution"] == {
        "client_hello": 1,
        "server_hello": 1,
    }
    assert result.values["tls_fingerprint_distribution"] == {"ja3-a": 2}
    assert result.values["packet_size_variation"] == 60


def test_empty_and_insufficient_windows_report_unavailable_features():
    extractor = BasicFeatureExtractor()
    empty = extractor.extract([])
    one_packet = extractor.extract([packet(0, None)])

    assert empty.values == {"packet_count": 0}
    assert empty.unavailable["mean_inter_arrival_time"] == "no observations"
    assert one_packet.values["packet_count"] == 1
    assert "byte_count" in one_packet.unavailable
    assert "mean_inter_arrival_time" in one_packet.unavailable
    assert "tcp_flag_distribution" in one_packet.unavailable


def test_missing_lengths_do_not_fabricate_byte_features():
    result = BasicFeatureExtractor().extract([packet(0, 100), packet(1, None)])

    assert "byte_count" not in result.values
    assert "bytes_per_sec" not in result.values
    assert result.unavailable["byte_count"] == "packet length is missing"