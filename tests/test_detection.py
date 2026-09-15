from datetime import UTC, datetime

from vajra.detection import (
    BeaconingDetector,
    BeaconThresholds,
    DetectionEngine,
    DnsAnomalyDetector,
    DnsAnomalyThresholds,
    EncryptedAnomalyThresholds,
    EncryptedSessionDetector,
    ExfiltrationThresholds,
    ExfiltrationVolumeDetector,
    ReconnaissanceDetector,
    ReconnaissanceThresholds,
    VolumetricThresholds,
    VolumetricUdpDetector,
)
from vajra.features import FeatureResult
from vajra.flows import FlowKey, FlowSnapshot


def flow() -> FlowSnapshot:
    key = FlowKey("192.0.2.10", "198.51.100.20", "UDP", 40000, 443)
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    return FlowSnapshot(key, timestamp, timestamp, 1, 100)


def features(**values) -> FeatureResult:
    return FeatureResult(values=values, unavailable={})


def test_volumetric_udp_detector_requires_multiple_signals_and_exposes_evidence():
    detector = VolumetricUdpDetector(
        VolumetricThresholds(
            min_packet_count=10,
            min_packets_per_sec=5,
            min_bytes_per_sec=500,
            min_udp_fraction=0.8,
        )
    )
    result = detector.evaluate(
        flow(),
        features(
            packet_count=20,
            packets_per_sec=10,
            bytes_per_sec=1000,
            protocol_distribution={"UDP": 20},
        ),
    )

    assert len(result) == 1
    assert result[0].threat_class == "volumetric_udp_anomaly"
    assert result[0].detection_method == "rule"
    assert result[0].evidence["udp_fraction"] == 1.0
    assert "heuristic score" in result[0].explanation

    weak = detector.evaluate(
        flow(),
        features(packet_count=2, protocol_distribution={"UDP": 2}),
    )
    assert weak == ()


def test_reconnaissance_detector_requires_packet_and_port_fan_out():
    detector = ReconnaissanceDetector(
        ReconnaissanceThresholds(min_packet_count=5, min_destination_port_fan_out=4)
    )

    result = detector.evaluate(
        flow(), features(packet_count=5, destination_port_fan_out=4)
    )

    assert result[0].threat_class == "reconnaissance_port_scanning"
    assert result[0].evidence == {"packet_count": 5.0, "destination_port_fan_out": 4.0}


def test_beaconing_detector_uses_periodicity_statistics():
    detector = BeaconingDetector(
        BeaconThresholds(min_packet_count=4, max_inter_arrival_coefficient=0.1)
    )

    result = detector.evaluate(
        flow(),
        features(
            packet_count=4,
            mean_inter_arrival_time=10,
            inter_arrival_variation=0.5,
        ),
    )

    assert result[0].threat_class == "c2_beaconing_periodicity"
    assert result[0].detection_method == "statistical"
    assert result[0].evidence["inter_arrival_coefficient"] == 0.05

    irregular = detector.evaluate(
        flow(),
        features(packet_count=4, mean_inter_arrival_time=10, inter_arrival_variation=5),
    )
    assert irregular == ()


def test_dns_detector_requires_repeated_queries_and_multiple_complexity_signals():
    detector = DnsAnomalyDetector(
        DnsAnomalyThresholds(
            min_query_frequency=5,
            min_query_length=40,
            min_query_entropy=3.5,
            min_label_count=4,
        )
    )

    result = detector.evaluate(
        flow(),
        features(
            dns_query_frequency=5,
            dns_query_length_mean=50,
            dns_query_entropy_mean=4,
            dns_label_count_mean=2,
        ),
    )

    assert result[0].threat_class == "dns_tunnelling_dga_like_anomaly"
    assert result[0].detection_method == "statistical"
    assert result[0].evidence["dns_query_frequency"] == 5.0

    weak = detector.evaluate(
        flow(),
        features(dns_query_frequency=5, dns_query_length_mean=50),
    )
    assert weak == ()


def test_exfiltration_detector_uses_one_way_volume_without_claiming_reverse_traffic():
    detector = ExfiltrationVolumeDetector(
        ExfiltrationThresholds(
            min_byte_count=1000,
            min_bytes_per_sec=100,
            min_mean_packet_size=500,
        )
    )

    result = detector.evaluate(
        flow(),
        features(byte_count=2000, bytes_per_sec=200, mean_packet_size=600),
    )

    assert result[0].threat_class == "data_exfiltration_like_volume"
    assert "observed one-way direction" in result[0].explanation


def test_encrypted_detector_uses_supplied_metadata_and_statistics_only():
    detector = EncryptedSessionDetector(
        EncryptedAnomalyThresholds(
            min_packet_count=4,
            min_size_coefficient=0.75,
            min_timing_coefficient=0.75,
        )
    )

    result = detector.evaluate(
        flow(),
        features(
            packet_count=4,
            mean_packet_size=100,
            packet_size_variation=90,
            mean_inter_arrival_time=1,
            inter_arrival_variation=0.9,
            tls_fingerprint_distribution={"observed": 4},
        ),
    )

    assert result[0].threat_class == "encrypted_session_metadata_anomaly"
    assert result[0].detection_method == "statistical"
    assert result[0].evidence["encrypted_metadata"] == "supplied"


def test_detection_engine_evaluates_only_configured_detectors():
    detector = ReconnaissanceDetector(
        ReconnaissanceThresholds(min_packet_count=1, min_destination_port_fan_out=1)
    )
    result = DetectionEngine((detector,)).evaluate(
        flow(), features(packet_count=1, destination_port_fan_out=1)
    )

    assert len(result) == 1
    assert result[0].threat_class == "reconnaissance_port_scanning"