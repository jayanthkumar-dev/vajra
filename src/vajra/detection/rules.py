"""Deterministic and statistical detectors over approved passive features."""

from collections.abc import Iterable
from dataclasses import dataclass
from math import isfinite

from vajra.alerts.schema import Alert, severity_for_score
from vajra.detection.protocol import Detector
from vajra.features.extractor import FeatureResult
from vajra.flows.models import FlowSnapshot


@dataclass(frozen=True, slots=True)
class VolumetricThresholds:
    """Thresholds for a multi-signal UDP/protocol volume rule."""

    min_packet_count: int = 100
    min_packets_per_sec: float = 50.0
    min_bytes_per_sec: float = 10_000.0
    min_udp_fraction: float = 0.8
    required_signals: int = 2


@dataclass(frozen=True, slots=True)
class ReconnaissanceThresholds:
    """Thresholds for packet-count and destination-port fan-out evidence."""

    min_packet_count: int = 10
    min_destination_port_fan_out: int = 8


@dataclass(frozen=True, slots=True)
class BeaconThresholds:
    """Thresholds for a periodicity coefficient-of-variation rule."""

    min_packet_count: int = 6
    max_inter_arrival_coefficient: float = 0.1


@dataclass(frozen=True, slots=True)
class DnsAnomalyThresholds:
    """Thresholds for a multi-signal DNS tunnelling/DGA-like rule."""

    min_query_frequency: int = 10
    min_query_length: float = 40.0
    min_query_entropy: float = 3.5
    min_label_count: float = 4.0
    required_signals: int = 2


@dataclass(frozen=True, slots=True)
class ExfiltrationThresholds:
    """Thresholds for one-way high-volume asymmetric behaviour."""

    min_byte_count: float = 1_000_000.0
    min_bytes_per_sec: float = 10_000.0
    min_mean_packet_size: float = 800.0
    required_signals: int = 2


@dataclass(frozen=True, slots=True)
class EncryptedAnomalyThresholds:
    """Thresholds for metadata-only encrypted-session variability."""

    min_packet_count: int = 6
    min_size_coefficient: float = 0.75
    min_timing_coefficient: float = 0.75


class VolumetricUdpDetector:
    """Rule detector for sustained, predominantly UDP volume."""

    def __init__(self, thresholds: VolumetricThresholds = VolumetricThresholds()) -> None:
        self.thresholds = thresholds

    def evaluate(self, flow: FlowSnapshot, features: FeatureResult) -> tuple[Alert, ...]:
        values = features.values
        distribution = values.get("protocol_distribution")
        packet_count = _number(values, "packet_count")
        if not isinstance(distribution, dict) or packet_count is None or packet_count <= 0:
            return ()
        udp_fraction = distribution.get("UDP", 0) / packet_count
        signals = {
            "packet_count": packet_count >= self.thresholds.min_packet_count,
            "packets_per_sec": _at_least(
                values, "packets_per_sec", self.thresholds.min_packets_per_sec
            ),
            "bytes_per_sec": _at_least(values, "bytes_per_sec", self.thresholds.min_bytes_per_sec),
            "udp_fraction": udp_fraction >= self.thresholds.min_udp_fraction,
        }
        if not signals["udp_fraction"] or sum(signals.values()) < self.thresholds.required_signals:
            return ()
        evidence = {
            "packet_count": packet_count,
            "udp_fraction": udp_fraction,
            "packets_per_sec": values.get("packets_per_sec", "unavailable"),
            "bytes_per_sec": values.get("bytes_per_sec", "unavailable"),
        }
        return (
            _alert(
                flow,
                "volumetric_udp_anomaly",
                signals,
                evidence,
                "rule",
                "the observed window is predominantly UDP and meets volume thresholds",
            ),
        )


class ReconnaissanceDetector:
    """Rule detector for repeated probes across many destination ports."""

    def __init__(self, thresholds: ReconnaissanceThresholds = ReconnaissanceThresholds()) -> None:
        self.thresholds = thresholds

    def evaluate(self, flow: FlowSnapshot, features: FeatureResult) -> tuple[Alert, ...]:
        values = features.values
        packet_count = _number(values, "packet_count")
        port_fan_out = _number(values, "destination_port_fan_out")
        if packet_count is None or port_fan_out is None:
            return ()
        signals = {
            "packet_count": packet_count >= self.thresholds.min_packet_count,
            "destination_port_fan_out": (
                port_fan_out >= self.thresholds.min_destination_port_fan_out
            ),
        }
        if not all(signals.values()):
            return ()
        evidence = {"packet_count": packet_count, "destination_port_fan_out": port_fan_out}
        return (
            _alert(
                flow,
                "reconnaissance_port_scanning",
                signals,
                evidence,
                "rule",
                "the observed source contacted many destination ports with enough packets",
            ),
        )


class BeaconingDetector:
    """Statistical detector for low-variance packet periodicity."""

    def __init__(self, thresholds: BeaconThresholds = BeaconThresholds()) -> None:
        self.thresholds = thresholds

    def evaluate(self, flow: FlowSnapshot, features: FeatureResult) -> tuple[Alert, ...]:
        values = features.values
        packet_count = _number(values, "packet_count")
        mean_iat = _number(values, "mean_inter_arrival_time")
        variation = _number(values, "inter_arrival_variation")
        if packet_count is None or mean_iat is None or variation is None or mean_iat <= 0:
            return ()
        coefficient = variation / mean_iat
        signals = {
            "packet_count": packet_count >= self.thresholds.min_packet_count,
            "low_inter_arrival_coefficient": (
                coefficient <= self.thresholds.max_inter_arrival_coefficient
            ),
        }
        if not all(signals.values()):
            return ()
        evidence = {
            "packet_count": packet_count,
            "mean_inter_arrival_time": mean_iat,
            "inter_arrival_variation": variation,
            "inter_arrival_coefficient": coefficient,
        }
        return (
            _alert(
                flow,
                "c2_beaconing_periodicity",
                signals,
                evidence,
                "statistical",
                "the observed inter-arrival times have low relative variation",
            ),
        )


class DnsAnomalyDetector:
    """Rule/statistical detector for repeated complex DNS query metadata."""

    def __init__(self, thresholds: DnsAnomalyThresholds = DnsAnomalyThresholds()) -> None:
        self.thresholds = thresholds

    def evaluate(self, flow: FlowSnapshot, features: FeatureResult) -> tuple[Alert, ...]:
        values = features.values
        frequency = _number(values, "dns_query_frequency")
        if frequency is None or frequency < self.thresholds.min_query_frequency:
            return ()
        signals = {
            "query_length": _at_least(
                values, "dns_query_length_mean", self.thresholds.min_query_length
            ),
            "query_entropy": _at_least(
                values, "dns_query_entropy_mean", self.thresholds.min_query_entropy
            ),
            "label_count": _at_least(
                values, "dns_label_count_mean", self.thresholds.min_label_count
            ),
        }
        if sum(signals.values()) < self.thresholds.required_signals:
            return ()
        evidence = {
            "dns_query_frequency": frequency,
            "dns_query_length_mean": values.get("dns_query_length_mean", "unavailable"),
            "dns_query_entropy_mean": values.get("dns_query_entropy_mean", "unavailable"),
            "dns_label_count_mean": values.get("dns_label_count_mean", "unavailable"),
        }
        return (
            _alert(
                flow,
                "dns_tunnelling_dga_like_anomaly",
                signals,
                evidence,
                "statistical",
                "repeated DNS metadata meets multiple query-complexity thresholds",
            ),
        )


class ExfiltrationVolumeDetector:
    """Rule detector for sustained high-volume behaviour in the observed direction."""

    def __init__(self, thresholds: ExfiltrationThresholds = ExfiltrationThresholds()) -> None:
        self.thresholds = thresholds

    def evaluate(self, flow: FlowSnapshot, features: FeatureResult) -> tuple[Alert, ...]:
        values = features.values
        signals = {
            "byte_count": _at_least(values, "byte_count", self.thresholds.min_byte_count),
            "bytes_per_sec": _at_least(values, "bytes_per_sec", self.thresholds.min_bytes_per_sec),
            "mean_packet_size": _at_least(
                values, "mean_packet_size", self.thresholds.min_mean_packet_size
            ),
        }
        if sum(signals.values()) < self.thresholds.required_signals:
            return ()
        evidence = {
            "byte_count": values.get("byte_count", "unavailable"),
            "bytes_per_sec": values.get("bytes_per_sec", "unavailable"),
            "mean_packet_size": values.get("mean_packet_size", "unavailable"),
        }
        return (
            _alert(
                flow,
                "data_exfiltration_like_volume",
                signals,
                evidence,
                "rule",
                "the observed one-way direction meets multiple sustained-volume thresholds",
            ),
        )


class EncryptedSessionDetector:
    """Statistical detector using encrypted-session metadata without decryption."""

    def __init__(
        self,
        thresholds: EncryptedAnomalyThresholds = EncryptedAnomalyThresholds(),
    ) -> None:
        self.thresholds = thresholds

    def evaluate(self, flow: FlowSnapshot, features: FeatureResult) -> tuple[Alert, ...]:
        values = features.values
        encrypted = any(
            key in values
            for key in (
                "tls_handshake_distribution",
                "tls_fingerprint_distribution",
                "quic_handshake_distribution",
                "quic_fingerprint_distribution",
            )
        )
        packet_count = _number(values, "packet_count")
        mean_size = _number(values, "mean_packet_size")
        size_variation = _number(values, "packet_size_variation")
        mean_iat = _number(values, "mean_inter_arrival_time")
        timing_variation = _number(values, "inter_arrival_variation")
        if not encrypted or packet_count is None or packet_count < self.thresholds.min_packet_count:
            return ()
        if not mean_size or not mean_iat or size_variation is None or timing_variation is None:
            return ()
        size_coefficient = size_variation / mean_size
        timing_coefficient = timing_variation / mean_iat
        signals = {
            "packet_size_variability": size_coefficient >= self.thresholds.min_size_coefficient,
            "timing_variability": timing_coefficient >= self.thresholds.min_timing_coefficient,
        }
        if not all(signals.values()):
            return ()
        evidence = {
            "packet_count": packet_count,
            "packet_size_coefficient": size_coefficient,
            "timing_coefficient": timing_coefficient,
            "encrypted_metadata": "supplied",
        }
        return (
            _alert(
                flow,
                "encrypted_session_metadata_anomaly",
                signals,
                evidence,
                "statistical",
                "supplied encrypted-session metadata accompanies high size and timing variability",
            ),
        )


class DetectionEngine:
    """Evaluate a configured collection of deterministic detectors."""

    def __init__(self, detectors: Iterable[Detector]) -> None:
        self.detectors = tuple(detectors)

    def evaluate(self, flow: FlowSnapshot, features: FeatureResult) -> tuple[Alert, ...]:
        return tuple(
            alert
            for detector in self.detectors
            for alert in detector.evaluate(flow, features)
        )


def default_detectors() -> tuple[Detector, ...]:
    """Return the six explicitly rule/statistical prototype detectors."""
    return (
        VolumetricUdpDetector(),
        ReconnaissanceDetector(),
        BeaconingDetector(),
        DnsAnomalyDetector(),
        ExfiltrationVolumeDetector(),
        EncryptedSessionDetector(),
    )


def _number(values: dict, key: str) -> float | None:
    value = values.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value):
        return None
    return float(value)


def _at_least(values: dict, key: str, threshold: float) -> bool:
    value = _number(values, key)
    return value is not None and value >= threshold


def _alert(flow, threat_class, signals, evidence, method, reasoning) -> Alert:
    matched = sum(signals.values())
    score = matched / len(signals)
    explanation = (
        f"Deterministic {method} detector matched {matched}/{len(signals)} configured signals: "
        f"{reasoning}; "
        "this is a heuristic score, not a probability or trained-model confidence."
    )
    return Alert(
        timestamp=flow.last_seen,
        flow=flow.key,
        threat_class=threat_class,
        score=score,
        severity=severity_for_score(score),
        evidence=evidence,
        explanation=explanation,
        detection_method=method,
        detector_source=f"{method}.{threat_class}",
        feature_values=evidence,
        score_method="matched_signals_fraction",
    )