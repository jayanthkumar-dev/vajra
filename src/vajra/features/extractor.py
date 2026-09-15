"""Feature extraction from passively observed packet windows."""

from dataclasses import dataclass
from datetime import timedelta
from math import log2
from typing import Protocol

from vajra.ingestion.models import PacketObservation


@dataclass(frozen=True, slots=True)
class FeatureResult:
    """Computed features and explicit reasons for values that are unavailable."""

    values: dict[str, int | float | str | dict[str, int]]
    unavailable: dict[str, str]


class FeatureExtractor(Protocol):
    """Contract for observable-metadata feature extraction."""

    def extract(self, observations: list[PacketObservation]) -> FeatureResult:
        """Extract features without payloads or reverse-path assumptions."""


class BasicFeatureExtractor:
    """Calculate defensible traffic, timing, distribution, and supplied metadata features."""

    def __init__(self, burst_gap: timedelta = timedelta(seconds=1)) -> None:
        if burst_gap <= timedelta(0):
            raise ValueError("burst_gap must be positive")
        self.burst_gap = burst_gap

    def extract(self, observations: list[PacketObservation]) -> FeatureResult:
        if not isinstance(observations, list):
            observations = list(observations)
        if any(not isinstance(observation, PacketObservation) for observation in observations):
            raise ValueError("observations must contain PacketObservation values")

        values: dict[str, int | float | str | dict[str, int]] = {
            "packet_count": len(observations),
        }
        unavailable: dict[str, str] = {}
        if not observations:
            self._mark_empty(unavailable)
            return FeatureResult(values, unavailable)

        ordered = sorted(observations, key=lambda observation: observation.timestamp)
        durations = ordered[-1].timestamp - ordered[0].timestamp
        lengths = [observation.packet_length for observation in observations]
        if all(length is not None for length in lengths):
            known_lengths = [length for length in lengths if length is not None]
            values["byte_count"] = sum(known_lengths)
            values["mean_packet_size"] = _mean(known_lengths)
            values["packet_size_variation"] = _population_stdev(known_lengths)
        else:
            self._mark(unavailable, "byte_count", "packet length is missing")
            self._mark(unavailable, "mean_packet_size", "packet length is missing")
            self._mark(unavailable, "packet_size_variation", "packet length is missing")

        if durations.total_seconds() > 0:
            seconds = durations.total_seconds()
            if "byte_count" in values:
                values["bytes_per_sec"] = values["byte_count"] / seconds
            values["packets_per_sec"] = len(observations) / seconds
        else:
            self._mark(unavailable, "packets_per_sec", "window duration is zero")
            self._mark(unavailable, "bytes_per_sec", "window duration is zero")

        if len(ordered) >= 2:
            inter_arrivals = [
                (later.timestamp - earlier.timestamp).total_seconds()
                for earlier, later in zip(ordered, ordered[1:])
            ]
            values["mean_inter_arrival_time"] = _mean(inter_arrivals)
            values["inter_arrival_variation"] = _population_stdev(inter_arrivals)
            self._add_burst_features(values, ordered)
        else:
            reason = "at least two observations are required"
            self._mark(unavailable, "mean_inter_arrival_time", reason)
            self._mark(unavailable, "inter_arrival_variation", reason)
            self._mark(unavailable, "burst_count", "at least two observations are required")
            self._mark(unavailable, "max_burst_size", "at least two observations are required")
            self._mark(unavailable, "burst_packet_fraction", reason)

        values["destination_fan_out"] = len(
            {observation.destination_ip for observation in observations}
        )
        values["destination_port_fan_out"] = len(
            {
                observation.destination_port
                for observation in observations
                if observation.destination_port is not None
            }
        )
        values["source_frequency"] = _frequency(
            observation.source_ip for observation in observations
        )
        values["destination_frequency"] = _frequency(
            observation.destination_ip for observation in observations
        )
        values["protocol_distribution"] = _frequency(
            observation.protocol.upper() for observation in observations
        )
        self._add_tcp_features(values, unavailable, observations)
        self._add_dns_features(values, unavailable, observations)
        self._add_encrypted_features(values, observations)
        return FeatureResult(values, unavailable)

    def _add_burst_features(self, values, ordered) -> None:
        bursts: list[int] = [1]
        gap = self.burst_gap.total_seconds()
        for earlier, later in zip(ordered, ordered[1:]):
            if (later.timestamp - earlier.timestamp).total_seconds() <= gap:
                bursts[-1] += 1
            else:
                bursts.append(1)
        values["burst_count"] = len(bursts)
        values["max_burst_size"] = max(bursts)
        values["burst_packet_fraction"] = max(bursts) / len(ordered)

    @staticmethod
    def _add_tcp_features(values, unavailable, observations) -> None:
        flags = [
            observation.tcp_flags
            for observation in observations
            if observation.protocol.upper() == "TCP" and observation.tcp_flags is not None
        ]
        if not flags:
            unavailable["tcp_flag_distribution"] = "TCP flags were not supplied"
            return
        names = {
            "FIN": 0x01,
            "SYN": 0x02,
            "RST": 0x04,
            "PSH": 0x08,
            "ACK": 0x10,
            "URG": 0x20,
            "ECE": 0x40,
            "CWR": 0x80,
        }
        values["tcp_flag_packet_count"] = len(flags)
        values["tcp_flag_distribution"] = {
            name: sum(1 for flag in flags if flag & mask) for name, mask in names.items()
        }

    @staticmethod
    def _add_dns_features(values, unavailable, observations) -> None:
        queries = [
            observation.dns_query
            for observation in observations
            if observation.dns_query is not None
        ]
        if not queries:
            unavailable["dns_features"] = "DNS query metadata was not supplied"
            return
        values["dns_query_length_mean"] = _mean([len(query) for query in queries])
        values["dns_label_count_mean"] = _mean(
            [len(query.strip(".").split(".")) for query in queries]
        )
        values["dns_query_entropy_mean"] = _mean([_entropy(query) for query in queries])
        values["dns_query_frequency"] = len(queries)
        record_types = [
            observation.dns_record_type.upper()
            for observation in observations
            if observation.dns_record_type is not None
        ]
        if record_types:
            values["dns_record_type_distribution"] = _frequency(record_types)
        else:
            unavailable["dns_record_type_distribution"] = "DNS record types were not supplied"

    @staticmethod
    def _add_encrypted_features(values, observations) -> None:
        for prefix, type_name, fingerprint_name in (
            ("tls", "tls_handshake_type", "tls_fingerprint"),
            ("quic", "quic_handshake_type", "quic_fingerprint"),
        ):
            types = [
                getattr(observation, type_name)
                for observation in observations
                if getattr(observation, type_name) is not None
            ]
            fingerprints = [
                getattr(observation, fingerprint_name)
                for observation in observations
                if getattr(observation, fingerprint_name) is not None
            ]
            if types:
                values[f"{prefix}_handshake_distribution"] = _frequency(types)
            if fingerprints:
                values[f"{prefix}_fingerprint_distribution"] = _frequency(fingerprints)

    @staticmethod
    def _mark_empty(unavailable) -> None:
        for name in (
            "byte_count", "packets_per_sec", "bytes_per_sec", "mean_packet_size",
            "packet_size_variation", "mean_inter_arrival_time", "inter_arrival_variation",
            "burst_count", "max_burst_size", "burst_packet_fraction", "tcp_flag_distribution",
            "dns_features",
        ):
            unavailable[name] = "no observations"

    @staticmethod
    def _mark(unavailable, name: str, reason: str) -> None:
        unavailable[name] = reason


def _mean(values: list[int | float]) -> float:
    return sum(values) / len(values)


def _population_stdev(values: list[int | float]) -> float:
    mean = _mean(values)
    return (sum((value - mean) ** 2 for value in values) / len(values)) ** 0.5


def _frequency(values) -> dict[str, int]:
    frequencies: dict[str, int] = {}
    for value in values:
        frequencies[value] = frequencies.get(value, 0) + 1
    return frequencies


def _entropy(value: str) -> float:
    counts = _frequency(value.lower())
    length = len(value)
    if length == 0:
        return 0.0
    return -sum((count / length) * log2(count / length) for count in counts.values())