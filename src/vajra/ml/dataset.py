"""Reproducible synthetic datasets over the approved scalar feature schema."""

import csv
import random
from dataclasses import dataclass
from pathlib import Path

from vajra.features.extractor import FeatureResult

FEATURE_NAMES = (
    "packet_count",
    "byte_count",
    "packets_per_sec",
    "bytes_per_sec",
    "mean_packet_size",
    "packet_size_variation",
    "mean_inter_arrival_time",
    "inter_arrival_variation",
    "burst_count",
    "max_burst_size",
    "burst_packet_fraction",
    "destination_fan_out",
    "destination_port_fan_out",
)


@dataclass(frozen=True, slots=True)
class LabeledFeatureRow:
    """A scalar approved-feature row with an explicit benign/abnormal label."""

    values: dict[str, float]
    label: int

    def as_feature_result(self) -> FeatureResult:
        return FeatureResult(values=dict(self.values), unavailable={})


def generate_synthetic_dataset(
    sample_count: int = 240,
    seed: int = 42,
) -> list[LabeledFeatureRow]:
    """Generate reproducible synthetic lab rows; labels are not real-world ground truth."""
    if sample_count < 4 or sample_count % 2:
        raise ValueError("sample_count must be an even number of at least 4")
    rng = random.Random(seed)
    rows: list[LabeledFeatureRow] = []
    for label in (0, 1):
        for _ in range(sample_count // 2):
            if label == 0:
                values = {
                    "packet_count": _positive(rng.gauss(30, 6)),
                    "byte_count": _positive(rng.gauss(18_000, 3_000)),
                    "packets_per_sec": _positive(rng.gauss(3, 0.7)),
                    "bytes_per_sec": _positive(rng.gauss(1_800, 350)),
                    "mean_packet_size": _positive(rng.gauss(600, 80)),
                    "packet_size_variation": _positive(rng.gauss(70, 20)),
                    "mean_inter_arrival_time": _positive(rng.gauss(1.5, 0.3)),
                    "inter_arrival_variation": _positive(rng.gauss(0.8, 0.2)),
                    "burst_count": _positive(rng.gauss(8, 2)),
                    "max_burst_size": _positive(rng.gauss(6, 1.5)),
                    "burst_packet_fraction": _bounded(rng.gauss(0.35, 0.08)),
                    "destination_fan_out": _positive(rng.gauss(1.5, 0.5)),
                    "destination_port_fan_out": _positive(rng.gauss(2, 0.7)),
                }
            else:
                values = {
                    "packet_count": _positive(rng.gauss(180, 25)),
                    "byte_count": _positive(rng.gauss(180_000, 25_000)),
                    "packets_per_sec": _positive(rng.gauss(45, 8)),
                    "bytes_per_sec": _positive(rng.gauss(45_000, 7_000)),
                    "mean_packet_size": _positive(rng.gauss(1_000, 150)),
                    "packet_size_variation": _positive(rng.gauss(450, 80)),
                    "mean_inter_arrival_time": _positive(rng.gauss(0.15, 0.04)),
                    "inter_arrival_variation": _positive(rng.gauss(0.12, 0.03)),
                    "burst_count": _positive(rng.gauss(35, 6)),
                    "max_burst_size": _positive(rng.gauss(30, 5)),
                    "burst_packet_fraction": _bounded(rng.gauss(0.8, 0.08)),
                    "destination_fan_out": _positive(rng.gauss(8, 2)),
                    "destination_port_fan_out": _positive(rng.gauss(25, 5)),
                }
            rows.append(LabeledFeatureRow(values=values, label=label))
    rng.shuffle(rows)
    return rows


def save_dataset(rows: list[LabeledFeatureRow], path: str | Path) -> None:
    """Save labeled rows as a portable CSV file."""
    with Path(path).open("w", newline="", encoding="utf-8") as dataset_file:
        writer = csv.DictWriter(dataset_file, fieldnames=[*FEATURE_NAMES, "label"])
        writer.writeheader()
        for row in rows:
            writer.writerow({**row.values, "label": row.label})


def load_dataset(path: str | Path) -> list[LabeledFeatureRow]:
    """Load and validate a labeled scalar-feature CSV."""
    with Path(path).open(newline="", encoding="utf-8") as dataset_file:
        reader = csv.DictReader(dataset_file)
        expected = [*FEATURE_NAMES, "label"]
        if reader.fieldnames != expected:
            raise ValueError("dataset columns do not match the approved feature schema")
        rows = []
        for raw_row in reader:
            values = {name: float(raw_row[name]) for name in FEATURE_NAMES}
            label = int(raw_row["label"])
            if label not in (0, 1):
                raise ValueError("dataset labels must be 0 (benign) or 1 (abnormal)")
            rows.append(LabeledFeatureRow(values=values, label=label))
    if not rows or {row.label for row in rows} != {0, 1}:
        raise ValueError("dataset must contain both benign and abnormal labels")
    return rows


def _positive(value: float) -> float:
    return max(0.01, value)


def _bounded(value: float) -> float:
    return min(0.99, max(0.01, value))