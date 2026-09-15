import json
from datetime import UTC, datetime, timedelta

import pytest

from vajra.alerts import Alert, AlertDeduplicator, severity_for_score
from vajra.flows import FlowKey


def make_alert(timestamp=None, score=0.8):
    timestamp = timestamp or datetime(2026, 1, 1, tzinfo=UTC)
    return Alert(
        timestamp=timestamp,
        flow=FlowKey("192.0.2.10", "198.51.100.20", "UDP", 40000, 53),
        threat_class="test_anomaly",
        score=score,
        severity=severity_for_score(score),
        evidence={"packets_per_sec": 50.0},
        explanation="Observed packet rate exceeded the configured threshold.",
        detection_method="rule",
        detector_source="test.detector",
        feature_values={"packets_per_sec": 50.0},
        score_method="matched_signals_fraction",
    )


def test_alert_contains_standard_fields_and_serializes_to_json():
    alert = make_alert()

    payload = alert.to_dict()
    decoded = json.loads(alert.to_json())

    assert len(alert.alert_id) == 64
    assert alert.flow_id == alert.flow.flow_id
    assert payload["alert_id"] == alert.alert_id
    assert payload["flow_id"] == alert.flow_id
    assert payload["detector_source"] == "test.detector"
    assert payload["feature_values"] == {"packets_per_sec": 50.0}
    assert decoded == payload


def test_alert_id_is_deterministic_for_same_content():
    assert make_alert().alert_id == make_alert().alert_id


@pytest.mark.parametrize(
    ("score", "severity"),
    [(0.0, "low"), (0.49, "low"), (0.5, "medium"), (0.75, "high"), (0.9, "critical")],
)
def test_severity_mapping_is_defined(score, severity):
    assert severity_for_score(score) == severity


def test_invalid_alert_is_rejected():
    with pytest.raises(ValueError, match="severity"):
        Alert(
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            flow=make_alert().flow,
            threat_class="invalid",
            score=0.9,
            severity="medium",
            evidence={"x": 1},
            explanation="mismatched severity",
            detector_source="test.detector",
            feature_values={"x": 1},
        )

    with pytest.raises(ValueError, match="supporting evidence"):
        Alert(
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            flow=make_alert().flow,
            threat_class="invalid",
            score=0.5,
            severity="medium",
            evidence={},
            explanation="missing evidence",
            detector_source="test.detector",
            feature_values={"x": 1},
        )


def test_deduplicator_suppresses_same_detection_during_cooldown():
    deduplicator = AlertDeduplicator(cooldown=timedelta(seconds=30))
    first = make_alert()
    repeated = make_alert(first.timestamp + timedelta(seconds=10))
    later = make_alert(first.timestamp + timedelta(seconds=31))

    assert deduplicator.filter([first, repeated, later]) == (first, later)


def test_deduplicator_keeps_different_detection_keys():
    deduplicator = AlertDeduplicator(cooldown=timedelta(minutes=5))
    first = make_alert()
    different = Alert(
        timestamp=first.timestamp,
        flow=first.flow,
        threat_class="different_anomaly",
        score=first.score,
        severity=first.severity,
        evidence=first.evidence,
        explanation=first.explanation,
        detector_source=first.detector_source,
        feature_values=first.feature_values,
    )

    assert deduplicator.filter([first, different]) == (first, different)