from datetime import UTC, datetime, timedelta

import pytest

from vajra.flows import FlowTracker
from vajra.ingestion import PacketObservation


def observation(
    timestamp,
    length,
    *,
    source_ip="192.0.2.10",
    destination_ip="198.51.100.20",
    protocol="TCP",
    source_port=40000,
    destination_port=443,
):
    return PacketObservation(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        packet_length=length,
    )


def test_tracker_accumulates_only_same_direction():
    first = datetime(2026, 1, 1, tzinfo=UTC)
    second = first.replace(second=1)
    tracker = FlowTracker()

    snapshot = tracker.observe(observation(first, 100))
    snapshot = tracker.observe(observation(second, 50))

    assert snapshot.packet_count == 2
    assert snapshot.byte_count == 150
    assert snapshot.first_seen == first
    assert snapshot.last_seen == second
    assert snapshot.duration == timedelta(seconds=1)
    assert len(snapshot.flow_id) == 64
    assert len(tracker.snapshot()) == 1


def test_one_way_udp_flow_is_created_without_reverse_packet():
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    tracker = FlowTracker()

    snapshot = tracker.observe(
        observation(
            timestamp,
            80,
            protocol="UDP",
            source_port=53000,
            destination_port=53,
        )
    )

    assert snapshot.packet_count == 1
    assert snapshot.byte_count == 80
    assert snapshot.key.source_ip == "192.0.2.10"
    assert snapshot.key.destination_ip == "198.51.100.20"
    assert snapshot.key.source_port == 53000
    assert snapshot.key.destination_port == 53


def test_tcp_packets_are_tracked_without_handshake_state():
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    tracker = FlowTracker()

    tracker.observe(observation(timestamp, 60))
    snapshot = tracker.observe(observation(timestamp + timedelta(seconds=2), 70))

    assert snapshot.packet_count == 2
    assert snapshot.byte_count == 130


def test_multiple_directional_flows_have_distinct_ids():
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    tracker = FlowTracker()

    forward = tracker.observe(observation(timestamp, 10))
    reverse = tracker.observe(
        observation(
            timestamp,
            20,
            source_ip="198.51.100.20",
            destination_ip="192.0.2.10",
            source_port=443,
            destination_port=40000,
        )
    )

    assert forward.flow_id != reverse.flow_id
    assert len(tracker.snapshot()) == 2


def test_inactivity_timeout_evicts_stale_flow():
    first = datetime(2026, 1, 1, tzinfo=UTC)
    tracker = FlowTracker(inactivity_timeout=timedelta(seconds=5))
    tracker.observe(observation(first, 10))

    tracker.observe(observation(first + timedelta(seconds=6), 20, destination_port=8443))

    snapshots = tracker.snapshot()
    assert len(snapshots) == 1
    assert snapshots[0].key.destination_port == 8443


def test_capacity_evicts_least_recently_seen_flow():
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    tracker = FlowTracker(max_flows=2)
    tracker.observe(observation(timestamp, 10, destination_port=1))
    tracker.observe(observation(timestamp + timedelta(seconds=1), 10, destination_port=2))
    tracker.observe(observation(timestamp + timedelta(seconds=2), 10, destination_port=3))

    ports = {snapshot.key.destination_port for snapshot in tracker.snapshot()}
    assert ports == {2, 3}


def test_out_of_order_tcp_packets_keep_observed_time_bounds():
    latest = datetime(2026, 1, 1, 0, 0, 5, tzinfo=UTC)
    earliest = datetime(2026, 1, 1, tzinfo=UTC)
    tracker = FlowTracker()

    tracker.observe(observation(latest, 50))
    snapshot = tracker.observe(observation(earliest, 25))

    assert snapshot.first_seen == earliest
    assert snapshot.last_seen == latest
    assert snapshot.duration == timedelta(seconds=5)


@pytest.mark.parametrize(
    "bad_observation",
    [
        object(),
        observation(datetime(2026, 1, 1, tzinfo=UTC), -1),
        observation(datetime(2026, 1, 1), 10),
        observation(datetime(2026, 1, 1, tzinfo=UTC), 10, source_ip="not-an-ip"),
    ],
)
def test_malformed_input_is_rejected_without_state_change(bad_observation):
    tracker = FlowTracker()

    with pytest.raises(ValueError):
        tracker.observe(bad_observation)

    assert tracker.snapshot() == ()