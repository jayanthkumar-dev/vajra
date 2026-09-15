import asyncio
from datetime import UTC, datetime, timedelta

from vajra.detection import VolumetricThresholds, VolumetricUdpDetector
from vajra.ingestion import PacketObservation
from vajra.pipeline import PipelineRuntime


def observation(timestamp, length=100):
    return PacketObservation(
        timestamp=timestamp,
        source_ip="192.0.2.10",
        destination_ip="198.51.100.20",
        protocol="UDP",
        source_port=40000,
        destination_port=53,
        packet_length=length,
    )


def runtime():
    return PipelineRuntime(
        detectors=(
            VolumetricUdpDetector(
                VolumetricThresholds(
                    min_packet_count=2,
                    min_packets_per_sec=1,
                    min_bytes_per_sec=50,
                    min_udp_fraction=0.8,
                )
            ),
        )
    )


def test_runtime_processes_observations_and_publishes_alerts():
    pipeline = runtime()
    first = datetime(2026, 1, 1, tzinfo=UTC)
    queue = pipeline.subscribe()

    assert pipeline.ingest_observation(observation(first)) == ()
    alerts = pipeline.ingest_observation(observation(first + timedelta(seconds=1), 120))

    assert len(alerts) == 1
    assert pipeline.traffic_statistics()["packet_count"] == 2
    assert pipeline.traffic_statistics()["byte_count"] == 220
    assert pipeline.active_flow_statistics()["active_flow_count"] == 1
    assert len(pipeline.recent_alerts()) == 1
    assert (
        pipeline.detector_statistics()["detectors"]["VolumetricUdpDetector"]["alerts_emitted"]
        == 1
    )
    streamed = asyncio.run(asyncio.wait_for(queue.get(), timeout=1))
    assert streamed.alert_id == alerts[0].alert_id


def test_runtime_cooldown_suppresses_repeated_alerts():
    pipeline = runtime()
    first = datetime(2026, 1, 1, tzinfo=UTC)

    pipeline.ingest_observation(observation(first))
    first_alert = pipeline.ingest_observation(observation(first + timedelta(seconds=1)))
    repeated_alert = pipeline.ingest_observation(observation(first + timedelta(seconds=2)))

    assert len(first_alert) == 1
    assert repeated_alert == ()
    stats = pipeline.detector_statistics()["detectors"]["VolumetricUdpDetector"]
    assert stats["alerts_suppressed"] == 1