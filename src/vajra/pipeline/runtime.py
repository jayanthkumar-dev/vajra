"""Frontend-independent in-memory VAJRA processing runtime."""

import asyncio
from collections import Counter, deque
from collections.abc import AsyncIterator, Iterable
from datetime import datetime, timedelta
from pathlib import Path

from vajra.alerts import Alert, AlertDeduplicator
from vajra.detection import DetectionEngine, Detector, default_detectors
from vajra.features import BasicFeatureExtractor
from vajra.flows import FlowKey, FlowTracker
from vajra.ingestion import PacketObservation, read_pcap


class PipelineRuntime:
    """Process passive observations without a database or network side effects."""

    def __init__(
        self,
        *,
        max_flows: int = 10_000,
        inactivity_timeout: timedelta = timedelta(minutes=5),
        window_size: int = 512,
        recent_alert_limit: int = 1_000,
        detectors: Iterable[Detector] | None = None,
    ) -> None:
        if window_size < 1 or recent_alert_limit < 1:
            raise ValueError("window_size and recent_alert_limit must be positive")
        self.flow_tracker = FlowTracker(
            inactivity_timeout=inactivity_timeout,
            max_flows=max_flows,
        )
        self.feature_extractor = BasicFeatureExtractor()
        self.detection_engine = DetectionEngine(
            tuple(detectors) if detectors is not None else default_detectors()
        )
        self.alert_deduplicator = AlertDeduplicator(cooldown=timedelta(minutes=5))
        self._windows: dict[FlowKey, deque[PacketObservation]] = {}
        self._window_size = window_size
        self._recent_alerts: deque[Alert] = deque(maxlen=recent_alert_limit)
        self._subscribers: set[asyncio.Queue[Alert]] = set()
        self._packet_count = 0
        self._byte_count = 0
        self._protocol_counts: Counter[str] = Counter()
        self._last_seen: datetime | None = None
        self._detector_stats: dict[str, dict[str, int]] = {
            detector.__class__.__name__: {
                "evaluations": 0,
                "alerts_emitted": 0,
                "alerts_suppressed": 0,
            }
            for detector in self.detection_engine.detectors
        }

    def ingest_observation(self, observation: PacketObservation) -> tuple[Alert, ...]:
        """Process one passive observation and return newly emitted alerts."""
        snapshot = self.flow_tracker.observe(observation)
        key = snapshot.key
        window = self._windows.setdefault(key, deque(maxlen=self._window_size))
        window.append(observation)
        self._packet_count += 1
        self._byte_count += observation.packet_length or 0
        self._protocol_counts[observation.protocol.upper()] += 1
        self._last_seen = (
            max(self._last_seen, observation.timestamp)
            if self._last_seen
            else observation.timestamp
        )

        features = self.feature_extractor.extract(list(window))
        emitted: list[Alert] = []
        for detector in self.detection_engine.detectors:
            name = detector.__class__.__name__
            self._detector_stats[name]["evaluations"] += 1
            for alert in detector.evaluate(snapshot, features):
                accepted = self.alert_deduplicator.accept(alert)
                if accepted is None:
                    self._detector_stats[name]["alerts_suppressed"] += 1
                    continue
                self._detector_stats[name]["alerts_emitted"] += 1
                self._recent_alerts.append(accepted)
                self._publish(accepted)
                emitted.append(accepted)
        self._purge_inactive_windows()
        return tuple(emitted)

    def ingest_pcap(self, path: str | Path) -> dict[str, int]:
        """Read a local PCAP incrementally through the existing passive reader."""
        packet_count = 0
        alert_count = 0
        for observation in read_pcap(path):
            packet_count += 1
            alert_count += len(self.ingest_observation(observation))
        return {
            "packets_processed": packet_count,
            "alerts_emitted": alert_count,
            "active_flow_count": len(self.flow_tracker.snapshot()),
        }

    def traffic_statistics(self) -> dict[str, object]:
        """Return observed traffic counters without inventing missing values."""
        return {
            "packet_count": self._packet_count,
            "byte_count": self._byte_count,
            "protocol_distribution": dict(self._protocol_counts),
            "last_seen": self._last_seen.isoformat() if self._last_seen else None,
        }

    def active_flow_statistics(self) -> dict[str, object]:
        """Return current directional flow snapshots."""
        flows = []
        for snapshot in self.flow_tracker.snapshot():
            flows.append(
                {
                    "flow_id": snapshot.flow_id,
                    "source_ip": snapshot.key.source_ip,
                    "destination_ip": snapshot.key.destination_ip,
                    "source_port": snapshot.key.source_port,
                    "destination_port": snapshot.key.destination_port,
                    "protocol": snapshot.key.protocol,
                    "first_seen": snapshot.first_seen.isoformat(),
                    "last_seen": snapshot.last_seen.isoformat(),
                    "duration_seconds": snapshot.duration.total_seconds(),
                    "packet_count": snapshot.packet_count,
                    "byte_count": snapshot.byte_count,
                }
            )
        return {"active_flow_count": len(flows), "flows": flows}

    def recent_alerts(self, limit: int = 100) -> list[dict[str, object]]:
        """Return recent serialized alerts, newest first."""
        if limit < 1:
            raise ValueError("limit must be positive")
        return [alert.to_dict() for alert in list(self._recent_alerts)[-limit:][::-1]]

    def detector_statistics(self) -> dict[str, object]:
        """Return detector evaluation and cooldown counters."""
        return {
            "ml_status": "offline_experiment_not_loaded",
            "detectors": self._detector_stats,
        }

    def subscribe(self) -> asyncio.Queue[Alert]:
        """Register an in-memory alert subscriber for the SSE stream."""
        queue: asyncio.Queue[Alert] = asyncio.Queue(maxsize=100)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Alert]) -> None:
        self._subscribers.discard(queue)

    async def alert_stream(self) -> AsyncIterator[str]:
        """Yield serialized alerts as server-sent events until disconnected."""
        queue = self.subscribe()
        try:
            while True:
                alert = await queue.get()
                yield f"data: {alert.to_json()}\n\n"
        finally:
            self.unsubscribe(queue)

    def _publish(self, alert: Alert) -> None:
        for queue in tuple(self._subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(alert)

    def _purge_inactive_windows(self) -> None:
        active_keys = {snapshot.key for snapshot in self.flow_tracker.snapshot()}
        for key in tuple(self._windows):
            if key not in active_keys:
                del self._windows[key]