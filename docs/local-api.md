# Local Streaming API

The VAJRA API is a local, in-memory interface around the passive processing pipeline:

```text
PCAP/lab traffic -> ingestion -> directional flows -> features -> detectors -> alerts -> API
```

The runtime is independent of the frontend. It has no database or cloud dependency and never transmits packets. It keeps bounded per-flow feature windows and bounded recent alerts in memory.

## Endpoints

- `GET /health`: process health and version.
- `POST /ingest/pcap?path=<local path>`: incrementally read a local classic PCAP through the passive ingestion layer.
- `GET /traffic/stats`: observed packet, byte, protocol, and last-seen statistics.
- `GET /flows/active`: directional active flow snapshots and counters.
- `GET /alerts/recent?limit=100`: newest standardized serialized alerts.
- `GET /alerts/stream`: server-sent event stream of newly emitted alerts.
- `GET /detectors/stats`: detector evaluation, emitted-alert, and cooldown-suppression counters.
- `GET /self-test`: local foundation checks.

The default runtime does not load the offline ML artifact automatically. ML remains a separate experiment and is reported as `offline_experiment_not_loaded` in detector statistics. This avoids silently changing model versions or mixing synthetic experiment behavior into live processing.