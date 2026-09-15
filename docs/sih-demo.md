# Reproducible Local SIH Demonstration

This demonstration uses only locally generated synthetic/lab PCAP files. It never opens a packet socket, targets an external address, or transmits traffic. The captures use documentation IP ranges and are not real-world evidence.

## Run the demonstration

From the repository root, using the configured `.venv`:

```powershell
python -m scripts.run_sih_demo --output artifacts/sih_demo_run
python -m scripts.benchmark --packets 5000 --flows 25 --pcap artifacts/sih_demo_run/benchmark.pcap --output artifacts/sih_demo_run/benchmark.json
```

The demo writes scenario PCAPs and `demo_report.json`. The benchmark writes measured values to `benchmark.json`.

## Dashboard procedure

Use two terminals:

```powershell
python -m vajra
python -m http.server 4173 --directory dashboard
```

Open `http://127.0.0.1:4173`, then ingest a generated scenario from a third terminal:

```powershell
Invoke-WebRequest -UseBasicParsing `
  -Method Post `
  -Uri "http://127.0.0.1:8000/ingest/pcap?path=artifacts%2Fsih_demo_run%2Fudp_volumetric_anomaly.pcap"
```

The dashboard should update from the existing API with traffic, flows, alerts, detector counters, threat analytics, and SSE alert entries. Select an alert to show its standardized ID, score method, detector source, explanation, and evidence.

## Scenario support

- **Benign traffic:** supported. The irregular TCP lab capture is processed with no alert.
- **UDP volumetric anomaly:** supported. The UDP lab capture produces `volumetric_udp_anomaly`; its regular timing may also produce the existing `c2_beaconing_periodicity` alert, which is reported rather than hidden.
- **C2 beaconing:** supported. The regular TCP lab capture produces `c2_beaconing_periodicity` with timing evidence.
- **Port scanning:** currently unsupported end to end. The existing `FlowKey` includes destination port, so each scanned port becomes a separate directional flow and the existing fan-out detector never receives one window containing the scan's port set. The demo records the separate flows and does not fabricate an alert.
- **DNS anomaly:** currently unsupported from classic PCAP ingestion. The existing parser does not populate `dns_query`, label, entropy, or record-type metadata. The demo processes the UDP/53 lab capture and reports no DNS alert rather than inventing query content.

## Benchmark meaning

The benchmark measures the current local Python pipeline over generated PCAP records using `time.perf_counter()`. It reports packets/sec, active flows/sec, total processing latency, and latency per packet for that run only. It is not a production benchmark and must not be presented as a real-world performance guarantee.