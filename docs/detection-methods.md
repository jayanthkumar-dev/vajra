# Detection Methods

VAJRA currently implements deterministic rules and simple statistical heuristics only. It does not contain a trained AI or ML model, and alert scores are not probabilities, confidence values, accuracy measurements, or benchmark results.

Every detector consumes `FeatureResult` values computed from passive observations. Missing features prevent the affected detector from alerting rather than being replaced with invented values. Alerts include the configured signals, observed evidence, an explanation, and `detection_method`.

## Prototype Detectors

- `volumetric_udp_anomaly` is a rule requiring predominantly UDP traffic plus multiple configurable volume signals: packet count, packets per second, and/or bytes per second.
- `reconnaissance_port_scanning` is a rule requiring both a minimum packet count and destination-port fan-out.
- `c2_beaconing_periodicity` is a statistical heuristic requiring enough packets and a low inter-arrival coefficient of variation.
- `dns_tunnelling_dga_like_anomaly` is a statistical heuristic requiring repeated DNS queries and multiple query-complexity signals such as length, entropy, and label count.
- `data_exfiltration_like_volume` is a one-way volume rule requiring multiple signals among byte count, byte rate, and mean packet size. It does not compare against a reverse direction and does not claim that a response exists.
- `encrypted_session_metadata_anomaly` is a metadata-only statistical heuristic requiring supplied TLS/QUIC handshake or fingerprint metadata plus high packet-size and timing variability. It never decrypts payloads.

## Score Meaning

The score is the fraction of configured signals that matched for the alert. It is a deterministic heuristic summary used to show rule support. It must not be presented as model confidence or maliciousness probability.

ML detection is intentionally not implemented. A future ML layer would need separate training, validation, and test data, leakage controls, and independently measured results before making model claims.