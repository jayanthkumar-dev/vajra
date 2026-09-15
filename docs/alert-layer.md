# Standardized Alert Layer

The alert layer is independent of the API and frontend. It validates and serializes alerts produced by deterministic or statistical detectors.

## Required Contract

Each `Alert` contains a UTC-aware timestamp, deterministic SHA-256 `alert_id`, directional `flow_id`, threat class, mapped severity, numeric score, score method, detector/model source, detection method, supporting evidence, relevant feature values, and explanation.

## Scoring and Severity

Current rule/statistical detectors use `matched_signals_fraction`: the number of configured signals that matched divided by the number of configured signals. This is a deterministic heuristic score, not a probability, confidence estimate, trained-model output, or accuracy claim.

Severity is mapped from that score:

- `< 0.50`: `low`
- `0.50` to `< 0.75`: `medium`
- `0.75` to `< 0.90`: `high`
- `>= 0.90`: `critical`

An alert with a mismatched severity is rejected by validation.

## Deduplication

`AlertDeduplicator` suppresses repeated alerts during a configurable cooldown keyed by directional flow ID, threat class, and detector source. It does not merge or discard distinct detection classes.

`to_dict()` and `to_json()` provide frontend-independent serialization. No frontend state or dashboard behavior is required to create, validate, deduplicate, or serialize an alert.