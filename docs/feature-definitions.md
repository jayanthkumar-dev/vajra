# Feature Definitions

`BasicFeatureExtractor` operates on a finite window of `PacketObservation` values. It uses only metadata available from passive observation. Missing metadata makes the affected feature unavailable and is recorded in `FeatureResult.unavailable`; values are never guessed.

## Traffic

- `packet_count`: number of observed packets in the window.
- `byte_count`: sum of packet lengths. Unavailable when any packet length is missing.
- `packets_per_sec`: packet count divided by the window duration, where duration is `max(timestamp) - min(timestamp)`. Unavailable for a zero-duration window.
- `bytes_per_sec`: byte count divided by the same duration. Unavailable when byte count or duration is unavailable.
- `mean_packet_size`: arithmetic mean of packet lengths. Unavailable when any length is missing.
- `packet_size_variation`: population standard deviation of packet lengths. Unavailable when any length is missing.

## Timing and Bursts

- `mean_inter_arrival_time`: mean of adjacent timestamp gaps after timestamp ordering. Requires at least two observations.
- `inter_arrival_variation`: population standard deviation of those gaps. Requires at least two observations.
- `burst_count`: number of groups whose adjacent gaps are at most `burst_gap` (one second by default). Requires at least two observations.
- `max_burst_size`: largest group under the same burst rule. Requires at least two observations.
- `burst_packet_fraction`: largest burst divided by packet count. Requires at least two observations.

## Distribution

- `destination_fan_out`: count of distinct observed destination addresses.
- `destination_port_fan_out`: count of distinct non-null destination ports.
- `source_frequency` and `destination_frequency`: observed address-to-packet-count maps.
- `protocol_distribution`: normalized protocol-to-packet-count map.

## TCP Flags

`tcp_flag_packet_count` and `tcp_flag_distribution` are emitted only when TCP observations include `tcp_flags`. The distribution counts packets containing each observed FIN, SYN, RST, PSH, ACK, URG, ECE, or CWR bit. No TCP state or handshake is inferred.

## DNS Metadata

DNS values are emitted only when an upstream passive parser supplies `dns_query` or `dns_record_type`; the feature extractor does not inspect or decrypt packet payloads.

- `dns_query_length_mean`: mean query-string character length.
- `dns_label_count_mean`: mean count of dot-separated labels after trimming terminal dots.
- `dns_query_entropy_mean`: mean Shannon entropy of query characters.
- `dns_query_frequency`: count of supplied queries in the window.
- `dns_record_type_distribution`: supplied record-type-to-count map, when record types are available.

## TLS and QUIC Metadata

Packet-size and timing features apply to any supplied window, including TLS or QUIC traffic, without decrypting payloads. When an upstream passive parser supplies metadata, the extractor emits `tls_handshake_distribution`, `tls_fingerprint_distribution`, `quic_handshake_distribution`, or `quic_fingerprint_distribution`. No handshake, fingerprint, or response is inferred when those fields are absent.