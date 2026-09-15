"""Measure actual local VAJRA ingestion throughput and latency."""

import argparse
import json
import time
from pathlib import Path

from scripts.demo_support import write_udp_pcap
from vajra.pipeline import PipelineRuntime


def measure(packet_count: int, flow_count: int, output: Path) -> dict[str, float | int | str]:
    """Generate a synthetic capture and measure the existing runtime processing."""
    if packet_count < flow_count or flow_count < 1:
        raise ValueError("packet_count must be at least flow_count and flow_count must be positive")
    write_udp_pcap(output, packet_count=packet_count, payload_size=80, flow_count=flow_count)
    runtime = PipelineRuntime()
    start = time.perf_counter()
    result = runtime.ingest_pcap(output)
    elapsed = time.perf_counter() - start
    return {
        "provenance": "synthetic/lab traffic generated locally",
        "packet_count": result["packets_processed"],
        "flow_count": result["active_flow_count"],
        "elapsed_seconds": elapsed,
        "packets_per_second": result["packets_processed"] / elapsed if elapsed else 0.0,
        "flows_per_second": result["active_flow_count"] / elapsed if elapsed else 0.0,
        "processing_latency_seconds": elapsed,
        "processing_latency_seconds_per_packet": (
            elapsed / result["packets_processed"] if result["packets_processed"] else 0.0
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure local VAJRA pipeline performance")
    parser.add_argument("--packets", type=int, default=5000)
    parser.add_argument("--flows", type=int, default=1)
    parser.add_argument("--pcap", type=Path, default=Path("artifacts/sih_demo/benchmark.pcap"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/sih_demo/benchmark.json"))
    args = parser.parse_args()
    result = measure(args.packets, args.flows, args.pcap)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()