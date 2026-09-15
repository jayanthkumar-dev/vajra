"""Run the reproducible local VAJRA SIH demonstration.

All generated captures are synthetic/lab traffic. This script writes PCAP files
locally and uses the existing FastAPI ASGI app; it never opens a packet socket.
"""

import argparse
import asyncio
import json
import shutil
from pathlib import Path

import httpx

from scripts.demo_support import _PCAP_HEADER, write_tcp_pcap, write_udp_pcap
from vajra.api.app import create_app
from vajra.pipeline import PipelineRuntime


def create_scenarios(directory: Path) -> dict[str, Path]:
    """Create the five controlled synthetic/lab captures."""
    return {
        "benign_traffic": write_tcp_pcap(
            directory / "benign_traffic.pcap",
            packet_count=5,
            interval_microseconds=400_000,
            payload_size=20,
        ),
        "udp_volumetric_anomaly": write_udp_pcap(
            directory / "udp_volumetric_anomaly.pcap",
            packet_count=100,
            interval_microseconds=10_000,
            payload_size=200,
        ),
        "port_scanning": _write_port_scan_capture(directory / "port_scanning.pcap"),
        "c2_beaconing": write_tcp_pcap(
            directory / "c2_beaconing.pcap",
            packet_count=12,
            interval_microseconds=10_000_000,
            payload_size=20,
        ),
        "dns_anomaly": write_udp_pcap(
            directory / "dns_anomaly.pcap",
            packet_count=20,
            interval_microseconds=10_000,
            destination_port=53,
            payload_size=80,
            intervals_microseconds=[2_000_000, 3_000_000, 2_000_000, 3_000_000, 2_000_000] * 4,
        ),
    }


def _write_port_scan_capture(path: Path) -> Path:
    """Create one packet per destination port to expose current flow granularity."""
    records = []
    for index, destination_port in enumerate(range(20, 40)):
        packet_path = path.with_name(f".port_scan_{index}.pcap")
        write_udp_pcap(
            packet_path,
            packet_count=1,
            interval_microseconds=0,
            destination_port=destination_port,
            payload_size=0,
        )
        records.append(packet_path.read_bytes()[24:])
        packet_path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_PCAP_HEADER + b"".join(records))
    return path


async def run_scenario(name: str, path: Path) -> dict[str, object]:
    """Run one scenario through API routes and consume one in-memory SSE alert when available."""
    runtime = PipelineRuntime()
    application = create_app(runtime)
    queue = runtime.subscribe()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://demo.local") as client:
        ingest = await client.post("/ingest/pcap", params={"path": str(path)})
        traffic = await client.get("/traffic/stats")
        flows = await client.get("/flows/active")
        alerts = await client.get("/alerts/recent")
        detectors = await client.get("/detectors/stats")
    streamed_alert = None
    if not alerts.json() and ingest.json()["alerts_emitted"]:
        raise AssertionError("API reported alerts but recent-alert endpoint was empty")
    if ingest.json()["alerts_emitted"]:
        streamed_alert = (await asyncio.wait_for(queue.get(), timeout=1)).to_dict()
    return {
        "scenario": name,
        "pcap": str(path),
        "ingest": ingest.json(),
        "traffic": traffic.json(),
        "flows": flows.json(),
        "alerts": alerts.json(),
        "detectors": detectors.json(),
        "sse_alert_received": streamed_alert is not None,
        "sse_alert": streamed_alert,
    }


def classify_result(name: str, result: dict[str, object]) -> dict[str, object]:
    alerts = result["alerts"]
    detected_classes = sorted({alert["threat_class"] for alert in alerts})
    expected = {
        "benign_traffic": [],
        "udp_volumetric_anomaly": ["volumetric_udp_anomaly"],
        "c2_beaconing": ["c2_beaconing_periodicity"],
        "port_scanning": [],
        "dns_anomaly": [],
    }[name]
    limitations = {
        "port_scanning": (
            "unsupported: destination-port fan-out is split into separate directional flows "
            "by the current FlowKey"
        ),
        "dns_anomaly": (
            "unsupported: classic PCAP ingestion does not currently populate dns_query metadata"
        ),
    }
    return {
        "status": (
            "detected"
            if expected and all(item in detected_classes for item in expected)
            else "unsupported_current_implementation"
            if name in {"port_scanning", "dns_anomaly"}
            else "benign_no_alert"
        ),
        "detected_classes": detected_classes,
        "expected_classes": expected,
        "limitation": limitations.get(name),
        "evidence_present": all(
            bool(alert.get("evidence")) and bool(alert.get("feature_values"))
            for alert in alerts
        ),
        "api_alert_count": len(alerts),
        "sse_alert_received": result["sse_alert_received"],
    }


async def main_async(output_directory: Path) -> dict[str, object]:
    if output_directory.exists():
        shutil.rmtree(output_directory)
    scenarios = create_scenarios(output_directory)
    reports = {}
    for name, path in scenarios.items():
        result = await run_scenario(name, path)
        reports[name] = {"result": classify_result(name, result), "details": result}
    report = {
        "provenance": "synthetic/lab traffic generated locally; not real-world traffic",
        "reports": reports,
    }
    (output_directory / "demo_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the local VAJRA SIH synthetic/lab demonstration"
    )
    parser.add_argument("--output", type=Path, default=Path("artifacts/sih_demo"))
    args = parser.parse_args()
    print(json.dumps(asyncio.run(main_async(args.output)), indent=2))


if __name__ == "__main__":
    main()