import asyncio
import struct
from pathlib import Path

import httpx

from vajra.api.app import app, create_app
from vajra.pipeline import PipelineRuntime


async def request(path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.get(path)


def test_health_endpoint():
    response = asyncio.run(request("/health"))

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_self_test_endpoint():
    response = asyncio.run(request("/self-test"))

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def _single_udp_pcap() -> bytes:
    transport = struct.pack("!HHHH", 53000, 53, 8, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28,
        1,
        0,
        64,
        17,
        0,
        b"\xc0\x00\x02\x01",
        b"\xc0\x00\x02\x02",
    )
    packet = b"\x00" * 12 + struct.pack("!H", 0x0800) + ip + transport
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1700000000, 0, len(packet), len(packet))
        + packet
    )


def test_api_ingests_pcap_and_exposes_pipeline_statistics(tmp_path: Path):
    path = tmp_path / "lab.pcap"
    path.write_bytes(_single_udp_pcap())
    local_app = create_app(PipelineRuntime())

    async def exercise():
        transport = httpx.ASGITransport(app=local_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            ingest = await client.post("/ingest/pcap", params={"path": str(path)})
            traffic = await client.get("/traffic/stats")
            flows = await client.get("/flows/active")
            recent = await client.get("/alerts/recent")
            detectors = await client.get("/detectors/stats")
        return ingest, traffic, flows, recent, detectors

    ingest, traffic, flows, recent, detectors = asyncio.run(exercise())

    assert ingest.status_code == 200
    assert ingest.json()["packets_processed"] == 1
    assert traffic.json()["packet_count"] == 1
    assert traffic.json()["protocol_distribution"] == {"UDP": 1}
    assert flows.json()["active_flow_count"] == 1
    assert recent.json() == []
    assert "detectors" in detectors.json()