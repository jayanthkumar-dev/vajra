"""Read-only HTTP application for foundation status."""

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from vajra import __version__
from vajra.health import run_self_test
from vajra.pipeline import PipelineRuntime


def create_app(runtime: PipelineRuntime | None = None) -> FastAPI:
    """Create the local API around an in-memory pipeline runtime."""
    application = FastAPI(title="VAJRA", version=__version__)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:4173", "http://localhost:4173"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    application.state.runtime = runtime or PipelineRuntime()

    @application.get("/health")
    def health() -> dict[str, str]:
        """Return process health without claiming traffic-analysis performance."""
        return {"status": "ok", "version": __version__}

    @application.get("/self-test")
    def self_test() -> dict[str, object]:
        """Run local foundation checks without network access."""
        result = run_self_test()
        return {"status": result.status, "checks": list(result.checks)}

    @application.post("/ingest/pcap")
    def ingest_pcap(request: Request, path: str = Query(..., min_length=1)) -> dict[str, int]:
        """Process a local PCAP path incrementally through the passive pipeline."""
        try:
            return request.app.state.runtime.ingest_pcap(path)
        except FileNotFoundError as error:
            raise HTTPException(status_code=404, detail="PCAP file was not found") from error
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @application.get("/traffic/stats")
    def traffic_statistics(request: Request) -> dict[str, object]:
        return request.app.state.runtime.traffic_statistics()

    @application.get("/flows/active")
    def active_flow_statistics(request: Request) -> dict[str, object]:
        return request.app.state.runtime.active_flow_statistics()

    @application.get("/alerts/recent")
    def recent_alerts(
        request: Request,
        limit: int = Query(100, ge=1, le=1000),
    ) -> list[dict[str, object]]:
        return request.app.state.runtime.recent_alerts(limit)

    @application.get("/detectors/stats")
    def detector_statistics(request: Request) -> dict[str, object]:
        return request.app.state.runtime.detector_statistics()

    @application.get("/alerts/stream")
    async def alert_stream(request: Request) -> StreamingResponse:
        return StreamingResponse(
            request.app.state.runtime.alert_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return application


app = create_app()