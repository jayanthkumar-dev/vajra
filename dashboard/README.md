# VAJRA Dashboard

This is a dependency-free static dashboard built from the Stitch visual reference. It consumes the existing FastAPI API and does not duplicate backend logic or invent telemetry.

## Run locally

Start the backend from the repository root:

```powershell
python -m vajra
```

In another terminal, serve this directory:

```powershell
python -m http.server 4173 --directory dashboard
```

Open `http://127.0.0.1:4173`. The dashboard reads `/health`, `/self-test`, `/traffic/stats`, `/flows/active`, `/alerts/recent`, `/detectors/stats`, and `/alerts/stream` from the local backend at `http://127.0.0.1:8000`.

All displayed metrics and alerts come from API responses. Empty runtime state is shown as `No observed traffic` or `No alerts observed`. Synthetic/lab provenance is not inferred by the frontend; it must be supplied and labeled by the data source.