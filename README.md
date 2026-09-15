# VAJRA

VAJRA (Vigilant AI for Judicious Real-time Asymmetric Analysis) is a research-prototype foundation for passive cyber-threat analysis over strictly unidirectional IP traffic.

The current project is intentionally only a foundation. It does not implement threat detection, machine-learning models, packet transmission, payload decryption, a database, or dashboard data generation.

## Requirements

- Python 3.12 or newer

## Setup

Create and activate a virtual environment, then install the package with development dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Run

Start the read-only API:

```powershell
python -m vajra
```

The API listens on `127.0.0.1:8000` by default. Configuration is read from environment variables prefixed with `VAJRA_`:

- `VAJRA_HOST`
- `VAJRA_PORT`
- `VAJRA_LOG_LEVEL`

Available endpoints:

- `GET /health` reports process health and version.
- `GET /self-test` runs non-network self-checks for the foundation.

## Test

```powershell
python -m pytest
```

## Project layout

```text
src/vajra/
  alerts/       Alert contract and evidence fields
  api/          HTTP application and routes
  detection/    Detector extension protocols; no detectors yet
  features/     Feature extraction extension point
  flows/        Unidirectional flow identity and incremental tracking
  ingestion/    Read-only observation contracts
  ml/           Future model contracts; no models yet
  config.py     Environment-backed settings
  health.py     Foundation self-checks
  logging_config.py
tests/          Unit and API tests
sample_data/    Clearly marked lab-data documentation only
dashboard/      Dashboard integration boundary documentation only
```

All sample traffic must be explicitly identified as synthetic or lab traffic. Production integrations must preserve the one-way observation constraint and must never send traffic toward an observed network.