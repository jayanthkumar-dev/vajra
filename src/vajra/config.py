"""Application settings loaded from environment variables."""

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime settings that do not contain network-observation data."""

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"


def get_settings() -> Settings:
    """Build settings from VAJRA-prefixed environment variables."""
    port_value = os.getenv("VAJRA_PORT", "8000")
    try:
        port = int(port_value)
    except ValueError as error:
        raise ValueError("VAJRA_PORT must be an integer") from error
    if not 1 <= port <= 65535:
        raise ValueError("VAJRA_PORT must be between 1 and 65535")

    return Settings(
        host=os.getenv("VAJRA_HOST", "127.0.0.1"),
        port=port,
        log_level=os.getenv("VAJRA_LOG_LEVEL", "INFO").upper(),
    )