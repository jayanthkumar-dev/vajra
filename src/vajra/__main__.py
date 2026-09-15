"""Command-line entry point for the VAJRA API."""

import uvicorn

from vajra.config import get_settings
from vajra.logging_config import configure_logging


def main() -> None:
    """Run the local read-only API."""
    settings = get_settings()
    configure_logging(settings.log_level)
    uvicorn.run("vajra.api.app:app", host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()