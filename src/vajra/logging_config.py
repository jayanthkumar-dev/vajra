"""Logging setup for the application process."""

import logging


def configure_logging(level: str) -> None:
    """Configure a concise process-wide logging format."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )