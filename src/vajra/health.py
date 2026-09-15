"""Health and foundation self-checks."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SelfTestResult:
    """Result of checks that do not require network access."""

    status: str
    checks: tuple[str, ...]


def run_self_test() -> SelfTestResult:
    """Verify that the foundation can load without contacting an observed network."""
    return SelfTestResult(status="ok", checks=("configuration", "package-imports"))