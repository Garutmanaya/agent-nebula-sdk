"""Unit tests for the production clock adapter."""

from __future__ import annotations

from datetime import UTC

from agent_nebula_sdk.ports.clock import SystemClock


def test_system_clock_returns_timezone_aware_utc() -> None:
    """Protocol timestamps always use timezone-aware UTC instants."""
    current = SystemClock().now()

    assert current.tzinfo == UTC
