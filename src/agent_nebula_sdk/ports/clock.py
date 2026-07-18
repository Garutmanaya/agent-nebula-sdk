"""Injectable clock abstraction for deterministic protocol validation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    """Return the current timezone-aware UTC instant."""

    def now(self) -> datetime:
        """Return the current UTC instant."""


class SystemClock:
    """Production clock implementation backed by the operating system."""

    def now(self) -> datetime:
        """Return the current timezone-aware UTC instant."""
        return datetime.now(UTC)
