"""HTTP transport port used by protocol clients and resolvers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """Transport-neutral HTTP response required by SDK protocol modules."""

    status_code: int
    headers: dict[str, str]
    body: bytes


class HttpTransport(Protocol):
    """Minimal outbound HTTP contract.

    Products can provide instrumented, policy-aware, or service-mesh transports
    without changing the protocol implementation.
    """

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Issue an HTTPS GET request and return a transport-neutral response."""
