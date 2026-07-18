"""Security policy for externally supplied ``jwks_uri`` values."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

from agent_nebula_sdk.core.errors import KeyValidationError

DnsResolver = Callable[[str], list[str]]


def system_dns_resolver(hostname: str) -> list[str]:
    """Resolve a hostname to unique textual IP addresses."""
    return sorted({str(entry[4][0]) for entry in socket.getaddrinfo(hostname, 443)})


class JwksUriPolicy:
    """Validate remote JWKS URIs and reduce SSRF exposure.

    RFC 7591 permits a client to register ``jwks_uri``. Because the value is
    attacker-controlled in an open-registration profile, the authorization
    server must apply deployment policy before fetching it.
    """

    def __init__(
        self,
        *,
        allow_http_for_loopback: bool = False,
        allow_private_networks: bool = False,
        dns_resolver: DnsResolver = system_dns_resolver,
    ) -> None:
        """Configure transport and network-range restrictions."""
        self._allow_http_for_loopback = allow_http_for_loopback
        self._allow_private_networks = allow_private_networks
        self._dns_resolver = dns_resolver

    def validate(self, uri: str) -> str:
        """Return the URI when safe or raise a stable validation error."""
        parsed = urlsplit(uri)
        if parsed.username is not None or parsed.password is not None:
            self._reject("jwks_uri must not contain user information", uri)
        if parsed.fragment:
            self._reject("jwks_uri must not contain a fragment", uri)
        if not parsed.hostname:
            self._reject("jwks_uri must contain a hostname", uri)

        hostname = parsed.hostname
        if hostname is None:
            self._reject("jwks_uri must contain a hostname", uri)
            raise AssertionError("unreachable")

        is_loopback_host = hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and self._allow_http_for_loopback and is_loopback_host
        ):
            self._reject("jwks_uri must use HTTPS", uri)

        addresses = self._dns_resolver(hostname)
        if not addresses:
            self._reject("jwks_uri hostname did not resolve", uri)
        if not self._allow_private_networks:
            for address in addresses:
                parsed_address = ipaddress.ip_address(address)
                if not parsed_address.is_global:
                    self._reject(
                        "jwks_uri resolves to a non-public network address",
                        uri,
                        address=address,
                    )
        return uri

    @staticmethod
    def _reject(message: str, uri: str, **details: str) -> None:
        """Raise one consistent URI-policy failure."""
        raise KeyValidationError(
            message,
            code="unsafe_jwks_uri",
            details={"uri": uri, **details},
        )
