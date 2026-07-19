"""Security and deployment policy for MCP Client ID Metadata Documents."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.jose.jwks.uri_policy import DnsResolver, system_dns_resolver
from agent_nebula_sdk.mcp.client_id_metadata.models import (
    ClientIdMetadataDocument,
    validate_client_identifier_url,
)


@dataclass(frozen=True, slots=True)
class ClientIdMetadataPolicy:
    """Define SSRF, redirect, authentication, and domain restrictions.

    Defaults are suitable for an Internet-facing authorization server. Local
    development can inject a deterministic DNS resolver and explicitly permit
    private networks without weakening production defaults.
    """

    allow_query_component: bool = False
    allow_private_networks: bool = False
    allow_loopback_redirects: bool = True
    require_private_key_jwt: bool = False
    allowed_client_hosts: frozenset[str] = frozenset()
    dns_resolver: DnsResolver = system_dns_resolver

    def validate_client_id(self, client_id: str) -> str:
        """Validate URL syntax, host policy, DNS resolution, and network range."""
        try:
            validate_client_identifier_url(
                client_id,
                allow_query=self.allow_query_component,
            )
        except ValueError as exc:
            raise ProtocolValidationError(
                str(exc),
                code="invalid_client_id_metadata_url",
                details={"client_id": client_id},
            ) from exc

        hostname = urlsplit(client_id).hostname
        if hostname is None:
            raise AssertionError("validated client identifier has no hostname")
        if self.allowed_client_hosts and hostname not in self.allowed_client_hosts:
            raise ProtocolValidationError(
                "client metadata host is not allowed",
                code="client_metadata_host_not_allowed",
                details={"hostname": hostname},
            )
        try:
            addresses = self.dns_resolver(hostname)
        except OSError as exc:
            raise ProtocolValidationError(
                "client metadata hostname could not be resolved",
                code="client_metadata_dns_failure",
                details={"hostname": hostname},
            ) from exc
        if not addresses:
            raise ProtocolValidationError(
                "client metadata hostname did not resolve",
                code="client_metadata_dns_failure",
                details={"hostname": hostname},
            )
        if not self.allow_private_networks:
            for address in addresses:
                if not ipaddress.ip_address(address).is_global:
                    raise ProtocolValidationError(
                        "client metadata hostname resolves to a non-public address",
                        code="unsafe_client_metadata_address",
                        details={"hostname": hostname, "address": address},
                    )
        return client_id

    def validate_document(self, document: ClientIdMetadataDocument) -> None:
        """Apply MCP-specific metadata and redirect-URI policy."""
        if (
            self.require_private_key_jwt
            and document.token_endpoint_auth_method != "private_key_jwt"
        ):
            raise ProtocolValidationError(
                "MCP client must use private_key_jwt under the active policy",
                code="client_authentication_method_not_allowed",
            )
        for redirect_uri in document.redirect_uris:
            parsed = urlsplit(redirect_uri)
            is_loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            if parsed.fragment:
                raise ProtocolValidationError(
                    "redirect URI must not contain a fragment",
                    code="invalid_client_redirect_uri",
                    details={"redirect_uri": redirect_uri},
                )
            if parsed.scheme == "https" and parsed.hostname:
                continue
            if (
                self.allow_loopback_redirects
                and parsed.scheme == "http"
                and is_loopback
                and parsed.path
            ):
                continue
            raise ProtocolValidationError(
                "redirect URI must use HTTPS or an allowed loopback HTTP URI",
                code="invalid_client_redirect_uri",
                details={"redirect_uri": redirect_uri},
            )
