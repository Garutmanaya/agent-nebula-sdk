"""RFC 8414 well-known URL construction and issuer validation."""

from __future__ import annotations

from urllib.parse import SplitResult, urlsplit, urlunsplit

from agent_nebula_sdk.core.errors import ProtocolValidationError


def authorization_server_metadata_url(issuer: str) -> str:
    """Build the RFC 8414 well-known URL using path insertion."""
    parsed = validate_issuer(issuer)
    suffix = parsed.path.lstrip("/")
    path = "/.well-known/oauth-authorization-server"
    if suffix:
        path = f"{path}/{suffix}"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def openid_configuration_urls(issuer: str) -> tuple[str, ...]:
    """Build OpenID Connect discovery fallbacks for interoperability.

    This is not RFC 8414 behavior; it is retained as a compatibility helper
    for SDK consumers that also support OpenID Provider metadata discovery.
    """
    parsed = validate_issuer(issuer)
    suffix = parsed.path.lstrip("/")
    inserted_path = "/.well-known/openid-configuration"
    if suffix:
        inserted_path = f"{inserted_path}/{suffix}"
    inserted = urlunsplit((parsed.scheme, parsed.netloc, inserted_path, "", ""))
    if not suffix:
        return (inserted,)
    appended_path = f"{parsed.path.rstrip('/')}/.well-known/openid-configuration"
    appended = urlunsplit((parsed.scheme, parsed.netloc, appended_path, "", ""))
    return (inserted, appended)


def validate_issuer(issuer: str) -> SplitResult:
    """Validate an RFC 8414 issuer URL before discovery."""
    parsed = urlsplit(issuer)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ProtocolValidationError("issuer must be an absolute HTTPS URL", code="invalid_issuer")
    if parsed.query or parsed.fragment:
        raise ProtocolValidationError(
            "issuer must not contain query or fragment components",
            code="invalid_issuer",
        )
    return parsed
