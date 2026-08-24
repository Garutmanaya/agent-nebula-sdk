"""RFC 9728 protected-resource metadata well-known URL discovery."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from agent_nebula_sdk.core.errors import ProtocolValidationError


def protected_resource_metadata_urls(resource: str) -> tuple[str, ...]:
    """Build RFC 9728 path-specific and root discovery candidates."""
    parsed = urlsplit(resource)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ProtocolValidationError(
            "resource must be an absolute HTTPS URL",
            code="invalid_resource",
        )
    if parsed.fragment:
        raise ProtocolValidationError(
            "resource must not contain a fragment",
            code="invalid_resource",
        )
    suffix = parsed.path.lstrip("/")
    path_specific = "/.well-known/oauth-protected-resource"
    if suffix:
        path_specific = f"{path_specific}/{suffix}"
    first = urlunsplit((parsed.scheme, parsed.netloc, path_specific, "", ""))
    root = urlunsplit(
        (parsed.scheme, parsed.netloc, "/.well-known/oauth-protected-resource", "", "")
    )
    return (first,) if first == root else (first, root)
