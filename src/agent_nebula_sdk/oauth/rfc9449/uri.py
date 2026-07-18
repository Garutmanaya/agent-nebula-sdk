"""HTTP target URI validation and normalization for RFC 9449 proofs."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc9449.constants import INVALID_DPOP_PROOF
from agent_nebula_sdk.oauth.rfc9449.policy import Rfc9449Policy


class DpopTargetUriNormalizer:
    """Normalize an HTTP target URI for exact ``htu`` comparison.

    RFC 9449 Section 4.2 excludes query and fragment components from ``htu``.
    Scheme and host are compared case-insensitively through URI normalization,
    while path and explicit non-default ports remain significant.
    """

    def __init__(self, *, policy: Rfc9449Policy) -> None:
        """Inject the deployment's HTTPS and fragment validation policy."""
        self._policy = policy

    def normalize(self, uri: str) -> str:
        """Return an absolute normalized URI without query or fragment."""
        parsed = urlsplit(uri)
        if not parsed.scheme or not parsed.netloc:
            self._invalid("DPoP target URI must be absolute")
        if self._policy.require_https_target and parsed.scheme.lower() != "https":
            self._invalid("DPoP target URI must use HTTPS")
        if self._policy.reject_uri_fragments and parsed.fragment:
            self._invalid("DPoP target URI must not contain a fragment")

        hostname = parsed.hostname
        if hostname is None:
            self._invalid("DPoP target URI must contain a host")
        assert hostname is not None
        scheme = str(parsed.scheme).lower()
        host = hostname.lower()
        port = parsed.port
        default_port = 443 if scheme == "https" else 80
        authority = host if port in (None, default_port) else f"{host}:{port}"
        path = parsed.path or "/"
        return str(urlunsplit((scheme, authority, path, "", "")))

    @staticmethod
    def _invalid(message: str) -> None:
        """Raise a stable RFC 9449 proof-validation error."""
        raise ProtocolValidationError(message, code=INVALID_DPOP_PROOF)
