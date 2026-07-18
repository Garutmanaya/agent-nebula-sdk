"""HTTP header codecs for RFC 9449 DPoP token use and nonce challenges.

The protocol places the proof JWT in the ``DPoP`` header and uses the ``DPoP``
authorization scheme for sender-constrained access tokens. This module keeps
HTTP syntax separate from cryptographic proof validation.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc9449.constants import (
    DPOP_AUTHORIZATION_SCHEME,
    DPOP_HEADER_NAME,
    DPOP_NONCE_HEADER_NAME,
    INVALID_DPOP_PROOF,
)


@dataclass(frozen=True, slots=True)
class DpopRequestHeaders:
    """Represent the three HTTP values used by a protected-resource request."""

    authorization: str
    proof: str

    def as_dict(self) -> dict[str, str]:
        """Return canonical HTTP header names and values for an outgoing request."""
        return {
            "Authorization": self.authorization,
            DPOP_HEADER_NAME: self.proof,
        }


class DpopHttpHeaderCodec:
    """Build and parse RFC 9449 authorization and proof headers."""

    def build_request_headers(self, *, access_token: str, proof: str) -> DpopRequestHeaders:
        """Create a protected-resource header pair using the ``DPoP`` scheme."""
        if not access_token.strip():
            raise ValueError("access_token must not be empty")
        if not proof.strip():
            raise ValueError("proof must not be empty")
        return DpopRequestHeaders(
            authorization=f"{DPOP_AUTHORIZATION_SCHEME} {access_token}",
            proof=proof,
        )

    def parse_authorization_header(self, value: str) -> str:
        """Extract a DPoP-bound access token and reject bearer-token downgrade."""
        scheme, separator, token = value.partition(" ")
        if separator != " " or scheme != DPOP_AUTHORIZATION_SCHEME or not token.strip():
            raise ProtocolValidationError(
                "Authorization header must use the DPoP scheme",
                code=INVALID_DPOP_PROOF,
            )
        return token.strip()

    @staticmethod
    def build_nonce_challenge_headers(nonce: str) -> dict[str, str]:
        """Return the RFC 9449 server nonce response header."""
        if not nonce.strip():
            raise ValueError("nonce must not be empty")
        return {DPOP_NONCE_HEADER_NAME: nonce}
