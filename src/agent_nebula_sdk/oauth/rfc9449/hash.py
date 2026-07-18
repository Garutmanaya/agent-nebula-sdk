"""Access-token hash calculation for the RFC 9449 ``ath`` claim."""

from __future__ import annotations

import hashlib

from agent_nebula_sdk.core.encoding import encode_base64url


class AccessTokenHashService:
    """Compute the SHA-256 hash that binds a DPoP proof to an access token."""

    def compute(self, access_token: str) -> str:
        """Return base64url(SHA-256(ASCII(access_token))) per RFC 9449 Section 4.2."""
        if not access_token:
            raise ValueError("access_token must not be empty")
        digest = hashlib.sha256(access_token.encode("ascii")).digest()
        return encode_base64url(digest)
