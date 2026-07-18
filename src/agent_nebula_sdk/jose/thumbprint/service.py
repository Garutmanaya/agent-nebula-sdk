"""RFC 7638 JSON Web Key thumbprint service."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from agent_nebula_sdk.core.encoding import encode_base64url
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk


class JwkThumbprintService:
    """Compute deterministic JWK thumbprints according to RFC 7638 Section 3."""

    def compute(
        self,
        jwk: SupportedPublicJwk,
        *,
        hash_algorithm: Literal["sha256", "sha384", "sha512"] = "sha256",
    ) -> str:
        """Return the base64url-encoded digest of canonical required members.

        The canonical JSON representation uses only the key-type-specific
        required members, lexicographic member ordering, no insignificant
        whitespace, UTF-8 encoding, and an explicit hash algorithm.
        """
        canonical_json = self.canonical_json(jwk)
        digest = hashlib.new(hash_algorithm, canonical_json.encode("utf-8")).digest()
        return encode_base64url(digest)

    def canonical_json(self, jwk: SupportedPublicJwk) -> str:
        """Return the RFC 7638 canonical JSON representation before hashing."""
        return json.dumps(
            jwk.required_thumbprint_members(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
