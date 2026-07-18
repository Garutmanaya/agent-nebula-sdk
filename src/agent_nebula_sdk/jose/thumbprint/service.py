"""RFC 7638 JSON Web Key thumbprint service."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from agent_nebula_sdk.core.encoding import encode_base64url
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk


class JwkThumbprintService:
    """Compute deterministic JWK thumbprints according to RFC 7638 Section 3.

    Class responsibility
    -----------------------
    Implements a focused protocol service with no product-specific persistence.

    Standards
    ---------
    * RFC 7638

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    def compute(
        self,
        jwk: SupportedPublicJwk,
        *,
        hash_algorithm: Literal["sha256", "sha384", "sha512"] = "sha256",
    ) -> str:
        """Return the base64url-encoded digest of canonical required members.

        Function responsibility
        -----------------------
        Implements a focused protocol service with no product-specific persistence.

        Standards
        ---------
        * RFC 7638

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        canonical_json = self.canonical_json(jwk)
        digest = hashlib.new(hash_algorithm, canonical_json.encode("utf-8")).digest()
        return encode_base64url(digest)

    def canonical_json(self, jwk: SupportedPublicJwk) -> str:
        """Return the RFC 7638 canonical JSON representation before hashing.

        Function responsibility
        -----------------------
        Implements a focused protocol service with no product-specific persistence.

        Standards
        ---------
        * RFC 7638

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        return json.dumps(
            jwk.required_thumbprint_members(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
