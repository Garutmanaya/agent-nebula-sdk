"""Client-side RFC 9449 DPoP proof JWT construction.

A new proof is created for every token-endpoint or protected-resource request.
The private key never leaves the client; only its public JWK is embedded in the
JOSE header as required by RFC 9449 Section 4.2.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast
from uuid import uuid4

import jwt

from agent_nebula_sdk.core.errors import ProtocolValidationError, UnsupportedAlgorithmError
from agent_nebula_sdk.jose.thumbprint.service import JwkThumbprintService
from agent_nebula_sdk.oauth.rfc9449.constants import DPOP_PROOF_TYPE
from agent_nebula_sdk.oauth.rfc9449.hash import AccessTokenHashService
from agent_nebula_sdk.oauth.rfc9449.models import (
    BuiltDpopProof,
    DpopProofBuildRequest,
    DpopProofClaims,
    DpopSigningKey,
)
from agent_nebula_sdk.oauth.rfc9449.policy import Rfc9449Policy
from agent_nebula_sdk.oauth.rfc9449.uri import DpopTargetUriNormalizer
from agent_nebula_sdk.ports.clock import Clock


class DpopProofBuilder:
    """Build request-specific DPoP proofs for OAuth and resource requests."""

    def __init__(
        self,
        *,
        clock: Clock,
        policy: Rfc9449Policy,
        uri_normalizer: DpopTargetUriNormalizer,
        token_hash_service: AccessTokenHashService | None = None,
        thumbprint_service: JwkThumbprintService | None = None,
        proof_id_factory: Callable[[], str] | None = None,
    ) -> None:
        """Inject deterministic time, identifiers, and protocol helpers."""
        self._clock = clock
        self._policy = policy
        self._uri_normalizer = uri_normalizer
        self._token_hash = token_hash_service or AccessTokenHashService()
        self._thumbprints = thumbprint_service or JwkThumbprintService()
        self._proof_id_factory = proof_id_factory or (lambda: str(uuid4()))

    def build(
        self,
        *,
        request: DpopProofBuildRequest,
        signing_key: DpopSigningKey,
    ) -> BuiltDpopProof:
        """Create one signed proof bound to method, URI, token, and nonce."""
        if signing_key.algorithm not in self._policy.allowed_algorithms:
            raise UnsupportedAlgorithmError(
                "DPoP proof signing algorithm is not allowed",
                code="unsupported_dpop_algorithm",
                details={"algorithm": signing_key.algorithm},
            )
        self._validate_public_key_metadata(signing_key)

        claims_data: dict[str, object] = {
            "jti": self._proof_id_factory(),
            "htm": request.http_method,
            "htu": self._uri_normalizer.normalize(request.target_uri),
            "iat": int(self._clock.now().timestamp()),
        }
        if request.access_token is not None:
            claims_data["ath"] = self._token_hash.compute(request.access_token)
        if request.nonce is not None:
            claims_data["nonce"] = request.nonce
        claims = DpopProofClaims.model_validate(claims_data)

        public_jwk = signing_key.public_jwk.model_dump(
            exclude_none=True,
            exclude={"kid", "use", "key_ops", "alg"},
        )
        try:
            proof = jwt.encode(
                payload=claims.model_dump(exclude_none=True),
                key=cast(Any, signing_key.private_key),
                algorithm=signing_key.algorithm,
                headers={
                    "typ": DPOP_PROOF_TYPE,
                    "alg": signing_key.algorithm,
                    "jwk": public_jwk,
                },
            )
        except (TypeError, ValueError, jwt.PyJWTError) as exc:
            raise ProtocolValidationError(
                "DPoP proof could not be signed",
                code="dpop_proof_signing_failed",
            ) from exc

        return BuiltDpopProof(
            proof=proof,
            claims=claims,
            key_thumbprint=self._thumbprints.compute(signing_key.public_jwk),
            algorithm=signing_key.algorithm,
        )

    @staticmethod
    def _validate_public_key_metadata(signing_key: DpopSigningKey) -> None:
        """Reject public JWK metadata that conflicts with proof signing intent."""
        public_jwk = signing_key.public_jwk
        if public_jwk.use not in (None, "sig"):
            raise ProtocolValidationError(
                "DPoP public JWK is not authorized for signatures",
                code="invalid_dpop_public_jwk",
            )
        if public_jwk.key_ops not in (None, (), ("verify",)):
            raise ProtocolValidationError(
                "DPoP public JWK has incompatible key operations",
                code="invalid_dpop_public_jwk",
            )
        if public_jwk.alg is not None and public_jwk.alg != signing_key.algorithm:
            raise ProtocolValidationError(
                "DPoP algorithm conflicts with public JWK metadata",
                code="invalid_dpop_public_jwk",
            )
