"""Authorization-server and resource-server validation for RFC 9449 proofs.

The validator performs JOSE routing checks, parses the embedded public JWK,
verifies the proof signature, validates request binding and time, enforces
optional nonce and access-token hash requirements, and atomically rejects
replayed proof identifiers.
"""

from __future__ import annotations

from typing import Any, NoReturn

import jwt
from pydantic import TypeAdapter, ValidationError

from agent_nebula_sdk.core.errors import ProtocolValidationError, UnsupportedAlgorithmError
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk
from agent_nebula_sdk.jose.thumbprint.service import JwkThumbprintService
from agent_nebula_sdk.oauth.rfc9449.constants import DPOP_PROOF_TYPE, INVALID_DPOP_PROOF
from agent_nebula_sdk.oauth.rfc9449.hash import AccessTokenHashService
from agent_nebula_sdk.oauth.rfc9449.models import DpopProofClaims, ValidatedDpopProof
from agent_nebula_sdk.oauth.rfc9449.policy import Rfc9449Policy
from agent_nebula_sdk.oauth.rfc9449.ports import DpopNonceStore, DpopReplayStore
from agent_nebula_sdk.oauth.rfc9449.uri import DpopTargetUriNormalizer
from agent_nebula_sdk.ports.clock import Clock

_PUBLIC_JWK_ADAPTER: TypeAdapter[SupportedPublicJwk] = TypeAdapter(SupportedPublicJwk)


class DpopProofValidator:
    """Validate DPoP proofs at token and protected-resource boundaries."""

    def __init__(
        self,
        *,
        clock: Clock,
        policy: Rfc9449Policy,
        replay_store: DpopReplayStore,
        uri_normalizer: DpopTargetUriNormalizer,
        nonce_store: DpopNonceStore | None = None,
        token_hash_service: AccessTokenHashService | None = None,
        thumbprint_service: JwkThumbprintService | None = None,
    ) -> None:
        """Inject deterministic time, persistence ports, and protocol helpers."""
        self._clock = clock
        self._policy = policy
        self._replay_store = replay_store
        self._uri_normalizer = uri_normalizer
        self._nonce_store = nonce_store
        self._token_hash = token_hash_service or AccessTokenHashService()
        self._thumbprints = thumbprint_service or JwkThumbprintService()

    def validate_token_request(
        self,
        proof: str,
        *,
        http_method: str,
        target_uri: str,
        nonce_context: str | None = None,
    ) -> ValidatedDpopProof:
        """Validate a token-endpoint proof, where ``ath`` is not required."""
        return self._validate(
            proof,
            http_method=http_method,
            target_uri=target_uri,
            access_token=None,
            nonce_context=nonce_context,
            require_access_token_hash=False,
        )

    def validate_resource_request(
        self,
        proof: str,
        *,
        http_method: str,
        target_uri: str,
        access_token: str,
        expected_key_thumbprint: str,
        nonce_context: str | None = None,
    ) -> ValidatedDpopProof:
        """Validate a protected-resource proof and its access-token binding."""
        validated = self._validate(
            proof,
            http_method=http_method,
            target_uri=target_uri,
            access_token=access_token,
            nonce_context=nonce_context,
            require_access_token_hash=self._policy.require_ath_for_resource_request,
        )
        if validated.key_thumbprint != expected_key_thumbprint:
            self._invalid("DPoP proof key does not match the access-token cnf.jkt claim")
        return validated

    def _validate(
        self,
        proof: str,
        *,
        http_method: str,
        target_uri: str,
        access_token: str | None,
        nonce_context: str | None,
        require_access_token_hash: bool,
    ) -> ValidatedDpopProof:
        """Execute the common RFC 9449 validation sequence."""
        self._validate_size(proof)
        header = self._read_header(proof)
        algorithm = self._read_required_header_string(header, "alg")
        if algorithm not in self._policy.allowed_algorithms:
            raise UnsupportedAlgorithmError(
                "DPoP proof algorithm is not allowed",
                code=INVALID_DPOP_PROOF,
                details={"algorithm": algorithm},
            )
        token_type = self._read_required_header_string(header, "typ")
        if token_type.lower() != DPOP_PROOF_TYPE:
            self._invalid("DPoP proof typ header must be dpop+jwt")
        public_jwk = self._parse_public_jwk(header.get("jwk"), algorithm=algorithm)

        try:
            decoded = jwt.decode(
                proof,
                key=public_jwk.to_public_key(),
                algorithms=[algorithm],
                options={
                    "require": ["jti", "htm", "htu", "iat"],
                    "verify_signature": True,
                    "verify_iat": False,
                    "verify_aud": False,
                },
            )
            claims = DpopProofClaims.model_validate(decoded)
        except (jwt.PyJWTError, ValidationError, TypeError, ValueError) as exc:
            raise ProtocolValidationError(
                "DPoP proof signature or claims are invalid",
                code=INVALID_DPOP_PROOF,
            ) from exc

        self._validate_request_binding(
            claims,
            http_method=http_method,
            target_uri=target_uri,
        )
        self._validate_time(claims)
        self._validate_access_token_hash(
            claims,
            access_token=access_token,
            required=require_access_token_hash,
        )
        self._validate_nonce(claims, nonce_context=nonce_context)

        thumbprint = self._thumbprints.compute(public_jwk)
        expires_at = self._clock.now() + self._policy.maximum_proof_age
        if not self._replay_store.consume(
            proof_id=claims.jti,
            key_thumbprint=thumbprint,
            expires_at=expires_at,
        ):
            self._invalid("DPoP proof has already been used")

        return ValidatedDpopProof(
            claims=claims,
            public_jwk=public_jwk,
            key_thumbprint=thumbprint,
            algorithm=algorithm,
        )

    def _parse_public_jwk(self, value: object, *, algorithm: str) -> SupportedPublicJwk:
        """Parse and constrain the public JWK embedded in the JOSE header."""
        if not isinstance(value, dict):
            self._invalid("DPoP proof must contain a public jwk header")
        try:
            public_jwk: SupportedPublicJwk = _PUBLIC_JWK_ADAPTER.validate_python(value)
        except ValidationError as exc:
            raise ProtocolValidationError(
                "DPoP proof jwk header is invalid",
                code=INVALID_DPOP_PROOF,
            ) from exc
        if public_jwk.alg is not None and public_jwk.alg != algorithm:
            self._invalid("DPoP proof algorithm conflicts with the embedded JWK")
        if public_jwk.use not in (None, "sig"):
            self._invalid("DPoP proof JWK is not authorized for signatures")
        if public_jwk.key_ops not in (None, (), ("verify",)):
            self._invalid("DPoP proof JWK has incompatible key operations")
        return public_jwk

    def _validate_request_binding(
        self,
        claims: DpopProofClaims,
        *,
        http_method: str,
        target_uri: str,
    ) -> None:
        """Require exact method and normalized target URI binding."""
        if claims.htm != http_method.strip().upper():
            self._invalid("DPoP htm claim does not match the HTTP request method")
        expected_uri = self._uri_normalizer.normalize(target_uri)
        if claims.htu != expected_uri:
            self._invalid("DPoP htu claim does not match the HTTP target URI")

    def _validate_time(self, claims: DpopProofClaims) -> None:
        """Reject proofs outside the configured RFC 9449 acceptance window."""
        now = int(self._clock.now().timestamp())
        skew = int(self._policy.clock_skew.total_seconds())
        maximum_age = int(self._policy.maximum_proof_age.total_seconds())
        if claims.iat > now + skew:
            self._invalid("DPoP proof was issued in the future")
        if claims.iat < now - maximum_age - skew:
            self._invalid("DPoP proof is older than the accepted proof window")

    def _validate_access_token_hash(
        self,
        claims: DpopProofClaims,
        *,
        access_token: str | None,
        required: bool,
    ) -> None:
        """Validate ``ath`` when a proof accompanies an access token."""
        if access_token is None:
            if claims.ath is not None:
                self._invalid("token-endpoint DPoP proof must not contain ath")
            return
        if required and claims.ath is None:
            self._invalid("resource-request DPoP proof must contain ath")
        if claims.ath is not None and claims.ath != self._token_hash.compute(access_token):
            self._invalid("DPoP ath claim does not match the access token")

    def _validate_nonce(
        self,
        claims: DpopProofClaims,
        *,
        nonce_context: str | None,
    ) -> None:
        """Consume a server nonce when the active profile requires one."""
        if not self._policy.require_nonce:
            return
        if claims.nonce is None or nonce_context is None or self._nonce_store is None:
            self._invalid("a valid server-provided DPoP nonce is required")
        if not self._nonce_store.consume(context=nonce_context, nonce=claims.nonce):
            self._invalid("DPoP nonce is invalid, expired, or already used")

    def _read_header(self, proof: str) -> dict[str, Any]:
        """Read untrusted JOSE routing metadata before signature validation."""
        try:
            return dict(jwt.get_unverified_header(proof))
        except jwt.PyJWTError as exc:
            raise ProtocolValidationError(
                "DPoP proof header is malformed",
                code=INVALID_DPOP_PROOF,
            ) from exc

    def _read_required_header_string(self, header: dict[str, Any], name: str) -> str:
        """Read one non-empty JOSE header string used in a trust decision."""
        value = header.get(name)
        if not isinstance(value, str) or not value.strip():
            self._invalid(f"DPoP proof header {name} must be a non-empty string")
        return value

    def _validate_size(self, proof: str) -> None:
        """Reject oversized proof JWTs before parsing and cryptographic work."""
        if len(proof.encode("utf-8")) > self._policy.maximum_proof_bytes:
            self._invalid("DPoP proof exceeds the configured size limit")

    @staticmethod
    def _invalid(message: str) -> NoReturn:
        """Raise the stable RFC 9449 invalid-proof error."""
        raise ProtocolValidationError(message, code=INVALID_DPOP_PROOF)
