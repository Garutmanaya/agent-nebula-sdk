"""Client-side RFC 9449 proof-builder tests."""

from __future__ import annotations

import jwt
import pytest
from tests.unit.oauth.rfc7523.helpers import build_ec_key_pair
from tests.unit.oauth.rfc9449.helpers import build_builder

from agent_nebula_sdk.oauth.rfc9449.models import DpopProofBuildRequest, DpopSigningKey


def test_build_token_request_proof() -> None:
    """Token-endpoint proofs contain required claims and a public JWK header."""
    private_key, public_jwk = build_ec_key_pair()
    built = build_builder().build(
        request=DpopProofBuildRequest(
            http_method="POST",
            target_uri="https://nebula.example/oauth/token?ignored=true",
        ),
        signing_key=DpopSigningKey(
            algorithm="ES256",
            private_key=private_key,
            public_jwk=public_jwk,
        ),
    )
    header = jwt.get_unverified_header(built.proof)
    claims = jwt.decode(built.proof, options={"verify_signature": False})
    assert header["typ"] == "dpop+jwt"
    assert "d" not in header["jwk"]
    assert claims["htu"] == "https://nebula.example/oauth/token"
    assert "ath" not in claims


def test_build_resource_proof_contains_access_token_hash() -> None:
    """Protected-resource proofs bind themselves to the access token via ``ath``."""
    private_key, public_jwk = build_ec_key_pair()
    built = build_builder().build(
        request=DpopProofBuildRequest(
            http_method="POST",
            target_uri="https://metro.example/a2a",
            access_token="header.payload.signature",
        ),
        signing_key=DpopSigningKey(
            algorithm="ES256",
            private_key=private_key,
            public_jwk=public_jwk,
        ),
    )
    assert built.claims.ath is not None


def test_builder_rejects_disallowed_algorithm() -> None:
    """The proof builder rejects algorithms outside the configured allowlist."""
    from agent_nebula_sdk.core.errors import UnsupportedAlgorithmError
    from agent_nebula_sdk.oauth.rfc9449.policy import Rfc9449Policy

    private_key, public_jwk = build_ec_key_pair()
    with pytest.raises(UnsupportedAlgorithmError):
        build_builder(policy=Rfc9449Policy(allowed_algorithms=frozenset({"RS256"}))).build(
            request=DpopProofBuildRequest(
                http_method="POST",
                target_uri="https://nebula.example/oauth/token",
            ),
            signing_key=DpopSigningKey(
                algorithm="ES256",
                private_key=private_key,
                public_jwk=public_jwk,
            ),
        )


def test_builder_rejects_conflicting_jwk_algorithm() -> None:
    """Signing metadata cannot conflict with the public JWK algorithm."""
    from agent_nebula_sdk.core.errors import ProtocolValidationError

    private_key, public_jwk = build_ec_key_pair()
    with pytest.raises(ProtocolValidationError):
        build_builder().build(
            request=DpopProofBuildRequest(
                http_method="POST",
                target_uri="https://nebula.example/oauth/token",
            ),
            signing_key=DpopSigningKey(
                algorithm="RS256",
                private_key=private_key,
                public_jwk=public_jwk,
            ),
        )
