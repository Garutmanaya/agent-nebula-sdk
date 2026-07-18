"""Authorization-server and resource-server DPoP proof-validation tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from tests.unit.oauth.rfc7523.helpers import FixedClock, build_ec_key_pair
from tests.unit.oauth.rfc9449.helpers import build_builder, build_validator

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc9449.adapters import InMemoryDpopReplayStore
from agent_nebula_sdk.oauth.rfc9449.models import DpopProofBuildRequest, DpopSigningKey
from agent_nebula_sdk.oauth.rfc9449.policy import Rfc9449Policy


def build_resource_proof(access_token: str = "access-token") -> tuple[str, str]:
    """Build one valid protected-resource proof and return its thumbprint."""
    private_key, public_jwk = build_ec_key_pair()
    built = build_builder().build(
        request=DpopProofBuildRequest(
            http_method="POST",
            target_uri="https://metro.example/a2a",
            access_token=access_token,
        ),
        signing_key=DpopSigningKey(
            algorithm="ES256",
            private_key=private_key,
            public_jwk=public_jwk,
        ),
    )
    return built.proof, built.key_thumbprint


def test_validate_resource_request() -> None:
    """A proof with matching method, URI, token hash, and key binding is accepted."""
    proof, thumbprint = build_resource_proof()
    validated = build_validator().validate_resource_request(
        proof,
        http_method="POST",
        target_uri="https://metro.example/a2a?request=1",
        access_token="access-token",
        expected_key_thumbprint=thumbprint,
    )
    assert validated.key_thumbprint == thumbprint


@pytest.mark.parametrize(
    ("method", "uri", "access_token", "thumbprint"),
    [
        ("GET", "https://metro.example/a2a", "access-token", None),
        ("POST", "https://metro.example/other", "access-token", None),
        ("POST", "https://metro.example/a2a", "other-token", None),
        ("POST", "https://metro.example/a2a", "access-token", "wrong-thumbprint"),
    ],
)
def test_reject_request_binding_mismatch(
    method: str,
    uri: str,
    access_token: str,
    thumbprint: str | None,
) -> None:
    """Any method, URI, token-hash, or key-binding mismatch is rejected."""
    proof, expected_thumbprint = build_resource_proof()
    with pytest.raises(ProtocolValidationError) as captured:
        build_validator().validate_resource_request(
            proof,
            http_method=method,
            target_uri=uri,
            access_token=access_token,
            expected_key_thumbprint=thumbprint or expected_thumbprint,
        )
    assert captured.value.code == "invalid_dpop_proof"


def test_reject_replayed_proof() -> None:
    """The replay store atomically rejects a second use of the same proof JWT."""
    proof, thumbprint = build_resource_proof()
    clock = FixedClock()
    replay_store = InMemoryDpopReplayStore(clock=clock)
    validator = build_validator(clock=clock, replay_store=replay_store)
    validator.validate_resource_request(
        proof,
        http_method="POST",
        target_uri="https://metro.example/a2a",
        access_token="access-token",
        expected_key_thumbprint=thumbprint,
    )
    with pytest.raises(ProtocolValidationError) as captured:
        validator.validate_resource_request(
            proof,
            http_method="POST",
            target_uri="https://metro.example/a2a",
            access_token="access-token",
            expected_key_thumbprint=thumbprint,
        )
    assert captured.value.code == "invalid_dpop_proof"


def test_reject_expired_proof() -> None:
    """Proofs older than the configured acceptance window are rejected."""
    proof, thumbprint = build_resource_proof()
    clock = FixedClock()
    clock.current += timedelta(minutes=10)
    with pytest.raises(ProtocolValidationError):
        build_validator(clock=clock).validate_resource_request(
            proof,
            http_method="POST",
            target_uri="https://metro.example/a2a",
            access_token="access-token",
            expected_key_thumbprint=thumbprint,
        )


def test_token_request_rejects_resource_access_token_hash() -> None:
    """A token-endpoint proof must not carry the resource-request ``ath`` claim."""
    proof, _ = build_resource_proof()
    with pytest.raises(ProtocolValidationError):
        build_validator().validate_token_request(
            proof,
            http_method="POST",
            target_uri="https://metro.example/a2a",
        )


def test_resource_request_rejects_missing_access_token_hash() -> None:
    """A protected-resource proof without ``ath`` is rejected by default."""
    private_key, public_jwk = build_ec_key_pair()
    built = build_builder().build(
        request=DpopProofBuildRequest(
            http_method="POST",
            target_uri="https://metro.example/a2a",
        ),
        signing_key=DpopSigningKey(
            algorithm="ES256",
            private_key=private_key,
            public_jwk=public_jwk,
        ),
    )
    with pytest.raises(ProtocolValidationError):
        build_validator().validate_resource_request(
            built.proof,
            http_method="POST",
            target_uri="https://metro.example/a2a",
            access_token="access-token",
            expected_key_thumbprint=built.key_thumbprint,
        )


def test_validator_rejects_malformed_or_oversized_proof() -> None:
    """Malformed and oversized proofs fail before expensive validation work."""
    with pytest.raises(ProtocolValidationError):
        build_validator().validate_token_request(
            "not-a-jwt",
            http_method="POST",
            target_uri="https://nebula.example/oauth/token",
        )
    policy = Rfc9449Policy(maximum_proof_bytes=1024)
    with pytest.raises(ProtocolValidationError):
        build_validator(policy=policy).validate_token_request(
            "x" * 1025,
            http_method="POST",
            target_uri="https://nebula.example/oauth/token",
        )


def test_nonce_required_profile_accepts_once_and_rejects_reuse() -> None:
    """A required server nonce is consumed once during proof validation."""
    from agent_nebula_sdk.oauth.rfc9449.adapters import InMemoryDpopNonceStore
    from agent_nebula_sdk.oauth.rfc9449.nonce import DpopNonceService
    from agent_nebula_sdk.oauth.rfc9449.policy import Rfc9449Policy
    from agent_nebula_sdk.oauth.rfc9449.uri import DpopTargetUriNormalizer
    from agent_nebula_sdk.oauth.rfc9449.validator import DpopProofValidator

    clock = FixedClock()
    policy = Rfc9449Policy(require_nonce=True)
    nonce_store = InMemoryDpopNonceStore(clock=clock)
    nonce = DpopNonceService(clock=clock, store=nonce_store).issue(context="token")
    private_key, public_jwk = build_ec_key_pair()
    built = build_builder(clock=clock, policy=policy).build(
        request=DpopProofBuildRequest(
            http_method="POST",
            target_uri="https://nebula.example/oauth/token",
            nonce=nonce,
        ),
        signing_key=DpopSigningKey(
            algorithm="ES256",
            private_key=private_key,
            public_jwk=public_jwk,
        ),
    )
    validator = DpopProofValidator(
        clock=clock,
        policy=policy,
        replay_store=InMemoryDpopReplayStore(clock=clock),
        uri_normalizer=DpopTargetUriNormalizer(policy=policy),
        nonce_store=nonce_store,
    )
    validator.validate_token_request(
        built.proof,
        http_method="POST",
        target_uri="https://nebula.example/oauth/token",
        nonce_context="token",
    )
    with pytest.raises(ProtocolValidationError):
        validator.validate_token_request(
            built.proof,
            http_method="POST",
            target_uri="https://nebula.example/oauth/token",
            nonce_context="token",
        )
