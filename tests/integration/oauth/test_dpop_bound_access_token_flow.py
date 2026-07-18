"""SDK integration flow for DPoP-bound RFC 9068 access-token invocation."""

from __future__ import annotations

from agent_nebula_sdk.oauth.rfc9068.adapters import InMemoryAccessTokenKeyResolver
from agent_nebula_sdk.oauth.rfc9068.issuer import JwtAccessTokenIssuer
from agent_nebula_sdk.oauth.rfc9068.models import AccessTokenIssueRequest, AccessTokenSigningKey
from agent_nebula_sdk.oauth.rfc9068.policy import Rfc9068Policy
from agent_nebula_sdk.oauth.rfc9068.validator import JwtAccessTokenValidator
from agent_nebula_sdk.oauth.rfc9449.adapters import InMemoryDpopReplayStore
from agent_nebula_sdk.oauth.rfc9449.builder import DpopProofBuilder
from agent_nebula_sdk.oauth.rfc9449.models import DpopProofBuildRequest, DpopSigningKey
from agent_nebula_sdk.oauth.rfc9449.policy import Rfc9449Policy
from agent_nebula_sdk.oauth.rfc9449.uri import DpopTargetUriNormalizer
from agent_nebula_sdk.oauth.rfc9449.validator import DpopProofValidator
from tests.unit.oauth.rfc7523.helpers import FixedClock, build_ec_key_pair, build_rsa_key_pair


def test_dpop_bound_access_token_and_provider_proof() -> None:
    """A provider accepts only a proof signed by the key bound in ``cnf.jkt``."""
    clock = FixedClock()
    dpop_policy = Rfc9449Policy()
    dpop_uri = DpopTargetUriNormalizer(policy=dpop_policy)
    client_private_key, client_public_jwk = build_ec_key_pair()
    proof_builder = DpopProofBuilder(
        clock=clock,
        policy=dpop_policy,
        uri_normalizer=dpop_uri,
    )
    token_request_proof = proof_builder.build(
        request=DpopProofBuildRequest(
            http_method="POST",
            target_uri="https://nebula.example/oauth/token",
        ),
        signing_key=DpopSigningKey(
            algorithm="ES256",
            private_key=client_private_key,
            public_jwk=client_public_jwk,
        ),
    )
    authorization_validator = DpopProofValidator(
        clock=clock,
        policy=dpop_policy,
        replay_store=InMemoryDpopReplayStore(clock=clock),
        uri_normalizer=dpop_uri,
    )
    token_proof = authorization_validator.validate_token_request(
        token_request_proof.proof,
        http_method="POST",
        target_uri="https://nebula.example/oauth/token",
    )

    issuer_private_key, issuer_public_jwk = build_rsa_key_pair()
    access_token = JwtAccessTokenIssuer(clock=clock, policy=Rfc9068Policy()).issue(
        request=AccessTokenIssueRequest(
            issuer="https://nebula.example",
            subject="parking-host",
            audience="https://metro.example/a2a",
            client_id="parking-host",
            confirmation_jkt=token_proof.key_thumbprint,
        ),
        signing_key=AccessTokenSigningKey(
            key_id="rsa-client-2026-01",
            algorithm="RS256",
            private_key=issuer_private_key,
        ),
    )

    issuer_keys = InMemoryAccessTokenKeyResolver()
    issuer_keys.register(issuer="https://nebula.example", key=issuer_public_jwk)
    validated_token = JwtAccessTokenValidator(
        clock=clock,
        policy=Rfc9068Policy(),
        key_resolver=issuer_keys,
    ).validate(
        access_token.token,
        expected_issuer="https://nebula.example",
        expected_audiences=("https://metro.example/a2a",),
    )
    assert validated_token.claims.cnf == {"jkt": token_proof.key_thumbprint}

    resource_proof = proof_builder.build(
        request=DpopProofBuildRequest(
            http_method="POST",
            target_uri="https://metro.example/a2a",
            access_token=access_token.token,
        ),
        signing_key=DpopSigningKey(
            algorithm="ES256",
            private_key=client_private_key,
            public_jwk=client_public_jwk,
        ),
    )
    provider_validator = DpopProofValidator(
        clock=clock,
        policy=dpop_policy,
        replay_store=InMemoryDpopReplayStore(clock=clock),
        uri_normalizer=dpop_uri,
    )
    validated_proof = provider_validator.validate_resource_request(
        resource_proof.proof,
        http_method="POST",
        target_uri="https://metro.example/a2a",
        access_token=access_token.token,
        expected_key_thumbprint=token_proof.key_thumbprint,
    )
    assert validated_proof.key_thumbprint == token_proof.key_thumbprint
