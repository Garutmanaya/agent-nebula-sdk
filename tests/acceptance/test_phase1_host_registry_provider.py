"""Acceptance tests for the complete Phase 1 Host → Registry → Provider flow."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.conformance import Phase1AcceptanceHarness
from agent_nebula_sdk.core.errors import AgentNebulaSdkError
from agent_nebula_sdk.oauth.rfc9449 import DpopProofBuildRequest, DpopSigningKey


def test_complete_phase1_flow_succeeds() -> None:
    """Open registration, token issuance, and A2A invocation compose successfully."""
    result = Phase1AcceptanceHarness().run()

    assert result.audience == Phase1AcceptanceHarness.provider_endpoint
    assert result.authenticated_subject == result.host_client_id
    assert result.authenticated_client_id == result.host_client_id
    assert result.response_payload["operation"] == "parking.search"


def test_replayed_client_assertion_is_rejected() -> None:
    """The RFC 7523 assertion identifier can be consumed only once."""
    harness = Phase1AcceptanceHarness()
    host_id, _ = harness.register_default_entities()
    request, authentication_key = harness.build_host_token_request(host_id)
    artifacts = harness.client.build_token_request(
        request=request,
        authentication_key=authentication_key,
        dpop_key=harness.host_dpop_signing_key,
    )
    from agent_nebula_sdk.authorization_server import TokenIssuanceRequest

    issuance_request = TokenIssuanceRequest(
        client_authentication=artifacts.client_authentication,
        dpop_proof=artifacts.dpop_proof.proof,
        token_endpoint=harness.token_endpoint,
        resource=harness.provider_endpoint,
        issuer=harness.issuer,
    )
    harness.authorization_server.issue_resource_token(
        request=issuance_request,
        signing_key=harness.issuer_signing_key,
    )
    with pytest.raises(AgentNebulaSdkError):
        harness.authorization_server.issue_resource_token(
            request=issuance_request,
            signing_key=harness.issuer_signing_key,
        )


def test_wrong_dpop_private_key_cannot_use_bound_token() -> None:
    """A stolen token is unusable without the Host DPoP private key."""
    harness = Phase1AcceptanceHarness()
    host_id, _ = harness.register_default_entities()
    issuance = harness.issue_host_token(host_id)
    attacker = harness._build_ec_key_pair("attacker-dpop-2026-01")
    proof = harness._dpop_builder.build(
        request=DpopProofBuildRequest(
            http_method="POST",
            target_uri=harness.provider_endpoint,
            access_token=issuance.access_token.token,
        ),
        signing_key=DpopSigningKey(
            algorithm="ES256",
            private_key=attacker.private_key,
            public_jwk=attacker.public_jwk,
        ),
    )
    with pytest.raises(AgentNebulaSdkError):
        harness.resource_server.authenticate_request(
            access_token=issuance.access_token.token,
            dpop_proof=proof.proof,
            http_method="POST",
            target_uri=harness.provider_endpoint,
            expected_issuer=harness.issuer,
        )


def test_wrong_http_method_is_rejected() -> None:
    """A proof created for POST cannot authenticate a GET request."""
    harness = Phase1AcceptanceHarness()
    host_id, _ = harness.register_default_entities()
    issuance = harness.issue_host_token(host_id)
    artifacts = harness.client.build_protected_request(
        http_method="POST",
        target_uri=harness.provider_endpoint,
        access_token=issuance.access_token.token,
        dpop_key=harness.host_dpop_signing_key,
    )
    with pytest.raises(AgentNebulaSdkError):
        harness.resource_server.authenticate_request(
            access_token=issuance.access_token.token,
            dpop_proof=artifacts.dpop_proof.proof,
            http_method="GET",
            target_uri=harness.provider_endpoint,
            expected_issuer=harness.issuer,
        )


def test_replayed_provider_proof_is_rejected() -> None:
    """A protected-resource DPoP proof is accepted exactly once."""
    harness = Phase1AcceptanceHarness()
    host_id, _ = harness.register_default_entities()
    issuance = harness.issue_host_token(host_id)
    artifacts = harness.client.build_protected_request(
        http_method="POST",
        target_uri=harness.provider_endpoint,
        access_token=issuance.access_token.token,
        dpop_key=harness.host_dpop_signing_key,
    )
    kwargs = {
        "access_token": issuance.access_token.token,
        "dpop_proof": artifacts.dpop_proof.proof,
        "http_method": "POST",
        "target_uri": harness.provider_endpoint,
        "expected_issuer": harness.issuer,
    }
    harness.resource_server.authenticate_request(**kwargs)
    with pytest.raises(AgentNebulaSdkError):
        harness.resource_server.authenticate_request(**kwargs)
