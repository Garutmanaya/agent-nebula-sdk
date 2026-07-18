"""Authorization-server issuance tests for RFC 9068."""

from __future__ import annotations

import jwt
import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc9068.issuer import JwtAccessTokenIssuer
from agent_nebula_sdk.oauth.rfc9068.models import AccessTokenIssueRequest, AccessTokenSigningKey
from agent_nebula_sdk.oauth.rfc9068.policy import Rfc9068Policy
from tests.unit.oauth.rfc7523.helpers import FixedClock, build_rsa_key_pair


def build_issuer() -> JwtAccessTokenIssuer:
    """Create a deterministic issuer for unit tests."""
    return JwtAccessTokenIssuer(
        clock=FixedClock(),
        policy=Rfc9068Policy(),
        token_id_factory=lambda: "11111111-1111-4111-8111-111111111111",
    )


def test_issue_required_claims_and_header() -> None:
    """Issued tokens contain the required profile claims and ``at+jwt`` type."""
    private_key, _ = build_rsa_key_pair()
    issued = build_issuer().issue(
        request=AccessTokenIssueRequest(
            issuer="https://nebula.example",
            subject="parking-host",
            audience="https://metro.example/a2a",
            client_id="parking-host",
        ),
        signing_key=AccessTokenSigningKey(
            key_id="rsa-client-2026-01",
            algorithm="RS256",
            private_key=private_key,
        ),
    )
    header = jwt.get_unverified_header(issued.token)
    claims = jwt.decode(issued.token, options={"verify_signature": False})
    assert header["typ"] == "at+jwt"
    assert claims["client_id"] == "parking-host"
    assert claims["aud"] == "https://metro.example/a2a"
    assert issued.expires_in == 600


def test_issue_scope_and_authorization_claims() -> None:
    """Standard scope, roles, groups, and entitlements are encoded consistently."""
    private_key, _ = build_rsa_key_pair()
    issued = build_issuer().issue(
        request=AccessTokenIssueRequest(
            issuer="https://nebula.example",
            subject="user-1",
            audience="https://bi.example",
            client_id="bi-host",
            scope=("read", "report"),
            roles=("analyst",),
            groups=("finance",),
            entitlements=("dashboard:create",),
        ),
        signing_key=AccessTokenSigningKey(
            key_id="rsa-client-2026-01",
            algorithm="RS256",
            private_key=private_key,
        ),
    )
    assert issued.claims.scope == "read report"
    assert issued.claims.roles == ("analyst",)


def test_issue_rejects_registered_claim_override() -> None:
    """Private extension claims cannot replace mandatory RFC 9068 semantics."""
    private_key, _ = build_rsa_key_pair()
    with pytest.raises(ProtocolValidationError) as captured:
        build_issuer().issue(
            request=AccessTokenIssueRequest(
                issuer="https://nebula.example",
                subject="parking-host",
                audience="https://metro.example",
                client_id="parking-host",
                additional_claims={"aud": "https://airport.example"},
            ),
            signing_key=AccessTokenSigningKey(
                key_id="rsa-client-2026-01",
                algorithm="RS256",
                private_key=private_key,
            ),
        )
    assert captured.value.code == "registered_claim_override"


def test_issue_rejects_non_collision_resistant_private_claim() -> None:
    """Private attributes require configured collision-resistant claim names."""
    private_key, _ = build_rsa_key_pair()
    with pytest.raises(ProtocolValidationError) as captured:
        build_issuer().issue(
            request=AccessTokenIssueRequest(
                issuer="https://nebula.example",
                subject="parking-host",
                audience="https://metro.example",
                client_id="parking-host",
                additional_claims={"trust_level": "verified"},
            ),
            signing_key=AccessTokenSigningKey(
                key_id="rsa-client-2026-01",
                algorithm="RS256",
                private_key=private_key,
            ),
        )
    assert captured.value.code == "invalid_private_claim_name"


def test_issue_dpop_confirmation_claim() -> None:
    """RFC 9449 integration emits a typed ``cnf.jkt`` confirmation claim."""
    private_key, _ = build_rsa_key_pair()
    issued = build_issuer().issue(
        request=AccessTokenIssueRequest(
            issuer="https://nebula.example",
            subject="parking-host",
            audience="https://metro.example/a2a",
            client_id="parking-host",
            confirmation_jkt="client-key-thumbprint",
        ),
        signing_key=AccessTokenSigningKey(
            key_id="rsa-client-2026-01",
            algorithm="RS256",
            private_key=private_key,
        ),
    )
    assert issued.claims.cnf == {"jkt": "client-key-thumbprint"}
