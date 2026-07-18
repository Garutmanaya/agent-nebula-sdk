"""Unit tests for the stable client-role facade."""

from unittest.mock import Mock

from agent_nebula_sdk.client import ClientTokenRequest, OAuthClientFacade
from agent_nebula_sdk.oauth.rfc7523 import ClientAuthenticationRequest
from agent_nebula_sdk.oauth.rfc9449 import BuiltDpopProof, DpopProofClaims


def test_build_token_request_composes_protocol_artifacts() -> None:
    """The facade must preserve client authentication, resource, scope, and DPoP."""
    assertion_builder = Mock()
    assertion_builder.build.return_value = ClientAuthenticationRequest(
        client_assertion="assertion",
        client_id="host-client",
    )
    dpop_builder = Mock()
    dpop_builder.build.return_value = BuiltDpopProof(
        proof="proof",
        claims=DpopProofClaims(jti="proof-id", htm="POST", htu="https://as/token", iat=1),
        key_thumbprint="thumbprint",
        algorithm="ES256",
    )
    facade = OAuthClientFacade(
        assertion_builder=assertion_builder,
        resource_codec=Mock(),
        dpop_builder=dpop_builder,
    )

    result = facade.build_token_request(
        request=ClientTokenRequest(
            client_id="host-client",
            token_endpoint="https://as/token",
            resource="https://provider.example/a2a",
            scope=("registry:discover",),
        ),
        authentication_key=Mock(),
        dpop_key=Mock(),
    )

    assert result.form_fields["grant_type"] == "client_credentials"
    assert result.form_fields["resource"] == "https://provider.example/a2a"
    assert result.form_fields["scope"] == "registry:discover"
    assert result.dpop_proof.proof == "proof"
