"""Unit tests for authorization-server workflow composition."""

from datetime import UTC, datetime
from unittest.mock import Mock

from agent_nebula_sdk.jose.jwk.parser import JwkParser
from agent_nebula_sdk.oauth.authorization_server import (
    AuthorizationServerFacade,
    TokenIssuanceRequest,
)
from agent_nebula_sdk.oauth.rfc7523 import AuthenticatedClient, ClientAuthenticationRequest
from agent_nebula_sdk.oauth.rfc9068 import AccessTokenClaims, IssuedAccessToken
from agent_nebula_sdk.oauth.rfc9449 import DpopProofClaims, ValidatedDpopProof


def test_issue_resource_token_uses_client_and_dpop_identity(
    ec_public_jwk: dict[str, str],
) -> None:
    """The issued token must use the authenticated client and DPoP thumbprint."""
    authenticator = Mock()
    authenticator.authenticate.return_value = AuthenticatedClient(
        client_id="host-client",
        key_id="auth-key",
        algorithm="ES256",
        assertion_id="assertion-id",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC),
    )
    resource_service = Mock()
    resource_service.resolve_single_audience.return_value = "https://provider.example/a2a"
    proof_validator = Mock()
    proof_validator.validate_token_request.return_value = ValidatedDpopProof(
        claims=DpopProofClaims(jti="proof-id", htm="POST", htu="https://as/token", iat=1),
        public_jwk=JwkParser().parse_public_jwk(ec_public_jwk),
        key_thumbprint="dpop-thumbprint",
        algorithm="ES256",
    )
    token_issuer = Mock()
    token_issuer.issue.return_value = IssuedAccessToken(
        token="access-token",
        expires_in=300,
        claims=AccessTokenClaims(
            iss="https://as",
            sub="host-client",
            aud="https://provider.example/a2a",
            exp=301,
            iat=1,
            jti="token-id",
            client_id="host-client",
            cnf={"jkt": "dpop-thumbprint"},
        ),
        key_id="as-key",
        algorithm="RS256",
    )
    facade = AuthorizationServerFacade(
        registration_service=Mock(),
        client_authenticator=authenticator,
        resource_service=resource_service,
        token_issuer=token_issuer,
        dpop_validator=proof_validator,
    )

    result = facade.issue_resource_token(
        request=TokenIssuanceRequest(
            client_authentication=ClientAuthenticationRequest(
                client_assertion="assertion",
                client_id="host-client",
            ),
            dpop_proof="proof",
            token_endpoint="https://as/token",
            resource="https://provider.example/a2a",
            issuer="https://as",
        ),
        signing_key=Mock(),
    )

    assert result.client_id == "host-client"
    assert result.audience == "https://provider.example/a2a"
    issue_request = token_issuer.issue.call_args.kwargs["request"]
    assert issue_request.confirmation_jkt == "dpop-thumbprint"
