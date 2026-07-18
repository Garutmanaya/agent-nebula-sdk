"""Unit tests for resource-server identity establishment."""

from unittest.mock import Mock

from agent_nebula_sdk.jose.jwk.parser import JwkParser
from agent_nebula_sdk.oauth.rfc9068 import AccessTokenClaims, ValidatedAccessToken
from agent_nebula_sdk.oauth.rfc9449 import DpopProofClaims, ValidatedDpopProof
from agent_nebula_sdk.resource_server import ResourceServerFacade


def test_authenticate_request_returns_provider_security_context(
    ec_public_jwk: dict[str, str],
) -> None:
    """Validated token and DPoP data must be exposed to local policy as one context."""
    claims = AccessTokenClaims(
        iss="https://as",
        sub="host-client",
        aud="https://provider.example/a2a",
        exp=301,
        iat=1,
        jti="token-id",
        client_id="host-client",
        cnf={"jkt": "thumbprint"},
    )
    token_validator = Mock()
    token_validator.validate.return_value = ValidatedAccessToken(
        claims=claims,
        key_id="as-key",
        algorithm="RS256",
        token_type="at+jwt",
    )
    audience_validator = Mock()
    audience_validator.expected_audience = "https://provider.example/a2a"
    binding_service = Mock()
    binding_service.extract_key_thumbprint.return_value = "thumbprint"
    dpop_validator = Mock()
    dpop_validator.validate_resource_request.return_value = ValidatedDpopProof(
        claims=DpopProofClaims(
            jti="proof-id",
            htm="POST",
            htu="https://provider.example/a2a",
            iat=1,
            ath="hash",
        ),
        public_jwk=JwkParser().parse_public_jwk(ec_public_jwk),
        key_thumbprint="thumbprint",
        algorithm="ES256",
    )
    facade = ResourceServerFacade(
        token_validator=token_validator,
        dpop_validator=dpop_validator,
        audience_validator=audience_validator,
        binding_service=binding_service,
    )

    context = facade.authenticate_request(
        access_token="access-token",
        dpop_proof="proof",
        http_method="POST",
        target_uri="https://provider.example/a2a",
        expected_issuer="https://as",
    )

    assert context.subject == "host-client"
    assert context.client_id == "host-client"
    dpop_validator.validate_resource_request.assert_called_once()
