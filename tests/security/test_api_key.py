from agent_nebula_sdk.security import (
    ApiKeyAuthenticator,
    ApiKeyRequest,
    AuthenticatedIdentity,
)


class Verifier:
    def verify(self, credential: str) -> AuthenticatedIdentity:
        assert credential == "secret"
        return AuthenticatedIdentity(subject="client-1", attributes={})


def test_api_key_supports_header_query_and_cookie() -> None:
    authenticator = ApiKeyAuthenticator(Verifier())
    cases = (
        (
            ApiKeyRequest(
                headers={"x-api-key": "secret"},
                target_uri="https://agent.test/a2a",
            ),
            "header",
            "X-API-Key",
        ),
        (
            ApiKeyRequest(
                headers={},
                target_uri="https://agent.test/a2a?key=secret",
            ),
            "query",
            "key",
        ),
        (
            ApiKeyRequest(
                headers={"cookie": "key=secret"},
                target_uri="https://agent.test/a2a",
            ),
            "cookie",
            "key",
        ),
    )
    for request, location, name in cases:
        identity = authenticator.authenticate(
            request=request,
            location=location,
            name=name,
        )
        assert identity.subject == "client-1"
