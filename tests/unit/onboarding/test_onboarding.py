"""Unit and negative tests for pluggable onboarding orchestration."""

from datetime import UTC, datetime

import pytest

from agent_nebula_sdk.core.errors import ConfigurationError, UnsupportedProtocolError
from agent_nebula_sdk.oauth.rfc7591.models import ClientMetadata, RegistrationRequest
from agent_nebula_sdk.oauth.rfc9728 import ProtectedResourceMetadata
from agent_nebula_sdk.onboarding import (
    AgentRegistrationInput,
    AgentRegistrationProfile,
    AgentRole,
    ApiKeyOnboardingAuthenticator,
    InitialAccessTokenOnboardingAuthenticator,
    MtlsOnboardingAuthenticator,
    OAuthClientRegistrationInput,
    OAuthClientRegistrationProfile,
    OnboardingAuthenticationInput,
    OnboardingAuthenticationMethod,
    OnboardingCommitResult,
    OnboardingComponentRegistry,
    OnboardingPrincipal,
    OnboardingRequest,
    OnboardingRuntimePlugin,
    OnboardingService,
    OpenOnboardingAuthenticator,
    ProtectedResourceRegistrationInput,
    ProtectedResourceRegistrationProfile,
    RegistrationProfileType,
    SoftwareStatementOnboardingAuthenticator,
)
from agent_nebula_sdk.runtime import ProtocolRuntime


class Transaction:
    """Capture prepared registrations for deterministic assertions."""

    def __init__(self) -> None:
        self.calls = []

    def resolve(self, registration):
        """Return no existing registration for onboarding unit tests."""
        del registration
        return None

    def commit(self, registration):
        """Persist the prepared registration in the in-memory test adapter."""
        self.calls.append(registration)
        return OnboardingCommitResult(
            onboarding_id="onboarding-1",
            entity_id="agent-1",
            committed_at=datetime.now(UTC),
        )


class ApiKeyVerifier:
    """Return a fixed API-key principal for adapter tests."""

    def __init__(self) -> None:
        self.calls = 0

    def verify(self, credential: str) -> OnboardingPrincipal:
        """Verify the expected synthetic API key."""
        self.calls += 1
        assert credential == "secret"
        return OnboardingPrincipal(
            subject="provider-1",
            authentication_method=OnboardingAuthenticationMethod.OPEN,
            trust_status="PARTNER",
        )


class TokenVerifier:
    """Return a fixed principal and record atomic token consumption."""

    def __init__(self) -> None:
        self.consumed = []

    def verify_and_consume(self, token: str) -> OnboardingPrincipal:
        """Consume and record the expected synthetic bootstrap token."""
        self.consumed.append(token)
        return OnboardingPrincipal(
            subject="bootstrap-1",
            authentication_method=OnboardingAuthenticationMethod.OPEN,
            trust_status="VERIFIED_ONBOARDING",
        )


class StatementVerifier:
    """Decode one synthetic signed statement for orchestration tests."""

    def verify(self, statement: str) -> dict[str, object]:
        """Return trusted synthetic statement claims or reject invalid input."""
        if statement == "bad":
            raise ValueError("bad statement")
        return {"iss": "publisher", "software_id": "parking"}


def provider_request(method=OnboardingAuthenticationMethod.OPEN, credential=None):
    """Build a combined Agent and protected-resource onboarding request."""
    return OnboardingRequest(
        entity_name="Parking Metro A",
        roles=frozenset({AgentRole.A2A_PROVIDER, AgentRole.OAUTH_PROTECTED_RESOURCE}),
        authentication=OnboardingAuthenticationInput(method=method, credential=credential),
        agent=AgentRegistrationInput(
            agent_card_uri="https://metro.example/.well-known/agent-card.json"
        ),
        protected_resource=ProtectedResourceRegistrationInput(
            metadata=ProtectedResourceMetadata(
                resource="https://metro.example/a2a",
                authorization_servers=("https://nebula.example",),
            )
        ),
    )


def configured_service(authenticator):
    """Create a service with all standard profile handlers."""
    registry = OnboardingComponentRegistry()
    registry.register_authenticator(authenticator)
    registry.register_profile(AgentRegistrationProfile())
    registry.register_profile(OAuthClientRegistrationProfile())
    registry.register_profile(ProtectedResourceRegistrationProfile())
    transaction = Transaction()
    return OnboardingService(registry=registry, transaction=transaction), transaction, registry


def test_open_combined_provider_onboarding_is_atomic():
    """Prepare Agent and protected-resource profiles in one transaction."""
    service, transaction, _ = configured_service(OpenOnboardingAuthenticator())
    result = service.onboard(provider_request())
    assert result.registered_profiles == (
        RegistrationProfileType.AGENT,
        RegistrationProfileType.PROTECTED_RESOURCE,
    )
    assert len(transaction.calls) == 1
    assert transaction.calls[0].principal.trust_status == "UNVERIFIED"


def test_oauth_client_profile_reuses_rfc7591_request_model():
    """Ensure OAuth onboarding emits the existing RFC 7591 request model."""
    service, transaction, _ = configured_service(OpenOnboardingAuthenticator())
    request = OnboardingRequest(
        entity_name="Parking Host",
        roles=frozenset({AgentRole.OAUTH_CLIENT}),
        authentication=OnboardingAuthenticationInput(method=OnboardingAuthenticationMethod.OPEN),
        oauth_client=OAuthClientRegistrationInput(
            metadata=ClientMetadata(
                client_name="Parking Host",
                grant_types=("client_credentials",),
                response_types=(),
                token_endpoint_auth_method="private_key_jwt",
                jwks_uri="https://host.example/.well-known/jwks.json",
            )
        ),
    )
    service.onboard(request)
    payload = transaction.calls[0].registrations[0].payload
    assert isinstance(payload, RegistrationRequest)
    assert payload.metadata.client_name == "Parking Host"


def test_api_key_verifier_is_called_once():
    """Invoke the product API-key verifier exactly once."""
    verifier = ApiKeyVerifier()
    service, _, _ = configured_service(ApiKeyOnboardingAuthenticator(verifier))
    result = service.onboard(provider_request(OnboardingAuthenticationMethod.API_KEY, "secret"))
    assert verifier.calls == 1
    assert result.principal.authentication_method is OnboardingAuthenticationMethod.API_KEY


def test_initial_access_token_is_consumed_before_commit():
    """Consume controlled onboarding tokens before product persistence."""
    verifier = TokenVerifier()
    service, transaction, _ = configured_service(
        InitialAccessTokenOnboardingAuthenticator(verifier)
    )
    service.onboard(
        provider_request(OnboardingAuthenticationMethod.INITIAL_ACCESS_TOKEN, "bootstrap")
    )
    assert verifier.consumed == ["bootstrap"]
    assert len(transaction.calls) == 1


def test_software_statement_uses_rfc7591_verifier_contract():
    """Reuse the RFC 7591 statement verifier contract for trust establishment."""
    service, _, _ = configured_service(
        SoftwareStatementOnboardingAuthenticator(StatementVerifier())
    )
    result = service.onboard(
        provider_request(OnboardingAuthenticationMethod.SOFTWARE_STATEMENT, "signed")
    )
    assert result.principal.subject == "parking"
    assert result.principal.claims["iss"] == "publisher"


def test_mtls_fails_explicitly_until_rfc8705_exists():
    """Reject mTLS onboarding until complete RFC 8705 support exists."""
    service, transaction, _ = configured_service(MtlsOnboardingAuthenticator())
    with pytest.raises(UnsupportedProtocolError):
        service.onboard(provider_request(OnboardingAuthenticationMethod.MTLS, "certificate"))
    assert transaction.calls == []


def test_duplicate_component_registration_is_rejected():
    """Reject silent replacement of onboarding strategies and profiles."""
    registry = OnboardingComponentRegistry()
    registry.register_authenticator(OpenOnboardingAuthenticator())
    with pytest.raises(ConfigurationError):
        registry.register_authenticator(OpenOnboardingAuthenticator())
    registry.register_profile(AgentRegistrationProfile())
    with pytest.raises(ConfigurationError):
        registry.register_profile(AgentRegistrationProfile())


def test_missing_role_profile_is_rejected_by_model():
    """Reject role declarations that omit their required profile metadata."""
    with pytest.raises(ValueError, match="OAUTH_CLIENT role requires"):
        OnboardingRequest(
            entity_name="Invalid",
            roles=frozenset({AgentRole.OAUTH_CLIENT}),
            authentication=OnboardingAuthenticationInput(
                method=OnboardingAuthenticationMethod.OPEN
            ),
            agent=AgentRegistrationInput(agent_card_uri="https://example.com/card"),
        )


def test_runtime_plugin_registers_namespaced_components():
    """Expose onboarding services through the existing ProtocolRuntime."""
    service, _, registry = configured_service(OpenOnboardingAuthenticator())
    plugin = OnboardingRuntimePlugin(
        service=service,
        authenticators=(registry.authenticator(OnboardingAuthenticationMethod.OPEN),),
        profiles=registry.profiles(),
    )
    runtime = ProtocolRuntime(plugins=(plugin,))
    assert runtime.registry.resolve("onboarding.service", OnboardingService) is service
    assert runtime.registry.resolve(
        "onboarding.authentication.open", OpenOnboardingAuthenticator
    )
