"""Tests for typed onboarding identifiers."""

from datetime import UTC, datetime

from agent_nebula_sdk.onboarding import (
    OAuthClientProfileResult,
    OnboardingCommitResult,
    RegistrationProfileType,
)


def test_oauth_result_keeps_internal_and_protocol_identifiers_distinct() -> None:
    """Keep internal OAuth IDs distinct from protocol client identifiers."""
    result = OnboardingCommitResult(
        onboarding_id="onb-1",
        entity_id="agent-1",
        profiles={
            RegistrationProfileType.OAUTH_CLIENT: OAuthClientProfileResult(
                oauth_client_id="uuid-1",
                client_id="neb_client_1",
            )
        },
        committed_at=datetime.now(UTC),
    )
    payload = result.model_dump(mode="json")
    assert payload["profiles"]["OAUTH_CLIENT"]["oauth_client_id"] == "uuid-1"
    assert payload["profiles"]["OAUTH_CLIENT"]["client_id"] == "neb_client_1"
