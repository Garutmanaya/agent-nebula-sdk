"""Tests for typed onboarding identifiers after OAuth externalization."""

from datetime import UTC, datetime

from agent_nebula_sdk.onboarding import (
    ClientEnrollmentProfileResult,
    OnboardingCommitResult,
    RegistrationProfileType,
)


def test_client_enrollment_result_does_not_expose_oauth_client_id() -> None:
    """Verify Registry onboarding returns enrollment identity, not OAuth identity."""
    result = OnboardingCommitResult(
        onboarding_id="onb-1",
        entity_id="agent-1",
        profiles={
            RegistrationProfileType.OAUTH_CLIENT: ClientEnrollmentProfileResult(
                client_enrollment_id="enrollment-1",
                public_key_thumbprints=("thumbprint-1",),
                jwks_uri="https://client.example/jwks.json",
            )
        },
        committed_at=datetime.now(UTC),
    )
    payload = result.model_dump(mode="json")
    client_profile = payload["profiles"]["OAUTH_CLIENT"]

    assert client_profile["client_enrollment_id"] == "enrollment-1"
    assert client_profile["public_key_thumbprints"] == ["thumbprint-1"]
    assert "client_id" not in client_profile
    assert "oauth_client_id" not in client_profile
