"""Unit tests for protected-resource audience validation."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc8707 import ResourceAudienceValidator


def test_expected_single_audience_is_accepted() -> None:
    """A provider accepts a token explicitly audience-bound to itself."""
    validator = ResourceAudienceValidator(expected_audience="parking-metro-a")
    result = validator.validate("parking-metro-a")
    assert result.token_audiences == ("parking-metro-a",)


def test_foreign_provider_audience_is_rejected() -> None:
    """Metro A rejects a token issued for Airport X."""
    validator = ResourceAudienceValidator(expected_audience="parking-metro-a")
    with pytest.raises(ProtocolValidationError) as error:
        validator.validate("parking-airport-x")
    assert error.value.code == "invalid_token_audience"


def test_single_audience_profile_rejects_array() -> None:
    """The Phase 1 resource server rejects multi-audience tokens."""
    validator = ResourceAudienceValidator(expected_audience="parking-metro-a")
    with pytest.raises(ProtocolValidationError, match="exactly one"):
        validator.validate(["parking-metro-a", "parking-airport-x"])


def test_generic_profile_accepts_expected_member() -> None:
    """The reusable validator can support trusted multi-audience deployments."""
    validator = ResourceAudienceValidator(
        expected_audience="parking-metro-a",
        require_single_audience=False,
    )
    result = validator.validate(["parking-metro-a", "parking-airport-x"])
    assert result.expected_audience == "parking-metro-a"


def test_empty_audience_is_rejected() -> None:
    """An empty audience claim never identifies a protected resource."""
    validator = ResourceAudienceValidator(expected_audience="parking-metro-a")
    with pytest.raises(ProtocolValidationError, match="missing"):
        validator.validate([])
