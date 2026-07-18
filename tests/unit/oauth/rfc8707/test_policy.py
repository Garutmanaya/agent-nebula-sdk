"""Unit tests for RFC 8707 resource-indicator validation policy."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc8707 import (
    ResourceIndicatorPolicy,
    ResourceIndicatorValidator,
)


def test_secure_profile_accepts_one_https_resource() -> None:
    """The Agent Nebula default profile accepts one HTTPS provider identifier."""
    validator = ResourceIndicatorValidator()
    assert validator.validate(("https://metro.example/a2a",)) == ("https://metro.example/a2a",)


def test_resource_must_be_absolute() -> None:
    """RFC 8707 rejects relative resource identifiers."""
    validator = ResourceIndicatorValidator()
    with pytest.raises(ProtocolValidationError) as error:
        validator.validate(("/a2a",))
    assert error.value.code == "invalid_target"


def test_fragment_is_rejected() -> None:
    """RFC 8707 forbids fragment components in a resource URI."""
    validator = ResourceIndicatorValidator()
    with pytest.raises(ProtocolValidationError, match="fragment"):
        validator.validate(("https://metro.example/a2a#invoke",))


def test_query_is_supported_by_default() -> None:
    """The RFC-recognized query-component use case remains available."""
    validator = ResourceIndicatorValidator()
    resource = "https://api.example/tenant?region=us"
    assert validator.validate((resource,)) == (resource,)


def test_query_can_be_disabled_by_profile() -> None:
    """Deployments may enforce the RFC recommendation to avoid queries."""
    validator = ResourceIndicatorValidator(ResourceIndicatorPolicy(allow_query=False))
    with pytest.raises(ProtocolValidationError, match="query"):
        validator.validate(("https://api.example/?tenant=one",))


def test_generic_rfc_profile_accepts_abstract_absolute_uri() -> None:
    """RFC 8707 permits abstract identifiers as well as network URLs."""
    validator = ResourceIndicatorValidator(
        ResourceIndicatorPolicy(allowed_schemes=None, maximum_resources=None)
    )
    assert validator.validate(("urn:agent:metro-a",)) == ("urn:agent:metro-a",)


def test_default_profile_rejects_multiple_resources() -> None:
    """The safer Phase 1 profile requires one resource per access token."""
    validator = ResourceIndicatorValidator()
    with pytest.raises(ProtocolValidationError) as error:
        validator.validate(("https://one.example/", "https://two.example/"))
    assert error.value.details["maximum_resources"] == 1


def test_rfc_profile_can_accept_multiple_resources() -> None:
    """The reusable implementation supports RFC 8707 multiplicity."""
    validator = ResourceIndicatorValidator(
        ResourceIndicatorPolicy(maximum_resources=None, allowed_schemes=None)
    )
    resources = ("https://one.example/", "urn:agent:two")
    assert validator.validate(resources) == resources


def test_duplicate_resource_is_rejected() -> None:
    """Duplicate indicators are rejected before audience mapping."""
    validator = ResourceIndicatorValidator(ResourceIndicatorPolicy(maximum_resources=2))
    with pytest.raises(ProtocolValidationError, match="duplicate"):
        validator.validate(("https://one.example/", "https://one.example/"))


def test_missing_resource_can_be_optional() -> None:
    """RFC 8707 permits an authorization server to apply a default resource."""
    validator = ResourceIndicatorValidator(
        ResourceIndicatorPolicy(require_resource=False, minimum_resources=0)
    )
    assert validator.validate(()) == ()


def test_invalid_policy_configuration_is_rejected() -> None:
    """Resource-count policy cannot contain impossible limits."""
    with pytest.raises(ValueError, match="must not exceed"):
        ResourceIndicatorPolicy(minimum_resources=2, maximum_resources=1)
