"""Unit tests for RFC 7517 JWK Set validation and selection."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_nebula_sdk.core.errors import DuplicateKeyIdentifierError, KeyResolutionError
from agent_nebula_sdk.jose.jwks.models import JwkSet


def test_selects_key_by_kid_and_algorithm(
    rsa_public_jwk: dict[str, str],
    ec_public_jwk: dict[str, str],
) -> None:
    """Key selection is deterministic when kid and algorithm are supplied."""
    jwks = JwkSet.from_untrusted_mapping({"keys": [rsa_public_jwk, ec_public_jwk]})

    selected = jwks.select(kid="ec-2026-01", alg="ES256")

    assert selected.kty == "EC"


def test_rejects_duplicate_kid(rsa_public_jwk: dict[str, str]) -> None:
    """Duplicate key identifiers are rejected as ambiguous."""
    second = {**rsa_public_jwk, "n": rsa_public_jwk["n"]}

    with pytest.raises(DuplicateKeyIdentifierError):
        JwkSet.from_untrusted_mapping({"keys": [rsa_public_jwk, second]})


def test_missing_kid_is_allowed_only_for_one_candidate(
    rsa_public_jwk: dict[str, str],
    ec_public_jwk: dict[str, str],
) -> None:
    """A JOSE header without kid cannot arbitrarily select from many keys."""
    one = JwkSet.from_untrusted_mapping({"keys": [{**rsa_public_jwk, "kid": None}]})
    assert one.select(kid=None).kty == "RSA"

    many = JwkSet.from_untrusted_mapping(
        {
            "keys": [
                {**rsa_public_jwk, "kid": None},
                {**ec_public_jwk, "kid": None},
            ]
        }
    )
    with pytest.raises(KeyResolutionError) as error:
        many.select(kid=None)
    assert error.value.code == "ambiguous_jwks_key"


def test_rejects_empty_jwks() -> None:
    """The Phase 1 publication and registration profile requires at least one key."""
    with pytest.raises(ValidationError):
        JwkSet.from_untrusted_mapping({"keys": []})
