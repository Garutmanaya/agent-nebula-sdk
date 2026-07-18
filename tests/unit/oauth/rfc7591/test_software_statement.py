"""Unit tests for RFC 7591 software statement processing."""

from __future__ import annotations

from agent_nebula_sdk.oauth.rfc7591.models import ClientMetadata
from agent_nebula_sdk.oauth.rfc7591.software_statement import SoftwareStatementProcessor


class StaticSoftwareStatementVerifier:
    """Return preconfigured trusted statement metadata."""

    def verify(self, statement: str) -> dict[str, object]:
        """Verify the expected fixture value and return signed claims."""
        assert statement == "signed-statement"
        return {"client_name": "Trusted Publisher Name", "software_id": "trusted-id"}


def test_verified_statement_metadata_takes_precedence(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Signed publisher metadata overrides conflicting untrusted request values."""
    metadata = ClientMetadata.model_validate(
        {
            "client_name": "Untrusted Name",
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["client_credentials"],
            "response_types": [],
            "jwks": {"keys": [rsa_public_jwk]},
            "software_statement": "signed-statement",
        }
    )
    processed = SoftwareStatementProcessor(StaticSoftwareStatementVerifier()).apply(metadata)
    assert processed.client_name == "Trusted Publisher Name"
    assert processed.software_id == "trusted-id"
    assert processed.software_statement is None


class FailingSoftwareStatementVerifier:
    """Simulate signature or issuer verification failure."""

    def verify(self, statement: str) -> dict[str, object]:
        """Raise the underlying verifier error expected by the processor."""
        raise RuntimeError(statement)


def test_invalid_software_statement_is_normalized(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Verifier failures become stable RFC 7591 protocol errors."""
    from agent_nebula_sdk.core.errors import ProtocolValidationError

    metadata = ClientMetadata.model_validate(
        {
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["client_credentials"],
            "response_types": [],
            "jwks": {"keys": [rsa_public_jwk]},
            "software_statement": "invalid",
        }
    )
    processor = SoftwareStatementProcessor(FailingSoftwareStatementVerifier())
    try:
        processor.apply(metadata)
    except ProtocolValidationError as error:
        assert error.code == "invalid_software_statement"
    else:
        raise AssertionError("invalid software statement was accepted")


def test_processor_without_statement_returns_same_metadata(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Registration without a software statement bypasses verifier processing."""
    metadata = ClientMetadata.model_validate(
        {
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["client_credentials"],
            "response_types": [],
            "jwks": {"keys": [rsa_public_jwk]},
        }
    )
    processor = SoftwareStatementProcessor(FailingSoftwareStatementVerifier())
    assert processor.apply(metadata) is metadata


def test_software_statement_is_preserved_in_registered_metadata(
    rsa_public_jwk: dict[str, str],
) -> None:
    """RFC 7591 Section 3.2.1 returns the statement unmodified in the response."""
    metadata = ClientMetadata.model_validate(
        {
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["client_credentials"],
            "response_types": [],
            "jwks": {"keys": [rsa_public_jwk]},
            "software_statement": "signed-statement",
        }
    )
    assert metadata.standard_metadata()["software_statement"] == "signed-statement"
