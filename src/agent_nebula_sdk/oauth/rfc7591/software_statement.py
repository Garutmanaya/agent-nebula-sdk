"""Software statement metadata processing for RFC 7591.

RFC 7591 Section 2.3 allows a signed software statement to contribute client
metadata. Verification is delegated to a trusted issuer adapter; this module
only applies the standard precedence and consistency rules.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc7591.models import ClientMetadata
from agent_nebula_sdk.oauth.rfc7591.ports import SoftwareStatementVerifier


class SoftwareStatementProcessor:
    """Verify software statements and merge trusted metadata into a request."""

    def __init__(self, verifier: SoftwareStatementVerifier) -> None:
        """Store the verifier used to establish software statement trust."""
        self._verifier = verifier

    def apply(self, metadata: ClientMetadata) -> ClientMetadata:
        """Return metadata after applying a verified software statement.

        RFC 7591 leaves conflict handling to authorization-server policy. This
        SDK profile gives verified statement claims precedence over matching
        request members, preventing an untrusted request from weakening signed
        publisher metadata.
        """
        statement = metadata.software_statement
        if statement is None:
            return metadata

        try:
            statement_claims = self._verifier.verify(statement)
        except Exception as exc:
            raise ProtocolValidationError(
                "software statement verification failed",
                code="invalid_software_statement",
            ) from exc

        merged: dict[str, Any] = metadata.model_dump(mode="python")
        merged.pop("software_statement", None)
        merged.update(statement_claims)
        try:
            return ClientMetadata.model_validate(merged)
        except ValidationError as exc:
            raise ProtocolValidationError(
                "software statement contains invalid client metadata",
                code="invalid_software_statement",
                details={"errors": exc.errors(include_url=False)},
            ) from exc
