"""Resource-server validation of audience restrictions selected via RFC 8707.

RFC 8707 recommends audience-restricting issued tokens to the indicated
resource. The future RFC 9068 validator will parse and cryptographically verify
the JWT; this module performs the independent audience membership decision.
"""

from __future__ import annotations

from collections.abc import Sequence

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc8707.models import AudienceValidationResult


class ResourceAudienceValidator:
    """Require an access token audience to include the local protected resource."""

    def __init__(self, *, expected_audience: str, require_single_audience: bool = True) -> None:
        """Configure the local resource identifier and audience-cardinality policy."""
        if not expected_audience:
            raise ValueError("expected_audience must not be empty")
        self._expected_audience = expected_audience
        self._require_single_audience = require_single_audience

    def validate(self, audience: str | Sequence[str]) -> AudienceValidationResult:
        """Validate a JWT-style string or string-array ``aud`` claim.

        This function assumes token signature and issuer checks have already
        succeeded. It rejects cross-provider token reuse before local business
        authorization is evaluated.
        """
        token_audiences = self._coerce_audiences(audience)
        if self._require_single_audience and len(token_audiences) != 1:
            raise ProtocolValidationError(
                "access token must contain exactly one audience",
                code="invalid_token_audience",
                details={"audiences": list(token_audiences)},
            )
        if self._expected_audience not in token_audiences:
            raise ProtocolValidationError(
                "access token is not intended for this protected resource",
                code="invalid_token_audience",
                details={
                    "expected_audience": self._expected_audience,
                    "token_audiences": list(token_audiences),
                },
            )
        return AudienceValidationResult(
            expected_audience=self._expected_audience,
            token_audiences=token_audiences,
        )

    @staticmethod
    def _coerce_audiences(audience: str | Sequence[str]) -> tuple[str, ...]:
        """Convert a JWT ``aud`` value into a non-empty immutable sequence."""
        audiences = (audience,) if isinstance(audience, str) else tuple(audience)
        if not audiences or any(not item for item in audiences):
            raise ProtocolValidationError(
                "access token audience is missing or malformed",
                code="invalid_token_audience",
            )
        return audiences
