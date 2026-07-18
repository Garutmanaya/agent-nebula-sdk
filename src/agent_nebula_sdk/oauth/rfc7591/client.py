"""Client-side HTTP integration for RFC 7591 registration."""

from __future__ import annotations

import json

from pydantic import ValidationError

from agent_nebula_sdk.core.errors import ExternalServiceError, ProtocolValidationError
from agent_nebula_sdk.oauth.rfc7591.constants import DYNAMIC_CLIENT_REGISTRATION_CONTENT_TYPE
from agent_nebula_sdk.oauth.rfc7591.models import ClientMetadata, RegistrationResponse
from agent_nebula_sdk.ports.http import HttpTransport


class DynamicClientRegistrationClient:
    """Submit registration metadata to an RFC 7591 endpoint."""

    def __init__(
        self,
        *,
        endpoint: str,
        transport: HttpTransport,
        maximum_response_bytes: int = 1_048_576,
    ) -> None:
        """Configure the endpoint, transport, and bounded response size."""
        if not endpoint.startswith("https://"):
            raise ValueError("registration endpoint must use HTTPS")
        if maximum_response_bytes < 1:
            raise ValueError("maximum_response_bytes must be positive")
        self._endpoint = endpoint
        self._transport = transport
        self._maximum_response_bytes = maximum_response_bytes

    def register(
        self,
        metadata: ClientMetadata,
        *,
        initial_access_token: str | None = None,
    ) -> RegistrationResponse:
        """Register a client and parse the successful response.

        RFC 7591 Section 3 requires a JSON request. A protected registration
        endpoint may additionally receive an initial access token in the
        Authorization header.
        """
        headers = {
            "Accept": DYNAMIC_CLIENT_REGISTRATION_CONTENT_TYPE,
            "Content-Type": DYNAMIC_CLIENT_REGISTRATION_CONTENT_TYPE,
        }
        if initial_access_token is not None:
            headers["Authorization"] = f"Bearer {initial_access_token}"

        body = json.dumps(metadata.model_dump(exclude_none=True, mode="json")).encode()
        response = self._transport.post(self._endpoint, headers=headers, body=body)
        if len(response.body) > self._maximum_response_bytes:
            raise ExternalServiceError(
                "registration response exceeded configured size limit",
                code="registration_response_too_large",
            )

        payload = self._decode_json_response(response.body)
        if response.status_code not in {200, 201}:
            raise ProtocolValidationError(
                str(payload.get("error_description", "registration request failed")),
                code=str(payload.get("error", "registration_error")),
                details={"status_code": response.status_code},
            )
        try:
            return RegistrationResponse.model_validate(payload)
        except ValidationError as exc:
            raise ExternalServiceError(
                "registration endpoint returned an invalid success response",
                code="invalid_registration_response",
                details={"errors": exc.errors(include_url=False)},
            ) from exc

    @staticmethod
    def _decode_json_response(body: bytes) -> dict[str, object]:
        """Decode an RFC 7591 JSON response without leaking JSON exceptions."""
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExternalServiceError(
                "registration endpoint returned invalid JSON",
                code="invalid_registration_json",
            ) from exc
        if not isinstance(payload, dict):
            raise ExternalServiceError(
                "registration endpoint response must be a JSON object",
                code="invalid_registration_json",
            )
        return payload
