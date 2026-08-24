"""Client-side HTTP integration for RFC 7592 registration management."""

from __future__ import annotations

import json

from pydantic import ValidationError

from agent_nebula_sdk.core.errors import ExternalServiceError, ProtocolValidationError
from agent_nebula_sdk.oauth.rfc7592.models import ClientConfigurationResponse, ClientUpdateRequest
from agent_nebula_sdk.ports.http import HttpTransport


class ClientRegistrationManagementClient:
    """Read, replace, and delete a client registration through RFC 7592."""

    def __init__(
        self,
        *,
        registration_client_uri: str,
        registration_access_token: str,
        transport: HttpTransport,
        maximum_response_bytes: int = 1_048_576,
    ) -> None:
        """Configure the server-issued endpoint, Bearer token, and transport."""
        if not registration_client_uri.startswith("https://"):
            raise ValueError("registration_client_uri must use HTTPS")
        if not registration_access_token:
            raise ValueError("registration_access_token is required")
        if maximum_response_bytes < 1:
            raise ValueError("maximum_response_bytes must be positive")
        self._registration_client_uri = registration_client_uri
        self._registration_access_token = registration_access_token
        self._transport = transport
        self._maximum_response_bytes = maximum_response_bytes

    def read(self) -> ClientConfigurationResponse:
        """Read the current RFC 7592 client configuration using Bearer authentication."""
        response = self._transport.get(
            self._registration_client_uri,
            headers=self._headers(),
        )
        return self._parse_configuration_response(response.status_code, response.body)

    def update(self, request: ClientUpdateRequest) -> ClientConfigurationResponse:
        """Replace client metadata with an RFC 7592 HTTP PUT operation."""
        payload = request.metadata.model_dump(exclude_none=True, mode="json")
        payload["client_id"] = request.client_id
        if request.client_secret is not None:
            payload["client_secret"] = request.client_secret
        response = self._transport.put(
            self._registration_client_uri,
            headers={**self._headers(), "Content-Type": "application/json"},
            body=json.dumps(payload).encode("utf-8"),
        )
        return self._parse_configuration_response(response.status_code, response.body)

    def delete(self) -> None:
        """Deprovision the client using the RFC 7592 HTTP DELETE operation."""
        response = self._transport.delete(
            self._registration_client_uri,
            headers=self._headers(),
        )
        if response.status_code != 204:
            self._raise_protocol_error(response.status_code, response.body)

    def _headers(self) -> dict[str, str]:
        """Build RFC 7592 Bearer authentication and response headers."""
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._registration_access_token}",
        }

    def _parse_configuration_response(
        self,
        status_code: int,
        body: bytes,
    ) -> ClientConfigurationResponse:
        """Parse an RFC 7592 read/update response and rotate local credentials."""
        if len(body) > self._maximum_response_bytes:
            raise ExternalServiceError(
                "client configuration response exceeded configured size limit",
                code="registration_management_response_too_large",
            )
        if status_code != 200:
            self._raise_protocol_error(status_code, body)
        payload = self._decode_json(body)
        try:
            result = ClientConfigurationResponse.model_validate(payload)
        except ValidationError as exc:
            raise ExternalServiceError(
                "client configuration endpoint returned an invalid response",
                code="invalid_registration_management_response",
                details={"errors": exc.errors(include_url=False)},
            ) from exc
        self._registration_client_uri = result.registration_client_uri
        self._registration_access_token = result.registration_access_token
        return result

    @staticmethod
    def _raise_protocol_error(status_code: int, body: bytes) -> None:
        """Normalize RFC 7592/Bearer error responses into SDK protocol errors."""
        payload = ClientRegistrationManagementClient._decode_json(body) if body else {}
        raise ProtocolValidationError(
            str(payload.get("error_description", "client registration management request failed")),
            code=str(payload.get("error", "registration_management_error")),
            details={"status_code": status_code},
        )

    @staticmethod
    def _decode_json(body: bytes) -> dict[str, object]:
        """Decode a JSON response without leaking JSON-library exceptions."""
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExternalServiceError(
                "client configuration endpoint returned invalid JSON",
                code="invalid_registration_management_json",
            ) from exc
        if not isinstance(payload, dict):
            raise ExternalServiceError(
                "client configuration endpoint response must be a JSON object",
                code="invalid_registration_management_json",
            )
        return payload
