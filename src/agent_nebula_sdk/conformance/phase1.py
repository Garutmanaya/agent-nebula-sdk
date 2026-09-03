"""SDK-only Phase 1 Host → authorization server → provider acceptance flow.

Purpose
-------
Compose every completed Phase 1 standards module through the public role
facades. The harness demonstrates that the SDK can register identities,
authenticate a Host, issue an audience-bound DPoP token, and authenticate a
protected-resource request without Agent Nebula or Agent Genesis product code.

Standards
---------
RFC 7517, RFC 7638, RFC 7523, RFC 7591, RFC 8707, RFC 9068, RFC 9449,
and generic OAuth protected-resource security.

Security boundary
-----------------
The harness establishes authenticated identity and proof of possession. The
final provider-local operation decision is intentionally represented by a
small policy callback because capability authorization is not centralized in
the registry.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import BaseModel, ConfigDict

from agent_nebula_sdk.core.encoding import encode_base64url
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk
from agent_nebula_sdk.jose.jwk.parser import JwkParser
from agent_nebula_sdk.jose.jwks.models import JwkSet
from agent_nebula_sdk.oauth.authorization_server import (
    AuthorizationServerFacade,
    TokenIssuanceRequest,
    TokenIssuanceResult,
)
from agent_nebula_sdk.oauth.client import ClientTokenRequest, OAuthClientFacade
from agent_nebula_sdk.oauth.resource_server import ResourceServerFacade
from agent_nebula_sdk.oauth.rfc7523 import (
    ClientAssertionBuilder,
    InMemoryAssertionReplayStore,
    InMemoryClientKeyResolver,
    InMemoryRegisteredClient,
    InMemoryRegisteredClientStore,
    JwtAssertionValidator,
    PrivateKeyJwtAuthenticator,
    PrivateKeyJwtSigningKey,
    Rfc7523Policy,
)
from agent_nebula_sdk.oauth.rfc7591 import (
    ClientMetadata,
    DynamicClientRegistrationService,
    InMemoryRegisteredClientRepository,
    OpenRegistrationPolicy,
    RegistrationRequest,
    UrlSafeClientIdentifierGenerator,
)
from agent_nebula_sdk.oauth.rfc8707 import (
    ExactResourceCanonicalizer,
    InMemoryResourceRegistry,
    ResourceAudienceValidator,
    ResourceIndicatorValidator,
    ResourceParameterCodec,
    ResourceRegistration,
    ResourceResolutionService,
)
from agent_nebula_sdk.oauth.rfc9068 import (
    AccessTokenSigningKey,
    InMemoryAccessTokenKeyResolver,
    JwtAccessTokenIssuer,
    JwtAccessTokenValidator,
    Rfc9068Policy,
)
from agent_nebula_sdk.oauth.rfc9449 import (
    DpopProofBuilder,
    DpopProofValidator,
    DpopSigningKey,
    DpopTargetUriNormalizer,
    InMemoryDpopReplayStore,
    Rfc9449Policy,
)
from agent_nebula_sdk.ports.clock import Clock
from agent_nebula_sdk.ports.http import HttpResponse, HttpTransport


@dataclass(slots=True)
class MutableClock:
    """Provide deterministic time shared by all acceptance-flow components."""

    current: datetime = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        """Return the configured acceptance-test instant."""
        return self.current


class Phase1AcceptanceResult(BaseModel):
    """Summarize the verified identities and protected-resource response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host_client_id: str
    provider_client_id: str
    audience: str
    authenticated_subject: str
    authenticated_client_id: str
    response_payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _AsymmetricKeyPair:
    """Carry private signing material and the matching validated public JWK."""

    private_key: object
    public_jwk: SupportedPublicJwk


class _ProviderLoopbackTransport(HttpTransport):
    """Route one protected-resource HTTP request into the resource server.

    This transport is intentionally local. It exercises the exact serialized
    headers and body produced by the OAuth client while avoiding a dependency on
    any web framework or product HTTP server.
    """

    def __init__(
        self,
        *,
        endpoint: str,
        expected_issuer: str,
        resource_server: ResourceServerFacade,
        operation_policy: Callable[[str, str], bool],
    ) -> None:
        """Configure the protected endpoint and provider-local policy callback."""
        self._endpoint = endpoint
        self._expected_issuer = expected_issuer
        self._resource_server = resource_server
        self._operation_policy = operation_policy

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Reject unsupported GET requests in this POST-only acceptance transport."""
        del url, headers
        return HttpResponse(status_code=405, headers={}, body=b"")

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> HttpResponse:
        """Authenticate the request, apply local policy, and return JSON output."""
        if url != self._endpoint:
            return self._json_response(404, {"error": "unknown_resource"})
        request_headers = headers or {}
        authorization = request_headers.get("Authorization", "")
        scheme, _, access_token = authorization.partition(" ")
        dpop_proof = request_headers.get("DPoP", "")
        if scheme.lower() != "dpop" or not access_token or not dpop_proof:
            return self._json_response(401, {"error": "invalid_request"})
        security_context = self._resource_server.authenticate_request(
            access_token=access_token,
            dpop_proof=dpop_proof,
            http_method="POST",
            target_uri=url,
            expected_issuer=self._expected_issuer,
        )
        payload = self._parse_payload(body)
        operation = payload.get("operation")
        if not isinstance(operation, str):
            return self._json_response(400, {"error": "missing_operation"})
        if not self._operation_policy(security_context.client_id, operation):
            return self._json_response(403, {"error": "local_policy_denied"})
        return self._json_response(
            200,
            {
                "status": "accepted",
                "operation": operation,
                "subject": security_context.subject,
                "client_id": security_context.client_id,
            },
        )

    @staticmethod
    def _parse_payload(body: bytes) -> dict[str, Any]:
        """Decode the small JSON object used by the acceptance scenario."""
        parsed = json.loads(body)
        if not isinstance(parsed, dict):
            raise ValueError("acceptance protected-resource payload must be a JSON object")
        return parsed

    @staticmethod
    def _json_response(status_code: int, payload: dict[str, Any]) -> HttpResponse:
        """Serialize a deterministic JSON transport response."""
        return HttpResponse(
            status_code=status_code,
            headers={"Content-Type": "application/json"},
            body=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        )


class Phase1AcceptanceHarness:
    """Execute the complete SDK-only Phase 1 security profile.

    Responsibility
    --------------
    Construct reference adapters, register a Host and Provider, bridge the
    resulting public registration data into RFC 7523 key resolution, issue a
    resource-targeted DPoP token, and invoke a generic OAuth protected resource.

    The bridge between RFC 7591 records and RFC 7523 stores represents the
    persistence adapter that Agent Nebula will implement in PostgreSQL.
    """

    issuer = "https://nebula.example"
    token_endpoint = "https://nebula.example/oauth/token"
    provider_endpoint = "https://metro.example/resource"

    def __init__(self, *, clock: Clock | None = None) -> None:
        """Build all Phase 1 roles with deterministic reference infrastructure."""
        self.clock = clock or MutableClock()
        self._host_auth_key = self._build_ec_key_pair("host-auth-2026-01")
        self._host_dpop_key = self._build_ec_key_pair("host-dpop-2026-01")
        self._provider_auth_key = self._build_ec_key_pair("provider-auth-2026-01")
        self._issuer_key = self._build_rsa_key_pair("nebula-signing-2026-01")

        self._registration_repository = InMemoryRegisteredClientRepository()
        registration_service = DynamicClientRegistrationService(
            repository=self._registration_repository,
            identifier_generator=UrlSafeClientIdentifierGenerator(),
            policy=OpenRegistrationPolicy(
                allowed_extension_names=frozenset({"agent_nebula_entity_type"})
            ),
            clock=self.clock,
        )
        self._registered_clients = InMemoryRegisteredClientStore()
        self._client_keys = InMemoryClientKeyResolver()

        rfc7523_policy = Rfc7523Policy()
        self._assertion_builder = ClientAssertionBuilder(
            clock=self.clock,
            policy=rfc7523_policy,
        )
        client_authenticator = PrivateKeyJwtAuthenticator(
            clients=self._registered_clients,
            keys=self._client_keys,
            replay_store=InMemoryAssertionReplayStore(clock=self.clock),
            validator=JwtAssertionValidator(clock=self.clock, policy=rfc7523_policy),
            accepted_audiences=(self.token_endpoint,),
        )

        resource_registry = InMemoryResourceRegistry(
            registrations=(
                ResourceRegistration(
                    resource=self.provider_endpoint,
                    audience=self.provider_endpoint,
                    metadata={"provider": "parking-metro-a"},
                ),
            )
        )
        resource_service = ResourceResolutionService(
            registry=resource_registry,
            validator=ResourceIndicatorValidator(),
            canonicalizer=ExactResourceCanonicalizer(),
        )

        dpop_policy = Rfc9449Policy()
        dpop_uri = DpopTargetUriNormalizer(policy=dpop_policy)
        self._dpop_builder = DpopProofBuilder(
            clock=self.clock,
            policy=dpop_policy,
            uri_normalizer=dpop_uri,
        )
        token_dpop_validator = DpopProofValidator(
            clock=self.clock,
            policy=dpop_policy,
            replay_store=InMemoryDpopReplayStore(clock=self.clock),
            uri_normalizer=dpop_uri,
        )
        provider_dpop_validator = DpopProofValidator(
            clock=self.clock,
            policy=dpop_policy,
            replay_store=InMemoryDpopReplayStore(clock=self.clock),
            uri_normalizer=dpop_uri,
        )

        rfc9068_policy = Rfc9068Policy()
        token_issuer = JwtAccessTokenIssuer(clock=self.clock, policy=rfc9068_policy)
        verification_keys = InMemoryAccessTokenKeyResolver()
        verification_keys.register(issuer=self.issuer, key=self._issuer_key.public_jwk)
        token_validator = JwtAccessTokenValidator(
            clock=self.clock,
            policy=rfc9068_policy,
            key_resolver=verification_keys,
        )

        self.client = OAuthClientFacade(
            assertion_builder=self._assertion_builder,
            resource_codec=ResourceParameterCodec(),
            dpop_builder=self._dpop_builder,
        )
        self.authorization_server = AuthorizationServerFacade(
            registration_service=registration_service,
            client_authenticator=client_authenticator,
            resource_service=resource_service,
            token_issuer=token_issuer,
            dpop_validator=token_dpop_validator,
        )
        self.resource_server = ResourceServerFacade(
            token_validator=token_validator,
            dpop_validator=provider_dpop_validator,
            audience_validator=ResourceAudienceValidator(expected_audience=self.provider_endpoint),
        )
        self._host_client_id: str | None = None
        self._provider_client_id: str | None = None
        self._last_access_token: str | None = None

    def run(self) -> Phase1AcceptanceResult:
        """Run registration, token issuance, and authenticated resource invocation."""
        host_client_id, provider_client_id = self.register_default_entities()
        issuance = self.issue_host_token(host_client_id)

        transport = _ProviderLoopbackTransport(
            endpoint=self.provider_endpoint,
            expected_issuer=self.issuer,
            resource_server=self.resource_server,
            operation_policy=lambda client_id, operation: (
                client_id == host_client_id and operation == "parking.search"
            ),
        )
        artifacts = self.client.build_protected_request(
            http_method="POST",
            target_uri=self.provider_endpoint,
            access_token=issuance.access_token.token,
            dpop_key=self.host_dpop_signing_key,
        )
        raw_response = transport.post(
            self.provider_endpoint,
            headers=artifacts.headers,
            body=json.dumps({"operation": "parking.search"}).encode("utf-8"),
        )
        response_payload = json.loads(raw_response.body) if raw_response.body else None
        if raw_response.status_code != 200 or not isinstance(response_payload, dict):
            raise RuntimeError("Phase 1 acceptance invocation did not succeed")
        self._last_access_token = issuance.access_token.token
        return Phase1AcceptanceResult(
            host_client_id=host_client_id,
            provider_client_id=provider_client_id,
            audience=issuance.audience,
            authenticated_subject=str(response_payload["subject"]),
            authenticated_client_id=str(response_payload["client_id"]),
            response_payload=response_payload,
        )

    def register_default_entities(self) -> tuple[str, str]:
        """Register the reference Host and Provider through RFC 7591."""
        host_client_id = self._register_entity(
            name="Parking Host",
            entity_type="service_client",
            public_jwk=self._host_auth_key.public_jwk,
        )
        provider_client_id = self._register_entity(
            name="Parking Metro A",
            entity_type="provider_agent",
            public_jwk=self._provider_auth_key.public_jwk,
        )
        self._host_client_id = host_client_id
        self._provider_client_id = provider_client_id
        return host_client_id, provider_client_id

    def build_host_token_request(
        self, host_client_id: str
    ) -> tuple[ClientTokenRequest, PrivateKeyJwtSigningKey]:
        """Build typed Host inputs used to create one fresh token request."""
        request = ClientTokenRequest(
            client_id=host_client_id,
            token_endpoint=self.token_endpoint,
            resource=self.provider_endpoint,
        )
        return request, self.host_authentication_signing_key

    def issue_host_token(self, host_client_id: str) -> TokenIssuanceResult:
        """Authenticate the Host and issue one audience-bound DPoP token."""
        request, authentication_key = self.build_host_token_request(host_client_id)
        artifacts = self.client.build_token_request(
            request=request,
            authentication_key=authentication_key,
            dpop_key=self.host_dpop_signing_key,
        )
        issuance = self.authorization_server.issue_resource_token(
            request=TokenIssuanceRequest(
                client_authentication=artifacts.client_authentication,
                dpop_proof=artifacts.dpop_proof.proof,
                token_endpoint=self.token_endpoint,
                resource=self.provider_endpoint,
                issuer=self.issuer,
                additional_claims={
                    "urn:agent-nebula:claims:registration_method": "open_rfc7591",
                    "urn:agent-nebula:claims:trust_status": "UNVERIFIED",
                },
            ),
            signing_key=self.issuer_signing_key,
        )
        self._last_access_token = issuance.access_token.token
        return issuance

    @property
    def host_authentication_signing_key(self) -> PrivateKeyJwtSigningKey:
        """Return the Host key used for RFC 7523 client authentication."""
        return PrivateKeyJwtSigningKey(
            key_id=self._host_auth_key.public_jwk.kid or "",
            algorithm="ES256",
            private_key=self._host_auth_key.private_key,
        )

    @property
    def last_access_token(self) -> str:
        """Return the most recently issued token or fail before issuance."""
        if self._last_access_token is None:
            raise RuntimeError("no access token has been issued")
        return self._last_access_token

    @property
    def host_dpop_signing_key(self) -> DpopSigningKey:
        """Return the Host key used to sender-constrain OAuth requests."""
        return DpopSigningKey(
            algorithm="ES256",
            private_key=self._host_dpop_key.private_key,
            public_jwk=self._host_dpop_key.public_jwk,
        )

    @property
    def issuer_signing_key(self) -> AccessTokenSigningKey:
        """Return the authorization-server key used for RFC 9068 issuance."""
        return AccessTokenSigningKey(
            key_id=self._issuer_key.public_jwk.kid or "",
            algorithm="RS256",
            private_key=self._issuer_key.private_key,
        )

    def _register_entity(
        self,
        *,
        name: str,
        entity_type: str,
        public_jwk: SupportedPublicJwk,
    ) -> str:
        """Register one entity and install its public key in the auth adapter."""
        metadata = ClientMetadata.model_validate(
            {
                "client_name": name,
                "grant_types": ["client_credentials"],
                "response_types": [],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": JwkSet(keys=(public_jwk,)).model_dump(mode="json"),
                "agent_nebula_entity_type": entity_type,
            }
        )
        response = self.authorization_server.register_client(RegistrationRequest(metadata=metadata))
        record = self._registration_repository.get(response.client_id)
        if record is None:
            raise RuntimeError("registered client record was not persisted")
        self._registered_clients.put(
            InMemoryRegisteredClient(
                client_id=response.client_id,
                is_active=record.is_active,
                token_endpoint_auth_method=str(record.metadata["token_endpoint_auth_method"]),
                metadata={
                    "registration_method": record.registration_method,
                    "trust_status": record.trust_status,
                    **record.metadata,
                },
            )
        )
        self._client_keys.put(client_id=response.client_id, key=public_jwk)
        return response.client_id

    @staticmethod
    def _build_ec_key_pair(key_id: str) -> _AsymmetricKeyPair:
        """Generate a P-256 key pair and validated ES256 public JWK."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        public_jwk = JwkParser().parse_public_jwk(
            {
                "kty": "EC",
                "kid": key_id,
                "use": "sig",
                "alg": "ES256",
                "crv": "P-256",
                "x": encode_base64url(numbers.x.to_bytes(32, byteorder="big")),
                "y": encode_base64url(numbers.y.to_bytes(32, byteorder="big")),
            }
        )
        return _AsymmetricKeyPair(private_key=private_key, public_jwk=public_jwk)

    @staticmethod
    def _build_rsa_key_pair(key_id: str) -> _AsymmetricKeyPair:
        """Generate an RSA key pair and validated RS256 public JWK."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private_key.public_key().public_numbers()
        public_jwk = JwkParser().parse_public_jwk(
            {
                "kty": "RSA",
                "kid": key_id,
                "use": "sig",
                "alg": "RS256",
                "n": Phase1AcceptanceHarness._encode_unsigned_integer(numbers.n),
                "e": Phase1AcceptanceHarness._encode_unsigned_integer(numbers.e),
            }
        )
        return _AsymmetricKeyPair(private_key=private_key, public_jwk=public_jwk)

    @staticmethod
    def _encode_unsigned_integer(value: int) -> str:
        """Encode a positive integer using the JWK base64urlUInt format."""
        length = max(1, (value.bit_length() + 7) // 8)
        return encode_base64url(value.to_bytes(length, byteorder="big"))
