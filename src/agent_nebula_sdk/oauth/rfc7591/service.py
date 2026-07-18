"""Authorization-server service for RFC 7591 registration.

The service validates metadata, applies optional software statements, invokes
an onboarding policy, creates a collision-resistant client identifier, and
persists the resulting client record through a product-owned repository.
"""

from __future__ import annotations

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc7591.models import (
    RegisteredClientRecord,
    RegistrationRequest,
    RegistrationResponse,
)
from agent_nebula_sdk.oauth.rfc7591.ports import (
    ClientIdentifierGenerator,
    RegisteredClientRepository,
    RegistrationPolicy,
)
from agent_nebula_sdk.oauth.rfc7591.software_statement import SoftwareStatementProcessor
from agent_nebula_sdk.ports.clock import Clock


class DynamicClientRegistrationService:
    """Coordinate RFC 7591 registration without owning infrastructure.

    Responsibility
    --------------
    Apply the registration protocol in a deterministic order and return a
    standards-compatible response. Secret generation is intentionally absent
    from the Agent Nebula Phase 1 profile because clients authenticate with
    RFC 7523 ``private_key_jwt``.
    """

    def __init__(
        self,
        *,
        repository: RegisteredClientRepository,
        identifier_generator: ClientIdentifierGenerator,
        policy: RegistrationPolicy,
        clock: Clock,
        software_statement_processor: SoftwareStatementProcessor | None = None,
        reject_duplicate_software_identity: bool = False,
        maximum_identifier_attempts: int = 5,
    ) -> None:
        """Configure persistence, policy, time, and optional statement processing."""
        if maximum_identifier_attempts < 1:
            raise ValueError("maximum_identifier_attempts must be positive")
        self._repository = repository
        self._identifier_generator = identifier_generator
        self._policy = policy
        self._clock = clock
        self._software_statement_processor = software_statement_processor
        self._reject_duplicate_software_identity = reject_duplicate_software_identity
        self._maximum_identifier_attempts = maximum_identifier_attempts

    def register(self, request: RegistrationRequest) -> RegistrationResponse:
        """Register a client and return the RFC 7591 response.

        Processing order matters: onboarding authorization occurs before
        potentially expensive software-statement processing or identifier
        allocation; metadata and extensions are then validated before durable
        persistence.
        """
        self._policy.authorize(request)

        metadata = request.metadata
        if self._software_statement_processor is not None:
            metadata = self._software_statement_processor.apply(metadata)

        self._policy.validate_extensions(metadata)
        self._reject_duplicate_software_registration(metadata)
        client_id = self._allocate_unique_client_identifier()
        issued_at = int(self._clock.now().timestamp())

        record = RegisteredClientRecord(
            client_id=client_id,
            client_id_issued_at=issued_at,
            metadata=metadata.standard_metadata(
                allowed_extension_names=self._policy.allowed_extension_names(),
            ),
            registration_method=self._policy.registration_method(request),
            trust_status=self._policy.trust_status(request),
        )
        self._repository.save(record)
        return RegistrationResponse.from_record(record)

    def _allocate_unique_client_identifier(self) -> str:
        """Generate a non-colliding client identifier with a bounded retry count."""
        for _ in range(self._maximum_identifier_attempts):
            candidate = self._identifier_generator.generate()
            if not self._repository.exists(candidate):
                return candidate
        raise ProtocolValidationError(
            "unable to allocate a unique client identifier",
            code="client_id_allocation_failed",
        )

    def _reject_duplicate_software_registration(self, metadata: object) -> None:
        """Optionally reject duplicate software identities.

        RFC 7591 does not require uniqueness for ``software_id``. This profile
        exposes duplicate handling as configuration because some enterprise
        registries require one active registration per software version while
        open ecosystems permit multiple client instances.
        """
        if not self._reject_duplicate_software_identity:
            return
        software_id = getattr(metadata, "software_id", None)
        software_version = getattr(metadata, "software_version", None)
        if software_id is None:
            return
        existing = self._repository.find_by_software_identity(
            software_id,
            software_version,
        )
        if existing is not None:
            raise ProtocolValidationError(
                "software identity is already registered",
                code="duplicate_software_identity",
                details={
                    "software_id": software_id,
                    "software_version": software_version,
                },
            )
