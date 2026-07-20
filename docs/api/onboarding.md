# Onboarding API

`agent_nebula_sdk.onboarding.OnboardingService` is the top-level orchestration API for dynamic registration. Authentication strategies and registration profiles are registered explicitly, and the application supplies one atomic transaction port.

## Standards composition

- OAuth client profile reuses RFC 7591 models.
- Protected-resource profile reuses RFC 9728 metadata and supports later RFC 8707 audience resolution.
- Software statements reuse the RFC 7591 verifier contract.
- mTLS is explicitly unavailable until RFC 8705 is implemented.

## Boundaries

The API owns no HTTP route, database, configuration loader, approval workflow, or business policy.
