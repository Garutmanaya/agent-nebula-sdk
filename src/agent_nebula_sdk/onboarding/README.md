# Onboarding

The onboarding package is the SDK entry point for secure registration of dynamic agents. It composes existing protocol modules and never reimplements OAuth, JOSE, JWT, JWK, MCP, TLS, or cryptographic behavior.

## Processing flow

1. Resolve the configured authentication strategy.
2. Authenticate before profile processing or network activity.
3. Prepare every declared registration profile.
4. Submit all prepared profiles to one application-owned atomic transaction.
5. Return normalized identifiers and trust information.

## Registration profiles

- `AGENT`: Agent identity and Agent Card linkage.
- `OAUTH_CLIENT`: RFC 7591 metadata represented by `RegistrationRequest`.
- `PROTECTED_RESOURCE`: RFC 9728 metadata used by RFC 8707 resource resolution.

## Authentication

Open, API key, initial access token, software statement, and mTLS strategies are pluggable. API-key storage and initial-access-token lifecycle are application responsibilities supplied through ports. mTLS authentication reuses the generic X.509 trust validator; OAuth certificate-bound token validation is implemented by the RFC 8705 module.

## Product boundary

The SDK contains no database, SQL, FastAPI route, configuration loader, approval workflow, or business policy. Agent Nebula and Agent Genesis supply adapters and composition.

## Typed registration results and resolution

Onboarding results distinguish internal persistence identifiers from protocol
identifiers. The OAuth profile returns both `oauth_client_id` (Nebula's UUID)
and the RFC-facing `client_id`. Protected-resource results similarly return the
internal UUID and the RFC 8707 `resource_identifier`.

The onboarding transaction port supports read-only resolution before creation.
Matching Agent identity, Agent Card URI, roles, public-key identity, RFC 7591
metadata, and protected-resource metadata resolve to the existing registration.
Conflicting public keys or metadata fail closed rather than replacing a
registration implicitly.

## Enterprise CLIENT enrollment result

`ClientEnrollmentProfileResult` is a protocol-neutral result contract used by
Agent Nebula to report a Registry enterprise CLIENT enrollment before RFC 7591
DCR.

**AGENT NEBULA ADDITIONAL FUNCTIONALITY:** the enrollment identifier is not an
OAuth `client_id`; Authorization Servers remain responsible for issuing
`client_id`.

