# Onboarding

The onboarding package is the SDK entry point for secure registration of dynamic agents. It composes existing protocol modules and never reimplements OAuth, JOSE, JWT, JWK, A2A, MCP, TLS, or cryptographic behavior.

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

Open, API key, initial access token, and software statement strategies are pluggable. API-key storage and initial-access-token lifecycle are application responsibilities supplied through ports. mTLS is an explicit placeholder until RFC 8705 is implemented.

## Product boundary

The SDK contains no database, SQL, FastAPI route, configuration loader, approval workflow, or business policy. Agent Nebula and Agent Genesis supply adapters and composition.
