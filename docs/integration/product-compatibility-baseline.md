# Product compatibility baseline

Agent Nebula SDK Phase 1 is integrated into Agent Nebula and Agent Genesis using a strict compatibility baseline before any product behavior is replaced.

## Required runtime

- CPython 3.12.x
- Agent Nebula SDK 1.9.0
- cryptography 45.0.0
- httpx 0.28.1
- PyJWT 2.10.1
- Pydantic 2.11.0

## Compatibility rule

All repositories must use the same Python minor version and the same exact versions of shared security and serialization packages. A dependency update is performed as a coordinated change across all three repositories and must pass the SDK conformance suite plus both product test suites.
