
## 1.3.0 - Step 4 RFC 7591

- Implement RFC 7591 dynamic client registration models, service, policies, software statements, and HTTP client.
- Add open and controlled registration profiles without coupling the SDK to product persistence.
- Add inline JWKS and JWKS URI validation, extension metadata support, duplicate software identity policy, and reference adapters.


## 1.2.2 - Step 3.1 documentation standard

- Expanded class, method, and function documentation across the SDK.
- Added package-level README files and a permanent source documentation standard.
- Preserved Step 3 protocol behavior and public APIs.

# Changelog
## 1.2.1 - Step 3 quality correction

- Formatted all source and test files with Ruff.
- Resolved all Ruff lint failures in the RFC 7523 implementation and tests.
- Replaced abstract `NotImplementedError` methods with explicit abstract methods.
- Added missing test-helper documentation.
- Added an automated source-quality audit for module, class, function, and method docstrings.
- Added a check that rejects multiple Python statements on one source line.
- Extended the verification gate to format, lint, and compile the `scripts` directory.
- Removed environment-specific lock and generated runtime artifacts from the release archive.


## 1.1.0 — Step 2

- Added production repository tooling and strict verification gates.
- Added stable SDK error and HTTP transport contracts.
- Implemented RFC 7517 public JWK and JWK Set validation.
- Implemented RFC 7638 thumbprints.
- Added RSA, EC, and RFC 8037 Ed25519 public-key conversion.
- Added secure `jwks_uri` policy, remote resolution, caching, and key-rotation refresh.
- Added unit, conformance, adversarial, and external HTTP tests.

## 1.0.0 — Step 1

- Architecture-only baseline.

## 1.2.0

- Implement RFC 7523 private-key JWT client authentication.
- Implement RFC 7523 JWT bearer authorization grants.
- Add strict assertion policy, replay ports, reference adapters, tests, and docs.

## 1.4.0 — Step 5 RFC 8707

- Added RFC 8707 resource-indicator models, validation, codecs, registry ports,
  reference adapters, audience mapping, and resource-server audience checks.
- Added prior-grant subset enforcement for authorization-code and refresh-token
  integrations.
- Added the complete roadmap and standards mapping.
- Reserved stable category-based package paths for future OAuth, metadata, A2A,
  MCP, TLS, SPIFFE, identity, and GNAP implementations.

## 1.5.0 — Step 6 RFC 9068

- Added RFC 9068 JWT access-token issuance and resource-server validation.
- Enforced `at+jwt`, mandatory claims, RS256 interoperability, explicit
  algorithm allowlists, exact issuer/audience validation, and stable
  `invalid_token` errors.
- Added optional authentication and authorization claims plus collision-resistant
  private claim policy.
- Integrated RFC 8707 audience resolution with RFC 9068 issuance tests.
