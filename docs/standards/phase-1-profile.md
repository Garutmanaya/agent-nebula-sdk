# Phase 1 Standards Profile

## Registry onboarding and authentication

- RFC 7591 dynamic registration supports open and controlled profiles.
- RFC 7523 `private_key_jwt` proves possession of a registered asymmetric key.
- RFC 7517 and RFC 7638 define public-key representation and thumbprints.

## Provider-targeted access

- RFC 8707 identifies the target protected resource.
- RFC 9068 defines JWT access-token claims and validation profile.
- RFC 9449 binds tokens to a DPoP key and proves possession on each request.

## Metadata

- RFC 8414 describes authorization-server capabilities.
- RFC 9728 describes protected-resource metadata.

## A2A and MCP

A2A identity is established at the HTTP layer and security requirements are declared in Agent Card security metadata. MCP protected resources use OAuth protected-resource metadata to locate authorization servers.

## Explicit exclusions

- No centralized catalog of provider business capabilities or permission scopes.
- No identity claims embedded in A2A JSON-RPC payloads.
- No custom bearer-token format.
- No private keys submitted during registration.
