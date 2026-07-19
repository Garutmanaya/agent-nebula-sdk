# Conformance package

## Purpose

This package proves that the independently implemented Phase 1 modules compose
into one complete Host → authorization server → provider flow without importing
Agent Nebula or Agent Genesis product code.

## Standards covered

- RFC 7517 and RFC 7638 for public keys and thumbprints
- RFC 7523 for `private_key_jwt`
- RFC 7591 for open dynamic registration
- RFC 8707 for protected-resource targeting
- RFC 9068 for JWT access tokens
- RFC 9449 for DPoP sender constraint and replay detection
- A2A HTTP security integration

## Boundary

The harness uses reference in-memory adapters. Production persistence, HTTP
routes, key custody, trust scoring, and provider business policy remain product
responsibilities.
