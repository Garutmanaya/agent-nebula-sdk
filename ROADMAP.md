# Roadmap

## Step 1 — Architecture baseline

Freeze boundaries, contracts, schema blueprint, plugin model, diagrams, testing strategy, and standards matrix. No protocol implementation.

## Step 2 — Core cryptographic and metadata foundation

Implement RFC 7517, RFC 7638, algorithm policy, key lifecycle, HTTP transport contracts, RFC 8414, and RFC 9728.

## Step 3 — Registry authentication and onboarding

Implement RFC 7523 and RFC 7591, including open and controlled registration profiles.

## Step 4 — Provider-targeted token profile

Implement RFC 8707 and RFC 9068.

## Step 5 — Sender-constrained requests

Implement RFC 9449 DPoP, nonce support, replay protection, and resource-server middleware.

## Step 6 — Protocol adapters

Implement A2A and MCP adapters without embedding identity in protocol payloads.

## Step 7 — SDK-only conformance system

Run Client → Authorization Server → Resource Server end to end without Agent Nebula or Agent Genesis.

## Product integration

1. Update Agent Nebula with PostgreSQL/Redis adapters.
2. Update Agent Genesis Host with client role.
3. Update Agent Genesis providers with client and resource-server roles.


## Completed: Step 3 — RFC 7523

- private_key_jwt client authentication
- JWT bearer authorization grants
- assertion replay prevention and strict validation policy
