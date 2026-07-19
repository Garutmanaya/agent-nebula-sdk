# Plugin and Extension Architecture

Extensions are supplied through explicit interfaces and configuration-selected implementations.

Examples include registration policy, key resolver, replay store, resource registry, software-statement verifier, nonce service, trust-claim provider, and HTTP transport.

A new protocol must not be activated by an empty placeholder. Unsupported future modules should fail explicitly until their conformance suite is complete.
