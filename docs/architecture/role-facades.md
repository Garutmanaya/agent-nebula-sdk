# Role Facades

The client facade builds registration requests, client assertions, resource-token requests, and DPoP-protected calls. The authorization-server facade validates registration, authenticates clients, resolves resources, validates DPoP, and issues tokens. The resource-server facade validates access tokens, audience, DPoP proofs, and produces a trusted security context.

Facades remain thin orchestration layers. Protocol rules stay inside RFC modules; product business policy stays outside the SDK.
