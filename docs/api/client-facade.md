# Client Facade

The client facade composes registration, RFC 7523 assertion creation, RFC 8707 resource requests, and RFC 9449 proof construction. It requires product-provided private keys, identifiers, clocks, nonce handling, and HTTP transport. It does not persist credentials or decide provider authorization.


## MCP client identification

The OAuth client facade remains responsible for token and DPoP artifacts. Current MCP Client ID Metadata Document resolution is supplied separately through the `mcp.client_id_metadata` runtime plugin and does not invoke RFC 7591.
