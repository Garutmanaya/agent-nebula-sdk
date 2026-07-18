# RFC 8707 Conformance Matrix

| Requirement | Status | Implementation |
|---|---|---|
| `resource` accepted at authorization and token requests | Implemented as reusable codec/model | `ResourceParameterCodec` |
| Resource value is an absolute URI | Implemented | `ResourceIndicatorValidator` |
| Fragment component prohibited | Implemented | `ResourceIndicatorValidator` |
| Query component discouraged but optionally accepted | Implemented through policy | `ResourceIndicatorPolicy.allow_query` |
| Multiple resource values supported by the RFC | Implemented | tuple model and repeated form codec |
| Authorization server may reject multiple resources | Implemented | `maximum_resources` policy |
| `invalid_target` extension error | Implemented | stable SDK protocol error code |
| Missing resource may use default or be rejected | Implemented as policy choice | `require_resource` |
| Resource may map to another audience identifier | Implemented | `ResourceRegistration.audience` |
| Token audience restriction | Audience selection and resource-server validation implemented; signing follows in RFC 9068 | `resolve_single_audience`, `ResourceAudienceValidator` |
| Authorization-code / refresh-token request limited to original grant or subset | Implemented | `PriorGrantResourcePolicy` |
| JWT authorization request string/array representation | Implemented | `decode_jwt_claim` |
| Privacy-aware downscoping by resource | Extension point; scope policy is product-owned | Deferred |

## Agent Nebula profile

The RFC permits multiple target resources, but Section 3 encourages using a
single resource because a multi-audience bearer token requires strong trust
between all recipients. Phase 1 therefore requires exactly one HTTPS resource.
