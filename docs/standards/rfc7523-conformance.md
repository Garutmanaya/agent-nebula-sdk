# RFC 7523 Conformance Matrix

| Requirement | Status | Source |
|---|---|---|
| JWT bearer authorization grant parameter profile | Implemented | `models.py`, `builder.py`, `grant.py` |
| JWT client-authentication parameter profile | Implemented | `models.py`, `builder.py`, `authenticator.py` |
| `iss`, `sub`, `aud`, `exp` processing | Implemented | `validator.py` |
| Signed JWT requirement | Implemented | `builder.py`, `validator.py` |
| Audience identifies authorization server/token endpoint | Implemented | `validator.py` |
| Replay protection through `jti` | Required by SDK profile | `ports.py`, `adapters.py` |
| Short assertion lifetime | Required by SDK profile | `policy.py`, `validator.py` |
| `iat` requirement | Required by SDK profile | `policy.py`, `validator.py` |
| Authorization-server mapping of grant subject | Product policy | Not owned by SDK |
| OAuth token issuance after successful assertion | Step 7 / product composition | Not part of RFC 7523 module |

The SDK profile is intentionally stricter than the minimum RFC claim set because
open machine registration requires bounded lifetime and replay prevention.
