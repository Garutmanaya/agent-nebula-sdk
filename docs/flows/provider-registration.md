# Provider Registration

Provider onboarding and Agent Card publication are separate operations.

```text
RFC 7591 registration
→ creates provider machine identity and public-key relationship

RFC 7523 authentication
→ proves possession of provider private key

Authenticated Agent Card registration
→ publishes provider-owned discovery metadata
```

A restart reuses persisted keys and registration state. A new key is introduced only through deliberate rotation with an overlap period.
