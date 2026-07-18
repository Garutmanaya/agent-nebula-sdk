# Trust and Local Policy

Agent Nebula signs high-level, registry-governed identity and trust claims. It does not maintain provider-specific business permissions.

Provider authorization remains local:

```text
validated client identity
+ exact provider audience
+ sender proof
+ signed trust attributes
+ provider-owned request context
→ local policy decision
```

The SDK defines `LocalPolicyDecisionPoint` as a port but does not implement parking-, travel-, BI-, or medical-specific policy.
