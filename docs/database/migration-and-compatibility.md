# Migration and Compatibility

Agent Nebula owns migrations. The SDK publishes storage-contract versions.

```text
SDK protocol version
SDK storage-contract version
Agent Nebula schema version
```

Startup must verify compatible versions before exposing token or registration endpoints. New optional protocols add new tables/adapters; they must not overload current columns with unrelated meanings.
