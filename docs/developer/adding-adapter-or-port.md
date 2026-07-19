# Adding an Adapter or Port

Ports describe required behavior without product dependencies. Adapters implement a port for memory, PostgreSQL, Redis, HTTP, KMS, or another infrastructure. Keep data conversion at the adapter boundary, avoid generic dictionaries, document concurrency guarantees, and test all external failure modes.
