# Replay Store Guide

Replay consumption must be atomic: the first valid proof or assertion identifier succeeds and all concurrent repeats fail. Redis is recommended for high-volume distributed DPoP replay state; PostgreSQL can be used where throughput permits. TTL must cover the accepted proof lifetime plus clock skew. In-memory stores are suitable only for single-process tests and development.
