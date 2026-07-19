# PostgreSQL Adapter Guide

Use one repository per storage port with exact query-specific parameters and schema-backed types. Transactions should cover logically atomic operations such as registration plus key insertion, resource activation plus aliases, or replay consumption. Constraints should enforce identifiers, key uniqueness, lifecycle state, and ownership.

The SDK must not contain SQL or migrations. Agent Nebula owns PostgreSQL schema and migration files.
