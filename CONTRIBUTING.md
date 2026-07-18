# Contributing

## Mandatory coding standards

- Python 3.12 or later.
- Object-oriented design with focused classes and explicit composition.
- One statement per line; no compressed functions.
- Public classes, methods, functions, and models require docstrings.
- Security-sensitive docstrings must identify the applicable standard and section.
- No generic `Exception`, untyped dictionary contracts, silent fallback, or algorithm auto-selection.
- No function longer than 50 lines without an approved ADR.
- No module may import another module's internal package.
- Every new external call requires success, timeout, TLS, malformed-response, 4xx, and 5xx tests.

## Required verification

```bash
uv run ruff format --check src tests
uv run ruff check src tests
uv run mypy --strict src
uv run pytest --cov=agent_nebula_sdk --cov-fail-under=90
python -m compileall src tests
```

Security-critical modules require 100% branch coverage.
