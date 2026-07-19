# Contributing

## Core rule

New functionality must be modular and additive. A new standard should normally add a package, public models, ports, adapters, documentation, and tests rather than modify unrelated protocol modules.

## Required quality gate

```bash
uv run ruff format --check src tests scripts
uv run ruff check src tests scripts
uv run mypy --strict src
uv run pytest
python -m compileall -q src tests scripts
```

## Required documentation

Every new package requires a `README.md`. Every public class, method, and function requires a meaningful docstring. Security-sensitive decisions require the relevant RFC section and a concise explanation of the validation rule.

## Architecture changes

Changes to dependency direction, public facade ownership, persistence boundaries, or protocol responsibility require an Architecture Decision Record under `docs/decisions/`.

See `docs/developer/` for detailed contribution guidance.
