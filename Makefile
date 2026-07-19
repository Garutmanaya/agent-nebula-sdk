.PHONY: sync test coverage acceptance format format-check lint typecheck quality compile verify package

sync:
	uv sync --group dev

test:
	uv run pytest

coverage:
	uv run pytest --cov=agent_nebula_sdk --cov-report=term-missing --cov-fail-under=90

acceptance:
	uv run python scripts/run_phase1_acceptance.py

format:
	uv run ruff format src tests scripts

format-check:
	uv run ruff format --check src tests scripts

lint:
	uv run ruff check src tests scripts

typecheck:
	uv run mypy src

quality:
	uv run python scripts/quality_audit.py

compile:
	uv run python -m compileall -q src tests scripts

verify: format-check lint typecheck quality coverage compile acceptance

package: verify
	uv build
