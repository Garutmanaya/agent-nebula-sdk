.PHONY: sync test coverage format format-check lint typecheck compile verify package

sync:
	uv sync --group dev

test:
	uv run pytest

coverage:
	uv run pytest --cov=agent_nebula_sdk --cov-report=term-missing --cov-fail-under=90

format:
	uv run ruff format src tests

format-check:
	uv run ruff format --check src tests

lint:
	uv run ruff check src tests

typecheck:
	uv run mypy src

compile:
	uv run python -m compileall -q src tests

verify: format-check lint typecheck coverage compile

package: verify
	uv build
