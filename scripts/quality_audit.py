"""Enforce source-quality invariants that formatters and linters do not cover.

The audit is intentionally small and deterministic so it can run in every
local verification and CI job. It checks the maintainability requirements for
this security SDK: every Python module, class, function, and method must carry
an explanatory docstring, and compressed semicolon-based statements are not
allowed.
"""

from __future__ import annotations

import ast
from pathlib import Path

SOURCE_ROOTS = (Path("src"), Path("tests"))
IGNORED_METHODS = frozenset({"__init__"})


def iter_python_files() -> list[Path]:
    """Return all Python files covered by the SDK quality policy."""
    return sorted(
        path for root in SOURCE_ROOTS for path in root.rglob("*.py") if ".venv" not in path.parts
    )


def collect_docstring_failures(path: Path) -> list[str]:
    """Return missing module, class, function, and method docstrings."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    failures: list[str] = []

    if ast.get_docstring(tree) is None:
        failures.append(f"{path}: missing module docstring")

    for node in ast.walk(tree):
        if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name in IGNORED_METHODS:
            continue
        if ast.get_docstring(node) is None:
            failures.append(f"{path}:{node.lineno}: {node.name} is missing a docstring")

    return failures


def collect_compressed_statement_failures(path: Path) -> list[str]:
    """Reject semicolon-separated Python statements outside string literals."""
    failures: list[str] = []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    lines: dict[int, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt):
            lines[node.lineno] = lines.get(node.lineno, 0) + 1

    for line_number, statement_count in sorted(lines.items()):
        if statement_count > 1:
            failures.append(f"{path}:{line_number}: multiple statements share one line")

    return failures


def main() -> int:
    """Run all quality audits and return a process-compatible status code."""
    failures: list[str] = []

    for path in iter_python_files():
        failures.extend(collect_docstring_failures(path))
        failures.extend(collect_compressed_statement_failures(path))

    if failures:
        print("Source-quality audit failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Source-quality audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
