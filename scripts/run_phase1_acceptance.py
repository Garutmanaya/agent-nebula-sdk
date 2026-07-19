"""Run the SDK-only Phase 1 acceptance scenario from the command line."""

from __future__ import annotations

import json

from agent_nebula_sdk.conformance import Phase1AcceptanceHarness


def main() -> None:
    """Execute the complete flow and print its typed result as JSON."""
    result = Phase1AcceptanceHarness().run()
    print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
