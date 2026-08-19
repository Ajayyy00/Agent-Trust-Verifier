"""CLI entrypoint for live red-team verification against an API deployment."""

from __future__ import annotations

import argparse

import httpx

from .attacks import run_all_attacks

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Agent Trust Verifier red-team attacks")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--target-agent-id", default="agent-api")
    args = parser.parse_args()

    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=10.0) as client:
        results = run_all_attacks(client, args.target_agent_id)

    print(f"{'Attack name':<24} {'Expected':<32} {'Actual':<32} Result")
    print("-" * 100)
    for result in results:
        status = f"{GREEN}PASS{RESET}" if result["passed"] else f"{RED}FAIL{RESET}"
        print(
            f"{result['name']:<24} {result['expected_reason']:<32} "
            f"{result['actual_reason']:<32} {status}"
        )

    caught = sum(result["passed"] for result in results)
    print(f"\n{caught}/{len(results)} attacks correctly caught.")
    return 0 if caught == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
