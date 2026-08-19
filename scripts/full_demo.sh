#!/usr/bin/env bash
# Live-only Phase 13 judge demo. This is intentionally not part of pytest.
# It uses the deployment's gated /test/bootstrap route to create disposable
# demo identities, then prints the required verification sequence.

set -euo pipefail

BASE_URL="https://sih25orneb.execute-api.eu-north-1.amazonaws.com"
if [[ "${1:-}" == "--base-url" ]]; then
  BASE_URL="${2:?--base-url requires a URL}"
  shift 2
fi
if [[ $# -ne 0 ]]; then
  echo "Usage: bash scripts/full_demo.sh [--base-url URL]" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python}"
"$PYTHON_BIN" - "$BASE_URL" <<'PY'
"""Print the ordered, live verification demo without duplicating attack logic."""

from __future__ import annotations

import sys

import httpx

from redteam.attacks import (
    _instruction_payload,
    attack_replay,
    attack_revoked_agent,
    attack_scope_escalation,
    attack_tampered_action,
    attack_wrong_destination,
    create_attack_context,
)
from verifier.result import ACCEPTED

base_url = sys.argv[1].rstrip("/")


def print_result(label: str, result: dict) -> None:
    outcome = "PASS" if result["passed"] else "FAIL"
    print(f"\n[{label}] {outcome}")
    print(f"Expected: {result['expected_reason']}")
    print(f"Actual:   {result['actual_reason']}")
    if not result["passed"]:
        raise SystemExit(f"{label} did not produce the expected verifier result")


with httpx.Client(base_url=base_url, timeout=30.0) as client:
    health = client.get("/health")
    health.raise_for_status()
    print("============================================================")
    print("Agent Trust Verifier - Live Security Demo")
    print("============================================================")
    print(f"API:    {base_url}")
    print(f"Health: {health.json().get('status', 'unknown')}")

    context = create_attack_context(client)
    valid = client.post(
        "/instruction/verify", json=_instruction_payload(context.new_instruction())
    )
    valid.raise_for_status()
    valid_body = valid.json()
    valid_result = {
        "expected_reason": ACCEPTED,
        "actual_reason": valid_body.get("reason_code"),
        "passed": (
            valid_body.get("accepted") is True
            and valid_body.get("reason_code") == ACCEPTED
        ),
    }
    print_result("1. Valid instruction accepted", valid_result)

    print_result(
        "2. MITM tamper rejected", attack_tampered_action(create_attack_context(client))
    )
    print_result(
        "3. Wrong destination rejected",
        attack_wrong_destination(create_attack_context(client)),
    )
    print_result(
        "4. Scope escalation rejected",
        attack_scope_escalation(create_attack_context(client)),
    )
    print_result("5. Replay rejected", attack_replay(create_attack_context(client)))
    print_result(
        "6. Revoked agent rejected", attack_revoked_agent(create_attack_context(client))
    )

print("\n============================================================")
print("Demo complete: every required verifier decision matched.")
print("============================================================")
PY
