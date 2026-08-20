"""End-to-end demo: Agent A proposes, Agent B verifies and executes via the live API.

Prerequisites:
  1. Start an API with ALLOW_TEST_BOOTSTRAP=1 for this demo.
  2. Set GEMINI_API_KEY in the environment.
  3. Run: python scripts/demo_valid_flow.py --base-url <API base URL>

This script is NOT part of the automated test suite — it makes real Gemini API
calls and requires a running local uvicorn instance. It is for manual demo use only.
"""

import argparse
import os
import sys

# Ensure the project root is on sys.path when running as a script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

from agents.agent_a import AgentA
from agents.agent_b import receive_instruction
from identity.delegation_token import DelegationToken
from identity.keygen import generate_keypair, serialize_public_key

ACTION = "finance:report:generate"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the live Agent A/Agent B demo")
    parser.add_argument(
        "--base-url", default=os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    )
    args = parser.parse_args()
    api_base = args.base_url.rstrip("/")
    print("\n" + "=" * 60)
    print("  Agent Trust Verifier — Phase 8 End-to-End Demo")
    print("=" * 60 + "\n")

    if not os.environ.get("GEMINI_API_KEY"):
        print("ERROR: GEMINI_API_KEY is not set. Exiting.")
        sys.exit(1)

    # --- Setup: provision Agent A against this API's root authority ---
    print("[Setup] Generating Agent A's keypair...")
    agent_a_keypair = generate_keypair()
    print("[Setup] Registering Agent A and requesting a root-signed token...")
    bootstrap = httpx.post(
        f"{api_base}/test/bootstrap",
        json={
            "public_key": serialize_public_key(agent_a_keypair.public_key),
            "subject_agent_id": "agent-a",
        },
        timeout=10.0,
    )
    if bootstrap.status_code != 200:
        print(f"[Setup] Bootstrap failed: {bootstrap.status_code} {bootstrap.text}")
        sys.exit(1)
    credentials = bootstrap.json()
    token = DelegationToken(**credentials["delegation_token"])

    # Construct Agent A
    agent_a = AgentA(
        keypair=agent_a_keypair,
        pubkey_id=credentials["key_version"],
        delegation_token=token,
        target_agent_id="agent-api",  # Must match VERIFIER_AGENT_ID in api/main.py
    )

    # --- Demo: Agent A proposes an instruction via LLM ---
    task = "Generate the Q3 2024 financial report for account ACC-001"
    print(f"\n[Agent A] Task: {task!r}")
    print("[Agent A] Asking Gemini to pick an action...")

    try:
        instruction = agent_a.propose_instruction(task)
    except Exception as exc:
        print(f"[Agent A] ERROR proposing instruction: {exc}")
        sys.exit(1)

    print(f"[Agent A] LLM chose action: {instruction.action!r}")
    print(f"[Agent A] LLM chose params: {instruction.params}")
    print(f"[Agent A] Signed instruction ID: {instruction.instruction_id}")

    # --- Demo: Agent B verifies via the API and executes ---
    print(f"\n[Agent B] Sending to verifier API at {api_base}/instruction/verify ...")
    print("[Agent B] Narration enabled (will call Gemini for a confirmation line).")

    try:
        result = receive_instruction(instruction, api_base, narrate=True)
    except Exception as exc:
        print(f"[Agent B] ERROR: {exc}")
        sys.exit(1)

    verification = result["verification"]
    print(f"\n[Verifier] accepted:      {verification['accepted']}")
    print(f"[Verifier] reason_code:   {verification['reason_code']}")
    print(f"[Verifier] reputation:    {verification['reputation_score']}")
    print(f"[Verifier] risk_level:    {verification['risk_level']}")

    if verification["accepted"]:
        print(f"\n[Agent B] Narration: {result['narration']}")
        print(f"[Agent B] Execution: {result['execution_result']}")
    else:
        print("\n[Agent B] Rejected — no execution occurred.")
        print(f"[Agent B] execution_result: {result['execution_result']}")

    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    main()
