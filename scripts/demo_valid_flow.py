"""End-to-end demo: Agent A proposes, Agent B verifies and executes via the live API.

Prerequisites:
  1. Start the local API server:     uvicorn api.main:app
  2. Set your Gemini key:            set GEMINI_API_KEY=your-key-here  (Windows)
                                     export GEMINI_API_KEY=your-key-here (Linux/Mac)
  3. Run this script:                python scripts/demo_valid_flow.py

This script is NOT part of the automated test suite — it makes real Gemini API
calls and requires a running local uvicorn instance. It is for manual demo use only.
"""

import os
import sys
import time

# Ensure the project root is on sys.path when running as a script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authority.delegation_issuer import DelegationIssuer
from identity.key_registry import KeyRegistry
from identity.keygen import generate_keypair, serialize_public_key

from agents.agent_a import AgentA
from agents.agent_b import receive_instruction

API_BASE = "http://127.0.0.1:8000"
ACTION = "finance:report:generate"


def main() -> None:
    print("\n" + "=" * 60)
    print("  Agent Trust Verifier — Phase 8 End-to-End Demo")
    print("=" * 60 + "\n")

    if not os.environ.get("GEMINI_API_KEY"):
        print("ERROR: GEMINI_API_KEY is not set. Exiting.")
        sys.exit(1)

    # --- Setup: generate keys and a delegation token ---
    print("[Setup] Generating root keypair and Agent A's keypair...")
    root_keypair = generate_keypair()
    agent_a_keypair = generate_keypair()

    # Register Agent A's key with the in-process registry so the API's verifier
    # can look it up. In a real deployment this would be an out-of-band provisioning step.
    print("[Setup] Registering Agent A's public key with the verifier API...")
    try:
        import httpx
        reg_response = httpx.post(
            f"{API_BASE}/agents/agent-a/register",  # Phase 9 may add this endpoint
            json={
                "public_key": serialize_public_key(agent_a_keypair.public_key),
                "key_version": "agent-a-v1",
            },
            timeout=5.0,
        )
        print(f"[Setup] Registration response: {reg_response.status_code}")
    except Exception as exc:
        print(f"[Setup] Key registration not available yet ({exc}) — using in-memory setup.")

    # Directly register for the demo (mirrors what the API's lifespan startup does)
    registry = KeyRegistry()
    registry.register(
        "agent-a",
        serialize_public_key(agent_a_keypair.public_key),
        "agent-a-v1",
    )

    # Issue a delegation token from root to Agent A
    print("[Setup] Issuing delegation token from root to Agent A...")
    issuer = DelegationIssuer(root_keypair.private_key, "root-v1")
    token = issuer.issue_token(
        subject_agent_id="agent-a",
        allowed_scope=[ACTION, "finance:payment:refund"],
        expiry_seconds=300,
    )

    # Construct Agent A
    agent_a = AgentA(
        keypair=agent_a_keypair,
        pubkey_id="agent-a-v1",
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
    print(f"\n[Agent B] Sending to verifier API at {API_BASE}/instruction/verify ...")
    print("[Agent B] Narration enabled (will call Gemini for a confirmation line).")

    try:
        result = receive_instruction(instruction, API_BASE, narrate=True)
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
        print(f"\n[Agent B] Rejected — no execution occurred.")
        print(f"[Agent B] execution_result: {result['execution_result']}")

    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    main()
