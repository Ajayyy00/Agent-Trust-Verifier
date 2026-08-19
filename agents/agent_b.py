"""Agent B: receives instructions, verifies via the API, executes if accepted.

The critical ordering enforced here:
  1. POST the instruction to the verifier API.
  2. If rejected → return the rejection immediately. Execute nothing.
  3. If accepted → optionally narrate, then call execute_action().

A rejected instruction NEVER reaches the LLM reasoning or business-action layer.
This is the architectural boundary the entire project is designed to enforce.
"""

import logging

import httpx

from identity.instruction import Instruction

from agents import business_actions
from agents import llm_client

logger = logging.getLogger(__name__)

_NARRATION_SYSTEM_PROMPT = """You are Agent B, a financial execution agent.
An instruction has been verified and you are about to execute it.
Produce a single short sentence (under 20 words) confirming what you are about to do.
Be specific about the action and key params. No preamble."""


def _instruction_to_payload(instruction: Instruction) -> dict:
    """Serialize an Instruction to the dict expected by POST /instruction/verify."""
    token = instruction.delegation_token
    return {
        "instruction_id": instruction.instruction_id,
        "instruction_nonce": instruction.instruction_nonce,
        "issued_at": instruction.issued_at,
        "issuer": instruction.issuer,
        "target_agent_id": instruction.target_agent_id,
        "action": instruction.action,
        "signer_pubkey_id": instruction.signer_pubkey_id,
        "signature": instruction.signature,
        "params": instruction.params,
        "delegation_token": {
            "token_id": token.token_id,
            "subject_agent_id": token.subject_agent_id,
            "max_scope": token.max_scope,
            "delegation_depth": token.delegation_depth,
            "max_delegation_depth": token.max_delegation_depth,
            "expiry": token.expiry,
            "issuer_key_id": token.issuer_key_id,
            "issuer_signature": token.issuer_signature,
        },
    }


def receive_instruction(
    instruction: Instruction,
    api_base_url: str,
    *,
    narrate: bool = False,
) -> dict:
    """Receive, verify via the API, and (if accepted) execute an instruction.

    Args:
        instruction: The signed Instruction from Agent A.
        api_base_url: Base URL of the running verifier API, e.g. 'http://127.0.0.1:8000'.
        narrate: If True and the instruction is accepted, call the LLM to produce
                 a short confirmation sentence (for demo narration). Default False
                 so CI tests never trigger real LLM calls.

    Returns:
        {
            "verification": <dict from the API>,
            "narration": <str | None>,
            "execution_result": <str | None>,  # None if rejected
        }
    """
    payload = _instruction_to_payload(instruction)

    try:
        response = httpx.post(
            f"{api_base_url}/instruction/verify",
            json=payload,
            timeout=10.0,
        )
        response.raise_for_status()
        verification = response.json()
    except httpx.HTTPError as exc:
        logger.error("Verifier API request failed: %s", exc)
        raise

    # --- REJECT FAST — before any reasoning or execution ---
    if not verification.get("accepted"):
        logger.info(
            "Instruction %s rejected: %s",
            instruction.instruction_id,
            verification.get("reason_code"),
        )
        return {
            "verification": verification,
            "narration": None,
            "execution_result": None,
        }

    # --- ACCEPTED — optionally narrate, then execute ---
    narration: str | None = None
    if narrate:
        try:
            narration = llm_client.ask_agent(
                _NARRATION_SYSTEM_PROMPT,
                f"Action: {instruction.action}, Params: {instruction.params}",
            )
        except Exception as exc:
            # Narration is cosmetic — don't let an LLM hiccup block execution
            logger.warning("Narration call failed (non-fatal): %s", exc)
            narration = None

    execution_result = business_actions.execute_action(
        instruction.action, instruction.params
    )

    return {
        "verification": verification,
        "narration": narration,
        "execution_result": execution_result,
    }
