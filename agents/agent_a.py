"""Agent A: issues signed instructions via LLM reasoning.

Agent A uses the LLM ONLY to decide which action and parameters to request,
based on its delegated scope and a natural-language task description.
All cryptographic operations (signing, nonce generation, envelope construction)
are performed by deterministic wrapper code — the LLM never touches them.
"""

import json
import secrets
import time
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity.delegation_token import DelegationToken
from identity.instruction import Instruction, sign_instruction
from identity.keygen import KeyPair

from agents import llm_client

# Actions Agent A is allowed to request — this mirrors the delegation token's
# max_scope and is used to constrain the LLM's output to valid choices.
AVAILABLE_ACTIONS = list({
    "finance:report:generate",
    "finance:payment:refund",
})

_SYSTEM_PROMPT = """You are Agent A, a financial automation agent.
Your job is to decide which action to request based on a user task.

You may ONLY request actions from this list:
{actions}

Respond with ONLY a JSON object in this exact format (no markdown, no explanation):
{{"action": "<action_string>", "params": {{"<key>": "<value>"}}}}

Example for a report request:
{{"action": "finance:report:generate", "params": {{"period": "Q3-2024", "account_id": "ACC-001"}}}}

Example for a refund request:
{{"action": "finance:payment:refund", "params": {{"amount": "150.00", "account_id": "ACC-001"}}}}

If the task doesn't match any available action, return:
{{"action": "finance:report:generate", "params": {{"period": "unknown", "account_id": "unknown"}}}}
"""


class InstructionParseError(ValueError):
    """Raised when the LLM response cannot be parsed into a valid action/params pair."""


@dataclass
class AgentA:
    """An agent that issues signed instructions based on LLM reasoning.

    Args:
        keypair: Agent A's own Ed25519 keypair used to sign instructions.
        pubkey_id: Registered key version identifier (e.g. "agent-a-v1").
        delegation_token: A DelegationToken already issued to this agent by the
            root authority. In a real deployment this comes from an out-of-band
            setup step, not from Agent A itself.
        target_agent_id: The agent_id of the intended recipient (Agent B / verifier).
    """

    keypair: KeyPair
    pubkey_id: str
    delegation_token: DelegationToken
    target_agent_id: str

    def propose_instruction(self, task_description: str) -> Instruction:
        """Use the LLM to pick an action, then deterministically build and sign the instruction.

        The LLM is asked only to select an action + params. All envelope
        construction and signing are performed by deterministic wrapper code.

        Args:
            task_description: A natural-language description of the task to perform.

        Returns:
            A fully signed Instruction ready to be sent to Agent B.

        Raises:
            InstructionParseError: If the LLM response cannot be parsed.
            RuntimeError: If the LLM call fails after retries.
        """
        system_prompt = _SYSTEM_PROMPT.format(
            actions="\n".join(f"  - {a}" for a in AVAILABLE_ACTIONS)
        )
        raw_response = llm_client.ask_agent(system_prompt, task_description)

        # --- Defensive JSON parsing — the LLM may not always return clean JSON ---
        action, params = self._parse_llm_response(raw_response)

        # --- Deterministic envelope construction — LLM never touches this part ---
        instruction = Instruction(
            instruction_id=str(uuid.uuid4()),
            instruction_nonce=secrets.token_hex(16),
            issued_at=int(time.time()),
            issuer=self.delegation_token.subject_agent_id,
            target_agent_id=self.target_agent_id,
            action=action,
            signer_pubkey_id=self.pubkey_id,
            signature=None,
            delegation_token=self.delegation_token,
            params=params,
        )
        return sign_instruction(instruction, self.keypair.private_key)

    @staticmethod
    def _parse_llm_response(raw: str) -> tuple[str, dict]:
        """Defensively extract action and params from the LLM's text output.

        Handles common cases: clean JSON, JSON embedded in markdown fences,
        leading/trailing whitespace.
        """
        text = raw.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.splitlines()
            # Drop first line (``` or ```json) and last line (```)
            text = "\n".join(lines[1:-1]).strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try extracting the first {...} block from the text
            start = text.find("{")
            end = text.rfind("}") + 1
            if start == -1 or end == 0:
                raise InstructionParseError(
                    f"Could not find JSON object in LLM response: {raw!r}"
                )
            try:
                data = json.loads(text[start:end])
            except json.JSONDecodeError as exc:
                raise InstructionParseError(
                    f"Failed to parse JSON from LLM response: {raw!r}"
                ) from exc

        action = data.get("action")
        params = data.get("params", {})

        if not isinstance(action, str) or not action:
            raise InstructionParseError(
                f"LLM response missing 'action' field: {data}"
            )
        if not isinstance(params, dict):
            params = {}

        return action, params
