"""Construct and execute red-team attacks against the verification API."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from identity.delegation_token import DelegationToken
from identity.instruction import Instruction, sign_instruction
from identity.keygen import KeyPair, generate_keypair, serialize_public_key
from verifier.result import (
    ACCEPTED,
    AGENT_REVOKED,
    INVALID_SIGNATURE,
    REPLAY_DETECTED,
    TOKEN_EXPIRED,
    TOKEN_SCOPE_DENIED,
    WRONG_AUDIENCE,
)

DEFAULT_ACTION = "finance:report:generate"
SCOPE_ESCAPE_ACTION = "finance:report:delete"


@dataclass
class AttackContext:
    """A bootstrap-provisioned identity used to construct valid instructions."""

    client: Any
    subject_agent_id: str
    keypair: KeyPair
    delegation_token: DelegationToken
    key_version: str
    target_agent_id: str

    def new_instruction(self, action: str = DEFAULT_ACTION) -> Instruction:
        """Build a fresh, correctly signed instruction using the provisioned identity."""
        unsigned = Instruction(
            instruction_id=f"redteam-{uuid.uuid4().hex}",
            instruction_nonce=uuid.uuid4().hex,
            issued_at=int(time.time()),
            issuer=self.subject_agent_id,
            target_agent_id=self.target_agent_id,
            action=action,
            signer_pubkey_id=self.key_version,
            signature=None,
            delegation_token=self.delegation_token,
            params={"account_id": "redteam-account"},
        )
        return sign_instruction(unsigned, self.keypair.private_key)


def create_attack_context(
    client: Any, target_agent_id: str = "agent-api"
) -> AttackContext:
    """Provision an ephemeral red-team identity through the gated test endpoint."""
    keypair = generate_keypair()
    subject_agent_id = f"redteam-{uuid.uuid4().hex}"
    response = client.post(
        "/test/bootstrap",
        json={
            "public_key": serialize_public_key(keypair.public_key),
            "subject_agent_id": subject_agent_id,
        },
    )
    if response.status_code != 200:
        raise RuntimeError(
            "Unable to bootstrap red-team identity: "
            f"HTTP {response.status_code} {response.text}"
        )
    payload = response.json()
    return AttackContext(
        client=client,
        subject_agent_id=subject_agent_id,
        keypair=keypair,
        delegation_token=DelegationToken(**payload["delegation_token"]),
        key_version=payload["key_version"],
        target_agent_id=target_agent_id,
    )


def _instruction_payload(instruction: Instruction) -> dict[str, Any]:
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


def _post_instruction(context: AttackContext, instruction: Instruction) -> Any:
    return context.client.post(
        "/instruction/verify", json=_instruction_payload(instruction)
    )


def _response_body(response: Any) -> dict[str, Any]:
    try:
        return response.json()
    except ValueError:
        return {"raw_body": response.text}


def _result(name: str, expected_reason: str, response: Any) -> dict[str, Any]:
    body = _response_body(response)
    actual_reason = body.get("reason_code")
    return {
        "name": name,
        "expected_reason": expected_reason,
        "actual_reason": actual_reason,
        "passed": response.status_code == 200 and actual_reason == expected_reason,
        "http_response": body,
    }


def attack_unsigned_instruction(context: AttackContext) -> dict[str, Any]:
    instruction = context.new_instruction()
    instruction.signature = None
    return _result(
        "unsigned instruction",
        INVALID_SIGNATURE,
        _post_instruction(context, instruction),
    )


def attack_forged_signature(context: AttackContext) -> dict[str, Any]:
    instruction = sign_instruction(
        context.new_instruction(), generate_keypair().private_key
    )
    return _result(
        "forged signature", INVALID_SIGNATURE, _post_instruction(context, instruction)
    )


def attack_tampered_action(context: AttackContext) -> dict[str, Any]:
    instruction = context.new_instruction()
    instruction.action = SCOPE_ESCAPE_ACTION
    return _result(
        "tampered action", INVALID_SIGNATURE, _post_instruction(context, instruction)
    )


def attack_wrong_destination(context: AttackContext) -> dict[str, Any]:
    """Change the audience after signing; audience is checked before signature validity."""
    instruction = context.new_instruction()
    instruction.target_agent_id = "redteam-wrong-destination"
    return _result(
        "wrong destination", WRONG_AUDIENCE, _post_instruction(context, instruction)
    )


def attack_scope_escalation(context: AttackContext) -> dict[str, Any]:
    instruction = context.new_instruction(SCOPE_ESCAPE_ACTION)
    return _result(
        "scope escalation", TOKEN_SCOPE_DENIED, _post_instruction(context, instruction)
    )


def attack_expired_token(context: AttackContext) -> dict[str, Any]:
    instruction = context.new_instruction()
    instruction.delegation_token.expiry = int(time.time()) - 1
    return _result(
        "expired token", TOKEN_EXPIRED, _post_instruction(context, instruction)
    )


def attack_replay(context: AttackContext) -> dict[str, Any]:
    instruction = context.new_instruction()
    first_response = _post_instruction(context, instruction)
    second_response = _post_instruction(context, instruction)
    first_body = _response_body(first_response)
    second_body = _response_body(second_response)
    expected_reason = f"{ACCEPTED} -> {REPLAY_DETECTED}"
    actual_reason = (
        f"{first_body.get('reason_code')} -> {second_body.get('reason_code')}"
    )
    return {
        "name": "replay",
        "expected_reason": expected_reason,
        "actual_reason": actual_reason,
        "passed": (
            first_response.status_code == 200
            and second_response.status_code == 200
            and first_body.get("reason_code") == ACCEPTED
            and second_body.get("reason_code") == REPLAY_DETECTED
        ),
        "http_response": {"first": first_body, "second": second_body},
    }


def attack_revoked_agent(context: AttackContext) -> dict[str, Any]:
    revoke_response = context.client.post(
        f"/agents/{context.subject_agent_id}/revoke",
        json={"reason": "red-team revocation test"},
    )
    instruction_response = _post_instruction(context, context.new_instruction())
    result = _result("revoked agent", AGENT_REVOKED, instruction_response)
    result["passed"] = result["passed"] and revoke_response.status_code == 200
    result["http_response"] = {
        "revoke": _response_body(revoke_response),
        "verify": result["http_response"],
    }
    return result


ATTACKS: list[Callable[[AttackContext], dict[str, Any]]] = [
    attack_unsigned_instruction,
    attack_forged_signature,
    attack_tampered_action,
    attack_wrong_destination,
    attack_scope_escalation,
    attack_expired_token,
    attack_replay,
    attack_revoked_agent,
]


def run_all_attacks(
    client: Any, target_agent_id: str = "agent-api"
) -> list[dict[str, Any]]:
    """Run all scenarios using a fresh provisioned identity for each attack."""
    return [
        attack(create_attack_context(client, target_agent_id)) for attack in ATTACKS
    ]
