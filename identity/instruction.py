"""Instruction envelopes sent between agents."""

import secrets
from dataclasses import dataclass, field, replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .delegation_token import (
    DelegationToken,
)
from .delegation_token import (
    to_signable_dict as token_to_signable_dict,
)
from .keygen import sign_payload


@dataclass
class Instruction:
    """A signed instruction and the delegation token authorizing it."""

    instruction_id: str
    instruction_nonce: str
    issued_at: int
    issuer: str
    target_agent_id: str
    action: str
    signer_pubkey_id: str
    signature: str | None
    delegation_token: DelegationToken
    params: dict = field(default_factory=dict)


def to_signable_dict(instruction: Instruction) -> dict[str, object]:
    """Return the complete instruction envelope protected by its outer signature."""
    token_data = token_to_signable_dict(instruction.delegation_token)
    token_data["issuer_signature"] = instruction.delegation_token.issuer_signature
    return {
        "instruction_id": instruction.instruction_id,
        "instruction_nonce": instruction.instruction_nonce,
        "issued_at": instruction.issued_at,
        "issuer": instruction.issuer,
        "target_agent_id": instruction.target_agent_id,
        "action": instruction.action,
        "signer_pubkey_id": instruction.signer_pubkey_id,
        "delegation_token": token_data,
        "params": instruction.params,
    }


def sign_instruction(
    instruction: Instruction, private_key: Ed25519PrivateKey
) -> Instruction:
    """Return a new instruction with a signature over its canonical envelope."""
    return replace(
        instruction, signature=sign_payload(private_key, to_signable_dict(instruction))
    )


def new_nonce() -> str:
    """Generate a cryptographically random instruction nonce."""
    return secrets.token_hex(16)
