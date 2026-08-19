from authority.delegation_issuer import DelegationIssuer
from identity.instruction import (
    Instruction,
    new_nonce,
    sign_instruction,
    to_signable_dict,
)
from identity.keygen import generate_keypair, verify_signature


def _signed_instruction() -> tuple[Instruction, object]:
    root = generate_keypair()
    issuer = generate_keypair()
    token = DelegationIssuer(root.private_key, "root-v1").issue_token(
        "agent-a", ["finance:report:generate"], expiry_seconds=300
    )
    instruction = Instruction(
        instruction_id="instr_1",
        instruction_nonce=new_nonce(),
        issued_at=1_000,
        issuer="agent-a",
        target_agent_id="agent-b",
        action="finance:report:generate",
        signer_pubkey_id="agent-a-v1",
        signature=None,
        delegation_token=token,
    )
    return sign_instruction(instruction, issuer.private_key), issuer.public_key


def test_instruction_signature_verifies() -> None:
    instruction, public_key = _signed_instruction()

    assert instruction.signature is not None
    assert verify_signature(
        public_key, to_signable_dict(instruction), instruction.signature
    )


def test_signable_instruction_excludes_outer_signature_and_includes_token_signature() -> (
    None
):
    instruction, _ = _signed_instruction()
    signable = to_signable_dict(instruction)

    assert "signature" not in signable
    assert signable["delegation_token"]["issuer_signature"] == (
        instruction.delegation_token.issuer_signature
    )


def test_tampering_with_instruction_fields_breaks_signature() -> None:
    instruction, public_key = _signed_instruction()
    assert instruction.signature is not None

    for field, value in (
        ("action", "finance:report:delete"),
        ("target_agent_id", "agent-c"),
        ("issued_at", 1_001),
    ):
        setattr(instruction, field, value)
        assert not verify_signature(
            public_key, to_signable_dict(instruction), instruction.signature
        )
        setattr(
            instruction,
            field,
            {
                "action": "finance:report:generate",
                "target_agent_id": "agent-b",
                "issued_at": 1_000,
            }[field],
        )
