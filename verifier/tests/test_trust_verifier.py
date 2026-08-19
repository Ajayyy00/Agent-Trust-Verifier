import base64

from authority.delegation_issuer import DelegationIssuer
from identity.instruction import Instruction, sign_instruction
from identity.key_registry import KeyRegistry
from identity.keygen import generate_keypair, serialize_public_key
from verifier.replay_store import ReplayStore
from verifier.result import (
    ACCEPTED,
    AGENT_REVOKED,
    FUTURE_TIMESTAMP,
    INVALID_SIGNATURE,
    POLICY_DENIED,
    REPLAY_DETECTED,
    STALE_INSTRUCTION,
    TOKEN_EXPIRED,
    TOKEN_SCOPE_DENIED,
    TOKEN_SIGNATURE_INVALID,
    TOKEN_SUBJECT_MISMATCH,
    UNKNOWN_KEY,
    WRONG_AUDIENCE,
)
from verifier.trust_verifier import TrustVerifier

NOW = 1_000_000
ACTION = "finance:report:generate"


def _happy_path(
    *,
    token_scope: list[str] | None = None,
    local_policy: set[str] | None = None,
) -> tuple[TrustVerifier, Instruction, KeyRegistry]:
    root = generate_keypair()
    agent_a = generate_keypair()
    registry = KeyRegistry()
    registry.register("agent_a", serialize_public_key(agent_a.public_key), "agent-a-v1")
    token = DelegationIssuer(root.private_key, "root-v1").issue_token(
        "agent_a",
        token_scope if token_scope is not None else [ACTION],
        expiry_seconds=300,
    )
    instruction = sign_instruction(
        Instruction(
            instruction_id="instr-1",
            instruction_nonce="nonce-1",
            issued_at=NOW,
            issuer="agent_a",
            target_agent_id="agent_b",
            action=ACTION,
            signer_pubkey_id="agent-a-v1",
            signature=None,
            delegation_token=token,
        ),
        agent_a.private_key,
    )
    verifier = TrustVerifier(
        "agent_b",
        root.public_key,
        registry,
        ReplayStore(),
        local_policy if local_policy is not None else {ACTION},
    )
    return verifier, instruction, registry


def test_happy_path_is_accepted() -> None:
    verifier, instruction, _ = _happy_path()

    assert verifier.verify(instruction, NOW).reason_code == ACCEPTED


def test_wrong_audience_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()
    instruction.target_agent_id = "agent_c"

    assert verifier.verify(instruction, NOW).reason_code == WRONG_AUDIENCE


def test_future_timestamp_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()
    instruction.issued_at = NOW + 31

    assert verifier.verify(instruction, NOW).reason_code == FUTURE_TIMESTAMP


def test_stale_instruction_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()
    instruction.issued_at = NOW - 301

    assert verifier.verify(instruction, NOW).reason_code == STALE_INSTRUCTION


def test_expired_token_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()
    instruction.delegation_token.expiry = NOW - 1

    assert verifier.verify(instruction, NOW).reason_code == TOKEN_EXPIRED


def test_tampered_token_is_rejected_before_outer_signature() -> None:
    verifier, instruction, _ = _happy_path()
    instruction.delegation_token.max_scope = ["finance:report:delete"]

    assert verifier.verify(instruction, NOW).reason_code == TOKEN_SIGNATURE_INVALID


def test_subject_mismatch_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()
    instruction.issuer = "agent_other"

    assert verifier.verify(instruction, NOW).reason_code == TOKEN_SUBJECT_MISMATCH


def test_instruction_signed_by_different_key_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()
    other_agent = generate_keypair()
    instruction = sign_instruction(instruction, other_agent.private_key)

    assert verifier.verify(instruction, NOW).reason_code == INVALID_SIGNATURE


def test_unsigned_instruction_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()
    instruction.signature = None

    assert verifier.verify(instruction, NOW).reason_code == INVALID_SIGNATURE


def test_empty_signature_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()
    instruction.signature = ""

    assert verifier.verify(instruction, NOW).reason_code == INVALID_SIGNATURE


def test_malformed_signature_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()
    instruction.signature = "not-valid-base64!!!"

    assert verifier.verify(instruction, NOW).reason_code == INVALID_SIGNATURE


def test_wrong_length_signature_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()
    instruction.signature = base64.b64encode(b"too-short").decode()

    assert verifier.verify(instruction, NOW).reason_code == INVALID_SIGNATURE


def test_unknown_key_id_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()
    instruction.signer_pubkey_id = "unknown-v1"

    assert verifier.verify(instruction, NOW).reason_code == UNKNOWN_KEY


def test_revoked_issuer_is_rejected() -> None:
    verifier, instruction, registry = _happy_path()
    registry.revoke("agent_a", "credential compromised")

    assert verifier.verify(instruction, NOW).reason_code == AGENT_REVOKED


def test_action_outside_delegated_scope_is_rejected() -> None:
    verifier, instruction, _ = _happy_path(token_scope=["finance:read"])

    assert verifier.verify(instruction, NOW).reason_code == TOKEN_SCOPE_DENIED


def test_local_policy_is_an_independent_ceiling() -> None:
    verifier, instruction, _ = _happy_path(local_policy=set())

    assert verifier.verify(instruction, NOW).reason_code == POLICY_DENIED


def test_replayed_valid_instruction_is_rejected() -> None:
    verifier, instruction, _ = _happy_path()

    assert verifier.verify(instruction, NOW).reason_code == ACCEPTED
    assert verifier.verify(instruction, NOW).reason_code == REPLAY_DETECTED


def test_same_nonce_has_only_one_successful_consumer() -> None:
    store = ReplayStore()

    outcomes = [store.consume("agent_b", "simultaneous-nonce") for _ in range(2)]

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 1
