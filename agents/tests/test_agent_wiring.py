"""Tests for agent_a and agent_b wiring — NO real LLM calls, NO real network.

Strategy:
  - monkeypatch agents.llm_client.ask_agent to return a fixed JSON string.
  - Use respx to mock httpx calls to the verifier API.
  - Use unittest.mock.patch as a spy on business_actions.execute_action to
    PROVE via assertion (not inference) that it is never called on a rejection.
"""

import json
from unittest.mock import patch

import pytest
import respx
from httpx import Response

from agents.agent_a import AgentA, InstructionParseError
from agents.agent_b import receive_instruction
from authority.delegation_issuer import DelegationIssuer
from identity.instruction import to_signable_dict
from identity.keygen import (
    generate_keypair,
    verify_signature,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

ACTION = "finance:report:generate"
PARAMS = {"period": "Q3-2024", "account_id": "ACC-001"}
FIXED_LLM_JSON = json.dumps({"action": ACTION, "params": PARAMS})

API_BASE = "http://127.0.0.1:8000"
VERIFY_URL = f"{API_BASE}/instruction/verify"


@pytest.fixture
def root_keypair():
    return generate_keypair()


@pytest.fixture
def agent_a_keypair():
    return generate_keypair()


@pytest.fixture
def delegation_token(root_keypair):
    issuer = DelegationIssuer(root_keypair.private_key, "root-v1")
    return issuer.issue_token(
        subject_agent_id="agent-a",
        max_scope=[ACTION, "finance:payment:refund"],
        expiry_seconds=300,
    )


@pytest.fixture
def agent_a(agent_a_keypair, delegation_token):
    return AgentA(
        keypair=agent_a_keypair,
        pubkey_id="agent-a-v1",
        delegation_token=delegation_token,
        target_agent_id="agent-b",
    )


# ---------------------------------------------------------------------------
# Agent A tests — deterministic wiring with a fake LLM
# ---------------------------------------------------------------------------


def test_propose_instruction_produces_correctly_signed_instruction(
    monkeypatch, agent_a, agent_a_keypair
) -> None:
    """The deterministic wrapper must sign correctly; we verify the signature ourselves."""
    monkeypatch.setattr("agents.llm_client.ask_agent", lambda *_: FIXED_LLM_JSON)

    instruction = agent_a.propose_instruction("Generate Q3 report for ACC-001")

    # Basic envelope checks
    assert instruction.action == ACTION
    assert instruction.params == PARAMS
    assert instruction.issuer == "agent-a"
    assert instruction.target_agent_id == "agent-b"
    assert instruction.signature is not None

    # Verify the signature ourselves using verify_signature(public_key, payload_dict, sig_b64).
    # This proves the *deterministic wrapper* (not the LLM) produced a valid signature.
    signable = to_signable_dict(instruction)
    pub_key = agent_a_keypair.public_key
    assert verify_signature(pub_key, signable, instruction.signature)


def test_propose_instruction_with_markdown_fenced_json(monkeypatch, agent_a) -> None:
    """Agent A should parse JSON even when the LLM wraps it in a markdown code fence."""
    fenced = f"```json\n{FIXED_LLM_JSON}\n```"
    monkeypatch.setattr("agents.llm_client.ask_agent", lambda *_: fenced)

    instruction = agent_a.propose_instruction("task")
    assert instruction.action == ACTION


def test_propose_instruction_with_garbage_response_raises(monkeypatch, agent_a) -> None:
    """A completely un-parseable LLM response should raise InstructionParseError."""
    monkeypatch.setattr(
        "agents.llm_client.ask_agent", lambda *_: "Sorry, I cannot help with that."
    )
    with pytest.raises(InstructionParseError):
        agent_a.propose_instruction("task")


def test_propose_instruction_with_missing_action_raises(monkeypatch, agent_a) -> None:
    monkeypatch.setattr(
        "agents.llm_client.ask_agent",
        lambda *_: json.dumps({"params": {"period": "Q1"}}),
    )
    with pytest.raises(InstructionParseError, match="missing 'action'"):
        agent_a.propose_instruction("task")


# ---------------------------------------------------------------------------
# Agent B tests — mocked HTTP + spy on execute_action
# ---------------------------------------------------------------------------


def _make_instruction(agent_a, monkeypatch):
    monkeypatch.setattr("agents.llm_client.ask_agent", lambda *_: FIXED_LLM_JSON)
    return agent_a.propose_instruction("Generate Q3 report for ACC-001")


@respx.mock
def test_agent_b_calls_execute_action_when_accepted(monkeypatch, agent_a) -> None:
    """When the API accepts an instruction, execute_action must be called exactly once."""
    instruction = _make_instruction(agent_a, monkeypatch)

    accepted_response = {
        "accepted": True,
        "reason_code": "ACCEPTED",
        "instruction_id": instruction.instruction_id,
        "issuer": instruction.issuer,
        "target": instruction.target_agent_id,
        "action": instruction.action,
        "token_id": instruction.delegation_token.token_id,
        "reputation_score": 100,
        "risk_level": "low",
        "requires_review": False,
    }
    respx.post(VERIFY_URL).mock(return_value=Response(200, json=accepted_response))

    with patch("agents.agent_b.business_actions.execute_action") as mock_execute:
        mock_execute.return_value = "Report generated"
        result = receive_instruction(instruction, API_BASE)

    # Spy assertion: called exactly once with correct args
    mock_execute.assert_called_once_with(ACTION, PARAMS)
    assert result["execution_result"] == "Report generated"
    assert result["verification"]["accepted"] is True


@respx.mock
def test_agent_b_never_calls_execute_action_when_rejected(monkeypatch, agent_a) -> None:
    """CRITICAL: When the API rejects an instruction, execute_action must NEVER be called.

    This is proven by a mock spy assertion, not inferred from the return value.
    A rejected instruction never reaches the business-action layer — that is the
    whole point of the architecture.
    """
    instruction = _make_instruction(agent_a, monkeypatch)

    rejected_response = {
        "accepted": False,
        "reason_code": "INVALID_SIGNATURE",
        "instruction_id": instruction.instruction_id,
        "issuer": instruction.issuer,
        "target": instruction.target_agent_id,
        "action": instruction.action,
        "token_id": instruction.delegation_token.token_id,
        "reputation_score": 60,
        "risk_level": "high",
        "requires_review": True,
    }
    respx.post(VERIFY_URL).mock(return_value=Response(200, json=rejected_response))

    with patch("agents.agent_b.business_actions.execute_action") as mock_execute:
        result = receive_instruction(instruction, API_BASE)

    # --- CRITICAL spy assertion ---
    mock_execute.assert_not_called()  # Proven, not inferred

    assert result["execution_result"] is None
    assert result["verification"]["accepted"] is False
    assert result["verification"]["reason_code"] == "INVALID_SIGNATURE"


@respx.mock
def test_agent_b_blocks_accepted_instruction_requiring_review(
    monkeypatch, agent_a
) -> None:
    instruction = _make_instruction(agent_a, monkeypatch)
    accepted_response = {
        "accepted": True,
        "reason_code": "ACCEPTED",
        "instruction_id": instruction.instruction_id,
        "issuer": instruction.issuer,
        "target": instruction.target_agent_id,
        "action": instruction.action,
        "token_id": instruction.delegation_token.token_id,
        "reputation_score": 40,
        "risk_level": "HIGH",
        "requires_review": True,
    }
    respx.post(VERIFY_URL).mock(return_value=Response(200, json=accepted_response))

    with patch("agents.agent_b.business_actions.execute_action") as mock_execute:
        result = receive_instruction(instruction, API_BASE)

    mock_execute.assert_not_called()
    assert result["execution_result"] == "BLOCKED_BY_REPUTATION"


@respx.mock
def test_agent_b_returns_rejection_reason_code(monkeypatch, agent_a) -> None:
    """The full rejection payload from the API must be surfaced in the result dict."""
    instruction = _make_instruction(agent_a, monkeypatch)

    rejected_response = {
        "accepted": False,
        "reason_code": "AGENT_REVOKED",
        "instruction_id": instruction.instruction_id,
        "issuer": instruction.issuer,
        "target": instruction.target_agent_id,
        "action": instruction.action,
        "token_id": None,
        "reputation_score": 80,
        "risk_level": "low",
        "requires_review": False,
    }
    respx.post(VERIFY_URL).mock(return_value=Response(200, json=rejected_response))

    with patch("agents.agent_b.business_actions.execute_action") as mock_execute:
        result = receive_instruction(instruction, API_BASE)

    mock_execute.assert_not_called()
    assert result["verification"]["reason_code"] == "AGENT_REVOKED"
