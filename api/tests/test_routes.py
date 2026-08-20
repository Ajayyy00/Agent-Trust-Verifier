"""FastAPI TestClient-based tests for the API layer."""

import time

import pytest
from fastapi.testclient import TestClient

from api.main import app
from authority.delegation_issuer import DelegationIssuer
from identity.delegation_token import DelegationToken
from identity.instruction import Instruction, sign_instruction
from identity.keygen import generate_keypair, serialize_public_key
from verifier.result import (
    ACCEPTED,
    AGENT_REVOKED,
    AUDIT_FAILURE,
    INVALID_SIGNATURE,
    TOKEN_SCOPE_DENIED,
)

ACTION = "finance:report:generate"


@pytest.fixture
def client():
    # Using 'with' triggers the lifespan events which initializes the state
    with TestClient(app) as c:
        yield c


def _generate_valid_payload(client: TestClient) -> dict:
    # Get the state directly from the app for our tests
    registry = app.state.key_registry
    root_keypair = app.state.root_keypair

    agent_a = generate_keypair()
    registry.register("agent-a", serialize_public_key(agent_a.public_key), "agent-a-v1")

    token = DelegationIssuer(root_keypair.private_key, "root-v1").issue_token(
        "agent-a",
        [ACTION],
        expiry_seconds=300,
    )

    instruction = Instruction(
        instruction_id="instr-1",
        instruction_nonce="nonce-1",
        issued_at=int(time.time()),
        issuer="agent-a",
        target_agent_id="agent-api",  # Must match the verifier's agent_id
        action=ACTION,
        signer_pubkey_id="agent-a-v1",
        signature=None,
        delegation_token=token,
    )
    signed_instruction = sign_instruction(instruction, agent_a.private_key)

    # Convert to dict for JSON payload
    payload = {
        "instruction_id": signed_instruction.instruction_id,
        "instruction_nonce": signed_instruction.instruction_nonce,
        "issued_at": signed_instruction.issued_at,
        "issuer": signed_instruction.issuer,
        "target_agent_id": signed_instruction.target_agent_id,
        "action": signed_instruction.action,
        "signer_pubkey_id": signed_instruction.signer_pubkey_id,
        "signature": signed_instruction.signature,
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
        "params": {},
    }
    return payload


def test_verify_happy_path(client: TestClient) -> None:
    payload = _generate_valid_payload(client)
    response = client.post("/instruction/verify", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["accepted"] is True
    assert data["reason_code"] == ACCEPTED


def test_dashboard_controls_are_demo_gated(client: TestClient, monkeypatch) -> None:
    monkeypatch.delenv("ALLOW_TEST_BOOTSTRAP", raising=False)

    assert client.post("/redteam/run", json={}).status_code == 403
    assert client.post("/demo/send-valid").status_code == 403
    assert (
        client.post(
            "/demo/manual", json={"prompt": "Generate a report", "agent_id": "agent_a"}
        ).status_code
        == 403
    )


def test_manual_prompt_is_llm_parsed_signed_and_verified(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "1")
    monkeypatch.setattr(
        "agents.llm_client.ask_agent",
        lambda _system, _prompt: '{"action":"finance:report:generate","params":{"account_id":"ACC-001"}}',
    )

    response = client.post(
        "/demo/manual",
        json={"prompt": "Generate the report for ACC-001", "agent_id": "agent_a"},
    )

    assert response.status_code == 200
    assert response.json()["accepted"] is True
    assert response.json()["reason_code"] == ACCEPTED


def test_manual_attacker_request_is_verified_against_its_narrow_scope(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "1")
    monkeypatch.setattr(
        "agents.llm_client.ask_agent",
        lambda _system, _prompt: '{"action":"finance:payment:refund","params":{"amount":"100"}}',
    )

    response = client.post(
        "/demo/manual",
        json={"prompt": "Refund 100", "agent_id": "attacker"},
    )

    assert response.status_code == 200
    assert response.json()["accepted"] is False
    assert response.json()["reason_code"] == TOKEN_SCOPE_DENIED


def test_dashboard_controls_run_against_the_live_app_state(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "1")

    valid = client.post("/demo/send-valid")
    redteam = client.post(
        "/redteam/run", json={"attacks": ["attack_unsigned_instruction"]}
    )
    state = client.get("/dashboard/state")

    assert valid.status_code == 200
    assert valid.json()["reason_code"] == ACCEPTED
    assert redteam.status_code == 200
    assert redteam.json()["results"][0]["passed"] is True
    assert state.status_code == 200
    assert "agent_status" in state.json()


def test_demo_audit_reset_is_gated_and_clears_the_feed(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.delenv("ALLOW_TEST_BOOTSTRAP", raising=False)
    assert client.post("/test/audit/reset").status_code == 403

    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "1")
    assert client.post("/demo/send-valid").status_code == 200
    assert client.get("/audit").json()

    reset = client.post("/test/audit/reset")
    assert reset.status_code == 200
    assert reset.json()["deleted"] >= 1
    assert client.get("/audit").json() == []


def test_audit_chaos_route_forces_a_fail_closed_rejection(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "1")
    assert client.post("/test/chaos/audit", json={"fail_next": True}).status_code == 200
    result = client.post("/demo/send-valid")
    assert result.status_code == 200
    assert result.json()["accepted"] is False
    assert result.json()["reason_code"] == AUDIT_FAILURE
    assert (
        client.post("/test/chaos/audit", json={"fail_next": False}).status_code == 200
    )


def test_test_bootstrap_is_disabled_by_default(client: TestClient, monkeypatch) -> None:
    monkeypatch.delenv("ALLOW_TEST_BOOTSTRAP", raising=False)

    response = client.post(
        "/test/bootstrap",
        json={"public_key": "not-used", "subject_agent_id": "test-agent"},
    )

    assert response.status_code == 403


def test_test_bootstrap_issues_a_token_that_verifies(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "1")
    agent_keypair = generate_keypair()
    subject_agent_id = "bootstrap-agent"
    bootstrap_response = client.post(
        "/test/bootstrap",
        json={
            "public_key": serialize_public_key(agent_keypair.public_key),
            "subject_agent_id": subject_agent_id,
        },
    )

    assert bootstrap_response.status_code == 200
    bootstrap = bootstrap_response.json()
    assert bootstrap["key_version"]
    token = DelegationToken(**bootstrap["delegation_token"])
    instruction = sign_instruction(
        Instruction(
            instruction_id="bootstrap-instruction",
            instruction_nonce="bootstrap-nonce",
            issued_at=int(time.time()),
            issuer=subject_agent_id,
            target_agent_id=app.state.trust_verifier.agent_id,
            action=ACTION,
            signer_pubkey_id=bootstrap["key_version"],
            signature=None,
            delegation_token=token,
            params={},
        ),
        agent_keypair.private_key,
    )
    response = client.post(
        "/instruction/verify",
        json={
            "instruction_id": instruction.instruction_id,
            "instruction_nonce": instruction.instruction_nonce,
            "issued_at": instruction.issued_at,
            "issuer": instruction.issuer,
            "target_agent_id": instruction.target_agent_id,
            "action": instruction.action,
            "signer_pubkey_id": instruction.signer_pubkey_id,
            "signature": instruction.signature,
            "delegation_token": bootstrap["delegation_token"],
            "params": instruction.params,
        },
    )

    assert response.status_code == 200
    assert response.json()["reason_code"] == ACCEPTED


@pytest.mark.parametrize("agent_id", ["agent_a", "agent_b", "attacker"])
def test_test_bootstrap_cannot_replace_dashboard_agent_identities(
    client: TestClient, monkeypatch, agent_id: str
) -> None:
    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "1")

    response = client.post(
        "/test/bootstrap",
        json={"public_key": "not-used", "subject_agent_id": agent_id},
    )

    assert response.status_code == 403


def test_verify_tampered_instruction_is_a_business_rejection_not_http_error(
    client: TestClient,
) -> None:
    payload = _generate_valid_payload(client)
    # Tamper with the action
    payload["action"] = "finance:report:delete"

    response = client.post("/instruction/verify", json=payload)

    # HTTP status is still 200 OK because the request was well-formed
    # The payload signifies the security decision
    assert response.status_code == 200
    data = response.json()
    assert data["accepted"] is False
    assert data["reason_code"] == INVALID_SIGNATURE


def test_revoke_agent_then_verify_fails(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "1")
    payload = _generate_valid_payload(client)

    # First revoke the agent
    revoke_response = client.post(
        "/agents/agent-a/revoke", json={"reason": "compromised"}
    )
    assert revoke_response.status_code == 200
    assert revoke_response.json()["status"] == "revoked"

    # Then try to verify the instruction
    verify_response = client.post("/instruction/verify", json=payload)
    assert verify_response.status_code == 200
    data = verify_response.json()
    assert data["accepted"] is False
    assert data["reason_code"] == AGENT_REVOKED


def test_audit_filters(client: TestClient) -> None:
    payload = _generate_valid_payload(client)
    # Verify instruction to create an audit record
    client.post("/instruction/verify", json=payload)

    response = client.get("/audit?issuer=agent-a")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert data[-1]["issuer"] == "agent-a"

    response_empty = client.get("/audit?issuer=agent-other")
    assert response_empty.status_code == 200
    assert len(response_empty.json()) == 0


def test_reputation_reflects_score_changes(client: TestClient) -> None:
    # Drive reputation down with invalid signatures
    payload = _generate_valid_payload(client)
    payload["action"] = "finance:report:delete"

    client.post("/instruction/verify", json=payload)
    client.post("/instruction/verify", json=payload)

    response = client.get("/reputation/agent-a")
    assert response.status_code == 200
    data = response.json()
    assert data["agent_id"] == "agent-a"
    assert data["score"] < 100


def test_health_check(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "backend" in data
    assert "latency_ms" in data


def test_payload_size_limit(client: TestClient) -> None:
    large_payload = "x" * (512 * 1024 + 10)
    response = client.post(
        "/instruction/verify",
        data=large_payload,
        headers={"Content-Length": str(len(large_payload))},
    )
    assert response.status_code == 413
    assert response.json()["error"] == "Payload too large"


def test_malformed_json_returns_structured_error(client: TestClient) -> None:
    response = client.post("/instruction/verify", data="not json")

    # Should be 422 Unprocessable Entity for invalid json, not 500
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"] == "Validation error"
    assert "details" in data
