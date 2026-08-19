"""API Endpoints."""

import time
from typing import List, Optional

from fastapi import APIRouter, Request

from .schemas import (
    AuditRecordResponse,
    DashboardStateResponse,
    HealthResponse,
    InstructionPayload,
    ReputationResponse,
    RevocationRequest,
    VerificationResponse,
)
from identity.delegation_token import DelegationToken
from identity.instruction import Instruction

router = APIRouter()


def _instruction_from_payload(payload: InstructionPayload) -> Instruction:
    token = DelegationToken(
        token_id=payload.delegation_token.token_id,
        subject_agent_id=payload.delegation_token.subject_agent_id,
        max_scope=payload.delegation_token.max_scope,
        delegation_depth=payload.delegation_token.delegation_depth,
        max_delegation_depth=payload.delegation_token.max_delegation_depth,
        expiry=payload.delegation_token.expiry,
        issuer_key_id=payload.delegation_token.issuer_key_id,
        issuer_signature=payload.delegation_token.issuer_signature,
    )
    return Instruction(
        instruction_id=payload.instruction_id,
        instruction_nonce=payload.instruction_nonce,
        issued_at=payload.issued_at,
        issuer=payload.issuer,
        target_agent_id=payload.target_agent_id,
        action=payload.action,
        signer_pubkey_id=payload.signer_pubkey_id,
        signature=payload.signature,
        delegation_token=token,
    )


@router.post("/instruction/verify", response_model=VerificationResponse)
def verify_instruction(payload: InstructionPayload, request: Request):
    """Verify an instruction using the TrustVerifier."""
    instruction = _instruction_from_payload(payload)
    verifier = request.app.state.trust_verifier
    now = int(time.time())
    result = verifier.verify(instruction, now)

    return VerificationResponse(
        accepted=result.accepted,
        reason_code=result.reason_code,
        instruction_id=result.instruction_id,
        issuer=result.issuer,
        target=result.target,
        action=result.action,
        token_id=result.token_id,
        reputation_score=result.reputation_score,
        risk_level=result.risk_level,
        requires_review=result.requires_review,
    )


@router.post("/agents/{agent_id}/revoke")
def revoke_agent(agent_id: str, payload: RevocationRequest, request: Request):
    """Revoke an agent's active key."""
    key_registry = request.app.state.key_registry
    key_registry.revoke(agent_id, payload.reason)
    status = key_registry.get_status(agent_id)
    return {"agent_id": agent_id, "status": status}


@router.get("/audit", response_model=List[AuditRecordResponse])
def get_audit(
    request: Request,
    issuer: Optional[str] = None,
    target: Optional[str] = None,
    start_time: Optional[int] = None,
    end_time: Optional[int] = None,
):
    """Query the audit log."""
    audit_service = request.app.state.audit_service
    time_range = None
    if start_time is not None and end_time is not None:
        time_range = (start_time, end_time)

    records = audit_service.query(issuer=issuer, target=target, time_range=time_range)
    return [
        AuditRecordResponse(
            instruction_id=r.instruction_id,
            issuer=r.issuer,
            target=r.target,
            action=r.action,
            token_id=r.token_id,
            policy_version=r.policy_version,
            key_id=r.key_id,
            result=r.result,
            reason_code=r.reason_code,
            timestamp=r.timestamp,
            payload_hash=r.payload_hash,
            prev_hash=r.prev_hash,
            record_hash=r.record_hash,
        )
        for r in records
    ]


@router.get("/reputation/{agent_id}", response_model=ReputationResponse)
def get_reputation(agent_id: str, request: Request):
    """Get the reputation of a specific agent."""
    reputation_service = request.app.state.reputation_service
    score = reputation_service.get_score(agent_id)
    risk_level = reputation_service.get_risk_level(agent_id)
    requires_review = reputation_service.requires_review(agent_id)
    return ReputationResponse(
        agent_id=agent_id,
        score=score,
        risk_level=risk_level,
        requires_review=requires_review,
    )


@router.get("/health", response_model=HealthResponse)
def health_check(request: Request):
    """Check storage backend connectivity."""
    import os

    start = time.perf_counter()
    backend = os.getenv("STORAGE_BACKEND", "memory").lower()

    status = "healthy"
    try:
        if backend == "dynamodb":
            # Lightweight read against the DynamoDB backend
            request.app.state.key_registry.get_status("health-check-dummy")
    except Exception:
        status = "unhealthy"

    latency_ms = (time.perf_counter() - start) * 1000
    return HealthResponse(status=status, backend=backend, latency_ms=latency_ms)


@router.get("/dashboard/state", response_model=DashboardStateResponse)
def get_dashboard_state(request: Request):
    """Aggregated endpoint for the dashboard."""
    health = health_check(request)

    # Get last 50 audit records
    audit_records = get_audit(request=request)
    audit_feed = audit_records[-50:]

    reputation = {}
    for agent in ["agent_a", "agent_b", "attacker"]:
        reputation[agent] = get_reputation(agent, request)

    return DashboardStateResponse(
        health=health,
        reputation=reputation,
        audit_feed=audit_feed,
    )
