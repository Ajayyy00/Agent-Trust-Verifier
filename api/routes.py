"""API Endpoints."""

import os
import time
import uuid
from dataclasses import dataclass

from fastapi import APIRouter, HTTPException, Request

from agents.agent_a import AgentA, InstructionParseError
from agents.business_actions import execute_action
from authority.delegation_issuer import DelegationIssuer
from identity.delegation_token import DelegationToken
from identity.instruction import Instruction, sign_instruction
from identity.keygen import generate_keypair, serialize_public_key

from .schemas import (
    AuditRecordResponse,
    BootstrapRequest,
    BootstrapResponse,
    DashboardStateResponse,
    DelegationTokenPayload,
    HealthResponse,
    InstructionPayload,
    ManualPromptRequest,
    RedTeamRunRequest,
    ReputationResponse,
    RevocationRequest,
    VerificationResponse,
)

router = APIRouter()

_TEST_BOOTSTRAP_SCOPE = ["finance:report:generate", "finance:payment:refund"]
_DASHBOARD_AGENTS = ["agent_a", "agent_b", "attacker"]
_MANUAL_AGENT_SCOPES = {
    "agent_a": _TEST_BOOTSTRAP_SCOPE,
    "agent_b": _TEST_BOOTSTRAP_SCOPE,
    # The attacker can produce a valid signature, but cannot authorize refunds.
    "attacker": ["finance:report:generate"],
}


@dataclass
class _ManualAgentCredentials:
    """Private demo credentials retained only in the running application process."""

    keypair: object
    key_version: str
    delegation_token: DelegationToken


def _require_demo_controls() -> None:
    """Keep dashboard actions unavailable unless this is an explicit demo deployment."""
    if os.getenv("ALLOW_TEST_BOOTSTRAP") != "1":
        raise HTTPException(status_code=403, detail="Dashboard controls are disabled")


def _bootstrap_credentials(
    app, public_key: str, subject_agent_id: str
) -> BootstrapResponse:
    """Register a generated test identity with an application's root authority."""
    key_version = f"{subject_agent_id}-{uuid.uuid4().hex}"
    app.state.key_registry.register(subject_agent_id, public_key, key_version)
    token = DelegationIssuer(app.state.root_keypair.private_key, "root-v1").issue_token(
        subject_agent_id,
        _TEST_BOOTSTRAP_SCOPE,
        expiry_seconds=300,
        requested_depth=1,
    )
    return BootstrapResponse(
        delegation_token=DelegationTokenPayload(
            token_id=token.token_id,
            subject_agent_id=token.subject_agent_id,
            max_scope=token.max_scope,
            delegation_depth=token.delegation_depth,
            max_delegation_depth=token.max_delegation_depth,
            expiry=token.expiry,
            issuer_key_id=token.issuer_key_id,
            issuer_signature=token.issuer_signature,
        ),
        key_version=key_version,
    )


def _reject_dashboard_identity_bootstrap(subject_agent_id: str) -> None:
    """Prevent public demo bootstrap from replacing dashboard agent identities."""
    if subject_agent_id in _DASHBOARD_AGENTS:
        raise HTTPException(
            status_code=403,
            detail="Bootstrap cannot register a dashboard agent identity",
        )


def _manual_agent_credentials(app, agent_id: str) -> _ManualAgentCredentials:
    """Provision one process-local signing identity for an interactive dashboard agent."""
    credentials_by_agent = getattr(app.state, "manual_agent_credentials", None)
    if credentials_by_agent is None:
        credentials_by_agent = {}
        app.state.manual_agent_credentials = credentials_by_agent

    credentials = credentials_by_agent.get(agent_id)
    if credentials is not None:
        return credentials

    keypair = generate_keypair()
    key_version = f"manual-{agent_id}-{uuid.uuid4().hex}"
    app.state.key_registry.register(
        agent_id, serialize_public_key(keypair.public_key), key_version
    )
    token = DelegationIssuer(app.state.root_keypair.private_key, "root-v1").issue_token(
        agent_id,
        _MANUAL_AGENT_SCOPES[agent_id],
        expiry_seconds=300,
        requested_depth=1,
    )
    credentials = _ManualAgentCredentials(
        keypair=keypair,
        key_version=key_version,
        delegation_token=token,
    )
    credentials_by_agent[agent_id] = credentials
    return credentials


@router.post("/test/bootstrap", response_model=BootstrapResponse)
def bootstrap_test_identity(
    payload: BootstrapRequest, request: Request
) -> BootstrapResponse:
    """Register an ephemeral test identity and issue a root-signed token when enabled.

    This route is intentionally unavailable unless the server is explicitly started
    with ``ALLOW_TEST_BOOTSTRAP=1``. It exists solely for local and test deployments
    whose ephemeral root authority is otherwise inaccessible to external tooling.
    """
    if os.getenv("ALLOW_TEST_BOOTSTRAP") != "1":
        raise HTTPException(status_code=403, detail="Test bootstrap is disabled")
    _reject_dashboard_identity_bootstrap(payload.subject_agent_id)

    return _bootstrap_credentials(
        request.app, payload.public_key, payload.subject_agent_id
    )


from pydantic import BaseModel


class ChaosRequest(BaseModel):
    fail_next: bool


@router.post("/test/chaos/audit")
def induce_audit_chaos(payload: ChaosRequest, request: Request):
    """Safely gated test-only route to induce audit-store failures."""
    _require_demo_controls()
    audit_service = request.app.state.audit_service
    audit_service.set_chaos_failure(payload.fail_next)
    return {"chaos_fail": payload.fail_next}


@router.post("/test/audit/reset")
def reset_demo_audit_log(request: Request):
    """Delete the complete audit ledger only in explicitly enabled demo deployments."""
    _require_demo_controls()
    deleted = request.app.state.audit_service.clear()
    return {"deleted": deleted}


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
        params=payload.params,
    )


@router.post("/instruction/verify", response_model=VerificationResponse)
def verify_instruction(payload: InstructionPayload, request: Request):
    """Verify an instruction using the TrustVerifier."""
    instruction = _instruction_from_payload(payload)
    verifier = request.app.state.trust_verifier
    now = int(time.time())
    result = verifier.verify(instruction, now)

    return _verification_response(result)


def _verification_response(result) -> VerificationResponse:
    """Serialize a verifier result for both HTTP and in-process callers."""
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


@dataclass
class _InProcessResponse:
    status_code: int
    body: dict

    def json(self) -> dict:
        return self.body

    @property
    def text(self) -> str:
        return str(self.body)


class _DashboardAttackClient:
    """Small route adapter used by the dashboard without an outbound HTTP hop."""

    def __init__(self, app) -> None:
        self.app = app

    def post(self, path: str, json: dict) -> _InProcessResponse:
        if path == "/test/bootstrap":
            _reject_dashboard_identity_bootstrap(json["subject_agent_id"])
            credentials = _bootstrap_credentials(
                self.app, json["public_key"], json["subject_agent_id"]
            )
            return _InProcessResponse(200, credentials.model_dump())
        if path == "/instruction/verify":
            instruction = _instruction_from_payload(InstructionPayload(**json))
            result = self.app.state.trust_verifier.verify(instruction, int(time.time()))
            return _InProcessResponse(200, _verification_response(result).model_dump())
        if path.startswith("/agents/") and path.endswith("/revoke"):
            agent_id = path.split("/")[2]
            self.app.state.key_registry.revoke(agent_id, json["reason"])
            return _InProcessResponse(
                200,
                {
                    "agent_id": agent_id,
                    "status": self.app.state.key_registry.get_status(agent_id),
                },
            )
        return _InProcessResponse(404, {"detail": "Not found"})


@router.post("/redteam/run")
def run_redteam(payload: RedTeamRunRequest, request: Request):
    """Run selected Phase 9 attacks against this app without an HTTP round trip."""
    from redteam.attacks import ATTACKS, create_attack_context

    _require_demo_controls()
    attack_map = {attack.__name__: attack for attack in ATTACKS}
    selected_names = payload.attacks or list(attack_map)
    unknown = sorted(set(selected_names) - set(attack_map))
    if unknown:
        raise HTTPException(status_code=422, detail={"unknown_attacks": unknown})

    client = _DashboardAttackClient(request.app)
    target_agent_id = request.app.state.trust_verifier.agent_id
    results = [
        attack(create_attack_context(client, target_agent_id))
        for name in selected_names
        for attack in [attack_map[name]]
    ]
    return {"results": results}


@router.post("/demo/send-valid", response_model=VerificationResponse)
def send_valid_instruction(request: Request):
    """Generate, sign, verify, and execute one non-destructive demo instruction."""
    _require_demo_controls()
    keypair = generate_keypair()
    subject_agent_id = f"dashboard-demo-{uuid.uuid4().hex}"
    credentials = _bootstrap_credentials(
        request.app, serialize_public_key(keypair.public_key), subject_agent_id
    )
    token = DelegationToken(**credentials.delegation_token.model_dump())
    instruction = sign_instruction(
        Instruction(
            instruction_id=f"dashboard-instruction-{uuid.uuid4().hex}",
            instruction_nonce=uuid.uuid4().hex,
            issued_at=int(time.time()),
            issuer=subject_agent_id,
            target_agent_id=request.app.state.trust_verifier.agent_id,
            action="finance:report:generate",
            signer_pubkey_id=credentials.key_version,
            signature=None,
            delegation_token=token,
            params={"period": "Q3-2024", "account_id": "dashboard"},
        ),
        keypair.private_key,
    )
    result = request.app.state.trust_verifier.verify(instruction, int(time.time()))
    if result.accepted:
        execute_action(instruction.action, instruction.params)
    return _verification_response(result)


@router.post("/demo/manual", response_model=VerificationResponse)
def submit_manual_prompt(payload: ManualPromptRequest, request: Request):
    """Parse a dashboard prompt with Gemini, sign it, and verify the result.

    This is demo-only and intentionally reuses Agent A's strict LLM parsing
    boundary: Gemini selects action and params; deterministic code creates the
    nonce, envelope, and Ed25519 signature.
    """
    _require_demo_controls()
    credentials = _manual_agent_credentials(request.app, payload.agent_id)
    agent = AgentA(
        keypair=credentials.keypair,
        pubkey_id=credentials.key_version,
        delegation_token=credentials.delegation_token,
        target_agent_id=request.app.state.trust_verifier.agent_id,
    )
    try:
        instruction = agent.propose_instruction(payload.prompt)
    except (OSError, InstructionParseError, RuntimeError) as error:
        raise HTTPException(
            status_code=502, detail=f"Prompt parsing failed: {error}"
        ) from error

    result = request.app.state.trust_verifier.verify(instruction, int(time.time()))
    return _verification_response(result)


@router.post("/agents/{agent_id}/revoke")
def revoke_agent(agent_id: str, payload: RevocationRequest, request: Request):
    """Revoke an agent's active key."""
    _require_demo_controls()
    key_registry = request.app.state.key_registry
    key_registry.revoke(agent_id, payload.reason)
    status = key_registry.get_status(agent_id)
    return {"agent_id": agent_id, "status": status}


@router.get("/audit", response_model=list[AuditRecordResponse])
def get_audit(
    request: Request,
    issuer: str | None = None,
    target: str | None = None,
    start_time: int | None = None,
    end_time: int | None = None,
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
    except Exception:  # noqa: BLE001 - health checks must degrade to unhealthy
        status = "unhealthy"

    latency_ms = (time.perf_counter() - start) * 1000
    return HealthResponse(
        status=status,
        backend=backend,
        latency_ms=latency_ms,
        region=os.getenv("AWS_REGION", "local"),
        environment=os.getenv("ENVIRONMENT", backend),
    )


@router.get("/dashboard/state", response_model=DashboardStateResponse)
def get_dashboard_state(request: Request):
    """Aggregated endpoint for the dashboard."""
    health = health_check(request)

    # Get last 50 audit records
    audit_records = get_audit(request=request)
    audit_feed = audit_records[-50:]

    reputation = {}
    agent_status = {}
    for agent in _DASHBOARD_AGENTS:
        reputation[agent] = get_reputation(agent, request)
        agent_status[agent] = request.app.state.key_registry.get_status(agent)

    return DashboardStateResponse(
        health=health,
        reputation=reputation,
        agent_status=agent_status,
        audit_feed=audit_feed,
    )
