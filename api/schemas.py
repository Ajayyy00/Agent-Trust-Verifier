"""Pydantic request/response models representing the API contract."""

from typing import List, Literal, Optional
from pydantic import BaseModel, Field


class DelegationTokenPayload(BaseModel):
    token_id: str
    subject_agent_id: str
    max_scope: List[str]
    delegation_depth: int
    max_delegation_depth: int
    expiry: int
    issuer_key_id: str
    issuer_signature: Optional[str] = None


class BootstrapRequest(BaseModel):
    """Development-only request for registering a test agent identity."""

    public_key: str
    subject_agent_id: str


class BootstrapResponse(BaseModel):
    """Development-only credentials used by the red-team suite."""

    delegation_token: DelegationTokenPayload
    key_version: str


class InstructionPayload(BaseModel):
    instruction_id: str
    instruction_nonce: str
    issued_at: int
    issuer: str
    target_agent_id: str
    action: str
    signer_pubkey_id: str
    signature: Optional[str] = None
    delegation_token: DelegationTokenPayload
    params: dict = {}


class RevocationRequest(BaseModel):
    reason: str


class VerificationResponse(BaseModel):
    accepted: bool
    reason_code: str
    instruction_id: str
    issuer: str
    target: str
    action: str
    token_id: Optional[str] = None
    reputation_score: int
    risk_level: str
    requires_review: bool


class RedTeamRunRequest(BaseModel):
    """Optional subset of red-team attack function names to execute."""

    attacks: List[str] | None = None


class ManualPromptRequest(BaseModel):
    """A dashboard prompt to parse and submit using a demo identity."""

    prompt: str = Field(min_length=1, max_length=4_000)
    agent_id: Literal["agent_a", "agent_b", "attacker"]


class AuditRecordResponse(BaseModel):
    instruction_id: str
    issuer: str
    target: str
    action: str
    token_id: Optional[str] = None
    policy_version: str
    key_id: Optional[str] = None
    result: str
    reason_code: str
    timestamp: int
    payload_hash: str
    prev_hash: str
    record_hash: str


class ReputationResponse(BaseModel):
    agent_id: str
    score: int
    risk_level: str
    requires_review: bool


class HealthResponse(BaseModel):
    status: str
    backend: str
    latency_ms: float
    region: str
    environment: str


class DashboardStateResponse(BaseModel):
    health: HealthResponse
    reputation: dict[str, ReputationResponse]
    agent_status: dict[str, str]
    audit_feed: List[AuditRecordResponse]


class ErrorResponse(BaseModel):
    error: str
