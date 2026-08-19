"""Pydantic request/response models representing the API contract."""

from typing import List, Optional
from pydantic import BaseModel


class DelegationTokenPayload(BaseModel):
    token_id: str
    subject_agent_id: str
    max_scope: List[str]
    delegation_depth: int
    max_delegation_depth: int
    expiry: int
    issuer_key_id: str
    issuer_signature: Optional[str] = None


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


class DashboardStateResponse(BaseModel):
    health: HealthResponse
    reputation: dict[str, ReputationResponse]
    audit_feed: List[AuditRecordResponse]


class ErrorResponse(BaseModel):
    error: str
