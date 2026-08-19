"""Verification outcomes and audit-friendly reason codes."""

from dataclasses import dataclass

ACCEPTED = "ACCEPTED"
INVALID_SIGNATURE = "INVALID_SIGNATURE"
TOKEN_SIGNATURE_INVALID = "TOKEN_SIGNATURE_INVALID"
TOKEN_EXPIRED = "TOKEN_EXPIRED"
TOKEN_SCOPE_DENIED = "TOKEN_SCOPE_DENIED"
AGENT_REVOKED = "AGENT_REVOKED"
WRONG_AUDIENCE = "WRONG_AUDIENCE"
REPLAY_DETECTED = "REPLAY_DETECTED"
FUTURE_TIMESTAMP = "FUTURE_TIMESTAMP"
STALE_INSTRUCTION = "STALE_INSTRUCTION"
POLICY_DENIED = "POLICY_DENIED"
TOKEN_SUBJECT_MISMATCH = "TOKEN_SUBJECT_MISMATCH"
UNKNOWN_KEY = "UNKNOWN_KEY"
INVALID_SCHEMA = "INVALID_SCHEMA"
AUDIT_FAILURE = "AUDIT_FAILURE"


@dataclass(frozen=True)
class VerificationResult:
    """The decision and context emitted for every verification attempt."""

    accepted: bool
    reason_code: str
    instruction_id: str
    issuer: str
    target: str
    action: str
    token_id: str | None = None
    reputation_score: int = 100
    risk_level: str = "NORMAL"
    requires_review: bool = False
