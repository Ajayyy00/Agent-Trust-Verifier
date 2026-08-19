"""Structured audit-record model."""

from dataclasses import dataclass


@dataclass
class AuditRecord:
    """Metadata-only, tamper-evident record of a verification decision."""

    instruction_id: str
    issuer: str
    target: str
    action: str
    token_id: str | None
    policy_version: str
    key_id: str | None
    result: str
    reason_code: str
    timestamp: int
    payload_hash: str
    prev_hash: str
    record_hash: str
