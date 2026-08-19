"""Hash-chain integrity helpers for audit records."""

import hashlib
from dataclasses import fields
from typing import Any

from identity.canonical import canonicalize

from .models import AuditRecord

GENESIS_HASH = "0" * 64


def compute_record_hash(prev_hash: str, record_without_hash: dict[str, Any]) -> str:
    """Hash a record's canonical fields together with its predecessor hash."""
    return hashlib.sha256(
        prev_hash.encode("ascii") + canonicalize(record_without_hash)
    ).hexdigest()


def _record_without_hash(record: AuditRecord) -> dict[str, Any]:
    return {
        field.name: getattr(record, field.name)
        for field in fields(AuditRecord)
        if field.name not in {"prev_hash", "record_hash"}
    }


def verify_chain(records: list[AuditRecord]) -> tuple[bool, int | None]:
    """Verify every predecessor link and record hash in chronological order."""
    expected_prev_hash = GENESIS_HASH
    for index, record in enumerate(records):
        expected_hash = compute_record_hash(
            expected_prev_hash, _record_without_hash(record)
        )
        if (
            record.prev_hash != expected_prev_hash
            or record.record_hash != expected_hash
        ):
            return False, index
        expected_prev_hash = record.record_hash
    return True, None
