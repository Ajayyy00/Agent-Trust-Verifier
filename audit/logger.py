"""Storage-agnostic audit service backed by an in-memory record list."""

from typing import Any

from .chain import GENESIS_HASH, compute_record_hash, verify_chain
from .models import AuditRecord


class AuditCommitError(RuntimeError):
    """Raised when a verification decision cannot be committed to the audit log."""


class AuditService:
    """Commit and query hash-chained audit records."""

    def __init__(self, simulate_failure: bool = False) -> None:
        self._records: list[AuditRecord] = []
        self._simulate_failure = simulate_failure

    @property
    def records(self) -> list[AuditRecord]:
        """Return a copy of committed audit records for inspection."""
        return self._records.copy()

    def commit(self, record_fields: dict[str, Any]) -> AuditRecord:
        """Hash, persist, and return an audit record or raise AuditCommitError."""
        if self._simulate_failure:
            raise AuditCommitError("Simulated audit commit failure")
        try:
            prev_hash = self._records[-1].record_hash if self._records else GENESIS_HASH
            record_hash = compute_record_hash(prev_hash, record_fields)
            record = AuditRecord(
                **record_fields, prev_hash=prev_hash, record_hash=record_hash
            )
            self._records.append(record)
            return record
        except Exception as error:
            raise AuditCommitError("Unable to commit audit record") from error

    def query(
        self,
        issuer: str | None = None,
        target: str | None = None,
        time_range: tuple[int, int] | None = None,
    ) -> list[AuditRecord]:
        """Return records matching optional issuer, target, and inclusive time filters."""
        return [
            record
            for record in self._records
            if (issuer is None or record.issuer == issuer)
            and (target is None or record.target == target)
            and (
                time_range is None or time_range[0] <= record.timestamp <= time_range[1]
            )
        ]

    def verify_integrity(self) -> tuple[bool, int | None]:
        """Verify the hash-chain integrity of every committed record."""
        return verify_chain(self._records)

    def clear(self) -> int:
        """Delete every in-memory audit record and return the count removed."""
        deleted = len(self._records)
        self._records.clear()
        return deleted

    def set_chaos_failure(self, enabled: bool) -> None:
        """Enable a test-only commit failure used by live fail-closed checks."""
        self._simulate_failure = enabled
