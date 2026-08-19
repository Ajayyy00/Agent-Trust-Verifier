import pytest

from audit.chain import GENESIS_HASH
from audit.logger import AuditCommitError, AuditService


def _record_fields(
    *, issuer: str = "agent-a", target: str = "agent-b", timestamp: int = 1_000
) -> dict[str, object]:
    return {
        "instruction_id": f"instruction-{timestamp}",
        "issuer": issuer,
        "target": target,
        "action": "finance:report:generate",
        "token_id": "token-1",
        "policy_version": "v1",
        "key_id": "agent-a-v1",
        "result": "accepted",
        "reason_code": "ACCEPTED",
        "timestamp": timestamp,
        "payload_hash": f"payload-{timestamp}",
    }


def test_commit_chains_each_record_to_its_predecessor() -> None:
    service = AuditService()
    first = service.commit(_record_fields(timestamp=1_000))
    second = service.commit(_record_fields(timestamp=1_001))

    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.record_hash


def test_query_filters_by_issuer_target_and_time_range() -> None:
    service = AuditService()
    first = service.commit(
        _record_fields(issuer="agent-a", target="agent-b", timestamp=1)
    )
    service.commit(_record_fields(issuer="agent-c", target="agent-b", timestamp=2))
    service.commit(_record_fields(issuer="agent-a", target="agent-d", timestamp=3))

    assert service.query(issuer="agent-a") == [first, service.records[2]]
    assert service.query(target="agent-b", time_range=(2, 2)) == [service.records[1]]


def test_simulated_commit_failure_raises_audit_commit_error() -> None:
    service = AuditService(simulate_failure=True)

    with pytest.raises(AuditCommitError):
        service.commit(_record_fields())
