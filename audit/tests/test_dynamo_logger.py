"""DynamoDB-backed audit service tests — interface-parity mirror of test_logger.py."""

import pytest

from audit.chain import GENESIS_HASH
from audit.dynamo_logger import DynamoAuditService
from storage.tests.helpers import create_test_tables


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def service_and_mock():
    mock, tables = create_test_tables()
    yield DynamoAuditService(tables["audit"])
    mock.stop()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Interface-parity tests (mirror of test_logger.py)
# ---------------------------------------------------------------------------


def test_commit_chains_each_record_to_its_predecessor(
    service_and_mock: DynamoAuditService,
) -> None:
    service = service_and_mock
    first = service.commit(_record_fields(timestamp=1_000))
    second = service.commit(_record_fields(timestamp=1_001))

    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.record_hash


def test_query_filters_by_issuer(service_and_mock: DynamoAuditService) -> None:
    service = service_and_mock
    first = service.commit(_record_fields(issuer="agent-a", target="agent-b", timestamp=1))
    service.commit(_record_fields(issuer="agent-c", target="agent-b", timestamp=2))
    service.commit(_record_fields(issuer="agent-a", target="agent-d", timestamp=3))

    results = service.query(issuer="agent-a")
    instruction_ids = {r.instruction_id for r in results}
    assert first.instruction_id in instruction_ids
    assert "instruction-3" in instruction_ids
    assert len(results) == 2


def test_query_filters_by_target_and_time_range(
    service_and_mock: DynamoAuditService,
) -> None:
    service = service_and_mock
    service.commit(_record_fields(issuer="agent-a", target="agent-b", timestamp=1))
    second = service.commit(_record_fields(issuer="agent-c", target="agent-b", timestamp=2))
    service.commit(_record_fields(issuer="agent-a", target="agent-d", timestamp=3))

    results = service.query(target="agent-b", time_range=(2, 2))
    assert len(results) == 1
    assert results[0].instruction_id == second.instruction_id


def test_verify_integrity_on_intact_chain(
    service_and_mock: DynamoAuditService,
) -> None:
    service = service_and_mock
    service.commit(_record_fields(timestamp=1_000))
    service.commit(_record_fields(timestamp=1_001))

    ok, bad_index = service.verify_integrity()
    assert ok is True
    assert bad_index is None


def test_empty_chain_verifies_cleanly(service_and_mock: DynamoAuditService) -> None:
    service = service_and_mock

    ok, bad_index = service.verify_integrity()
    assert ok is True
    assert bad_index is None


def test_query_with_no_filters_returns_all_records(
    service_and_mock: DynamoAuditService,
) -> None:
    service = service_and_mock
    service.commit(_record_fields(timestamp=1))
    service.commit(_record_fields(timestamp=2))

    results = service.query()
    assert len(results) == 2


def test_counter_item_never_appears_in_query_results(
    service_and_mock: DynamoAuditService,
) -> None:
    """The internal atomic counter row must be filtered out of all query results."""
    service = service_and_mock
    service.commit(_record_fields(timestamp=1))

    results = service.query()
    # The counter item has instruction_id == "__audit_chain_counter__"
    assert all(r.instruction_id != "__audit_chain_counter__" for r in results)
