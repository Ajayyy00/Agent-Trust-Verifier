from audit.chain import compute_record_hash, verify_chain
from audit.logger import AuditService


def _record_fields(index: int) -> dict[str, object]:
    return {
        "instruction_id": f"instruction-{index}",
        "issuer": "agent-a",
        "target": "agent-b",
        "action": "finance:report:generate",
        "token_id": "token-1",
        "policy_version": "v1",
        "key_id": "agent-a-v1",
        "result": "accepted",
        "reason_code": "ACCEPTED",
        "timestamp": 1_000 + index,
        "payload_hash": f"payload-{index}",
    }


def test_record_hash_is_deterministic() -> None:
    fields = _record_fields(1)

    assert compute_record_hash("0" * 64, fields) == compute_record_hash(
        "0" * 64, fields
    )


def test_changing_any_field_changes_record_hash() -> None:
    fields = _record_fields(1)
    changed_fields = {**fields, "action": "finance:report:delete"}

    assert compute_record_hash("0" * 64, fields) != compute_record_hash(
        "0" * 64, changed_fields
    )


def test_untouched_five_record_chain_verifies() -> None:
    service = AuditService()
    for index in range(5):
        service.commit(_record_fields(index))

    assert verify_chain(service.records) == (True, None)


def test_corrupted_middle_record_reports_its_index() -> None:
    service = AuditService()
    for index in range(5):
        service.commit(_record_fields(index))
    records = service.records
    records[2].action = "tampered"

    assert verify_chain(records) == (False, 2)
