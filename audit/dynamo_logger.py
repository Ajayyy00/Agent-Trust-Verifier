"""DynamoDB-backed, hash-chained audit service."""

from typing import Any

from boto3.dynamodb.conditions import Key

from .chain import GENESIS_HASH, compute_record_hash, verify_chain
from .models import AuditRecord

_COUNTER_ID = "__audit_chain_counter__"


class DynamoAuditService:
    """Persist audit records in DynamoDB.

    A global chain uses an atomic counter to assign a serialized sequence position.
    This is correct for the demo but not infinitely scalable; production should use
    sharded or time-windowed chains from the Production Hardening Boundary.
    """

    def __init__(self, table: Any) -> None:
        self._table = table

    @staticmethod
    def _record_from_item(item: dict[str, Any]) -> AuditRecord:
        return AuditRecord(
            instruction_id=item.get("actual_instruction_id", item["instruction_id"]),
            issuer=item["issuer"],
            target=item["target"],
            action=item["action"],
            token_id=item.get("token_id"),
            policy_version=item["policy_version"],
            key_id=item.get("key_id"),
            result=item["result"],
            reason_code=item["reason_code"],
            timestamp=int(item["timestamp"]),
            payload_hash=item["payload_hash"],
            prev_hash=item["prev_hash"],
            record_hash=item["record_hash"],
        )

    def _next_sequence(self) -> int:
        # The atomic counter serializes chain-position allocation across writers.
        response = self._table.update_item(
            Key={"instruction_id": _COUNTER_ID},
            UpdateExpression="ADD #sequence :one",
            ExpressionAttributeNames={"#sequence": "sequence"},
            ExpressionAttributeValues={":one": 1},
            ReturnValues="UPDATED_NEW",
        )
        return int(response["Attributes"]["sequence"])

    def _previous_hash(self, sequence: int) -> str:
        if sequence == 1:
            return GENESIS_HASH
        response = self._table.scan(
            FilterExpression="#sequence = :sequence",
            ExpressionAttributeNames={"#sequence": "sequence"},
            ExpressionAttributeValues={":sequence": sequence - 1},
            ConsistentRead=True,
        )
        previous = response.get("Items", [])
        if not previous:
            raise RuntimeError("Previous audit-chain position has not committed")
        return previous[0]["record_hash"]

    def commit(self, record_fields: dict[str, Any]) -> AuditRecord:
        """Commit a record at the next serialized chain position."""
        sequence = self._next_sequence()
        prev_hash = self._previous_hash(sequence)
        record_hash = compute_record_hash(prev_hash, record_fields)
        record = AuditRecord(**record_fields, prev_hash=prev_hash, record_hash=record_hash)
        item = {
            **record_fields,
            "instruction_id": str(sequence),
            "actual_instruction_id": record_fields["instruction_id"],
            "prev_hash": prev_hash,
            "record_hash": record_hash,
            "sequence": sequence,
        }
        self._table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(instruction_id)",
        )
        return record

    def query(
        self,
        issuer: str | None = None,
        target: str | None = None,
        time_range: tuple[int, int] | None = None,
    ) -> list[AuditRecord]:
        """Filter audit records using issuer/target indexes when available."""
        if issuer is not None:
            response = self._table.query(
                IndexName="issuer-index", KeyConditionExpression=Key("issuer").eq(issuer)
            )
        elif target is not None:
            response = self._table.query(
                IndexName="target-index", KeyConditionExpression=Key("target").eq(target)
            )
        else:
            response = self._table.scan()
        records = [
            self._record_from_item(item)
            for item in response.get("Items", [])
            if item["instruction_id"] != _COUNTER_ID
            and (issuer is None or item["issuer"] == issuer)
            and (target is None or item["target"] == target)
            and (
                time_range is None
                or time_range[0] <= int(item["timestamp"]) <= time_range[1]
            )
        ]
        return sorted(records, key=lambda record: record.instruction_id)

    def verify_integrity(self) -> tuple[bool, int | None]:
        """Verify the persisted chain in sequence order."""
        response = self._table.scan()
        records_with_sequence = [
            item for item in response.get("Items", []) if item["instruction_id"] != _COUNTER_ID
        ]
        records_with_sequence.sort(key=lambda item: int(item["sequence"]))
        return verify_chain([self._record_from_item(item) for item in records_with_sequence])
