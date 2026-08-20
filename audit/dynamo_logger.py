"""DynamoDB-backed, hash-chained audit service with transactional head updates."""

from __future__ import annotations

import time
from threading import Lock
from typing import Any

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from .chain import GENESIS_HASH, compute_record_hash, verify_chain
from .logger import AuditCommitError
from .models import AuditRecord

_CHAIN_HEAD_ID = "__chain_head__"
_LEGACY_COUNTER_ID = "__audit_chain_counter__"
_CHAOS_ID = "__audit_chaos__"
_MAX_TRANSACTION_ATTEMPTS = 10
_RETRY_BASE_SECONDS = 0.01


class DynamoAuditService:
    """Persist a gap-free hash chain using an optimistic transactional head."""

    def __init__(self, table: Any) -> None:
        self._table = table
        # Avoid duplicate in-process races (and keep the local Moto emulator safe).
        # Cross-process/Lambda races remain guarded by the transactional head condition.
        self._commit_lock = Lock()

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

    def _head(self) -> tuple[int, str, bool]:
        response = self._table.get_item(
            Key={"instruction_id": _CHAIN_HEAD_ID}, ConsistentRead=True
        )
        head = response.get("Item")
        if head is None:
            return 0, GENESIS_HASH, False
        return int(head["sequence"]), head["record_hash"], True

    def _chaos_failure_enabled(self) -> bool:
        """Read the test-only fault switch from DynamoDB, not process memory.

        Lambda may serve two sequential API requests from different warm
        processes. Persisting the switch makes the live fail-closed check
        deterministic across those processes.
        """
        try:
            response = self._table.get_item(
                Key={"instruction_id": _CHAOS_ID}, ConsistentRead=True
            )
        except ClientError as error:
            raise AuditCommitError(
                "Unable to read audit failure test switch"
            ) from error
        return bool(response.get("Item", {}).get("enabled", False))

    def _transactional_append(
        self,
        sequence: int,
        previous_hash: str,
        record_fields: dict[str, Any],
        head_exists: bool,
    ) -> AuditRecord:
        record_hash = compute_record_hash(previous_hash, record_fields)
        record = AuditRecord(
            **record_fields, prev_hash=previous_hash, record_hash=record_hash
        )
        item = {
            **record_fields,
            "instruction_id": str(sequence),
            "actual_instruction_id": record_fields["instruction_id"],
            "prev_hash": previous_hash,
            "record_hash": record_hash,
            "sequence": sequence,
        }
        transactions = [
            {
                "Put": {
                    "TableName": self._table.name,
                    "Item": item,
                    "ConditionExpression": "attribute_not_exists(#id)",
                    "ExpressionAttributeNames": {"#id": "instruction_id"},
                }
            }
        ]
        if head_exists:
            transactions.append(
                {
                    "Update": {
                        "TableName": self._table.name,
                        "Key": {"instruction_id": _CHAIN_HEAD_ID},
                        "UpdateExpression": "SET #sequence = :next, record_hash = :record_hash",
                        "ConditionExpression": "#sequence = :current AND record_hash = :previous",
                        "ExpressionAttributeNames": {"#sequence": "sequence"},
                        "ExpressionAttributeValues": {
                            ":next": sequence,
                            ":current": sequence - 1,
                            ":record_hash": record_hash,
                            ":previous": previous_hash,
                        },
                    }
                }
            )
        else:
            transactions.append(
                {
                    "Put": {
                        "TableName": self._table.name,
                        "Item": {
                            "instruction_id": _CHAIN_HEAD_ID,
                            "sequence": sequence,
                            "record_hash": record_hash,
                        },
                        "ConditionExpression": "attribute_not_exists(#id)",
                        "ExpressionAttributeNames": {"#id": "instruction_id"},
                    }
                }
            )
        self._table.meta.client.transact_write_items(TransactItems=transactions)
        return record

    def commit(self, record_fields: dict[str, Any]) -> AuditRecord:
        """Atomically append a record, retrying head-change conflicts."""
        if self._chaos_failure_enabled():
            raise AuditCommitError("Simulated chaos audit commit failure")

        last_cancellation: ClientError | None = None
        with self._commit_lock:
            for attempt in range(_MAX_TRANSACTION_ATTEMPTS):
                sequence, previous_hash, head_exists = self._head()
                try:
                    return self._transactional_append(
                        sequence + 1, previous_hash, record_fields, head_exists
                    )
                except ClientError as error:
                    if (
                        error.response.get("Error", {}).get("Code")
                        != "TransactionCanceledException"
                    ):
                        raise AuditCommitError(
                            "Unable to commit audit record to DynamoDB"
                        ) from error
                    last_cancellation = error
                    if attempt == _MAX_TRANSACTION_ATTEMPTS - 1:
                        break
                    time.sleep(_RETRY_BASE_SECONDS * (2**attempt))
                except Exception as error:
                    raise AuditCommitError(
                        "Unable to commit audit record to DynamoDB"
                    ) from error

        raise AuditCommitError(
            "Audit-chain head changed too frequently to commit safely"
            + (f": {last_cancellation}" if last_cancellation else "")
        )

    def query(
        self,
        issuer: str | None = None,
        target: str | None = None,
        time_range: tuple[int, int] | None = None,
    ) -> list[AuditRecord]:
        """Filter audit records and return them chronologically."""
        if issuer is not None:
            operation = self._table.query
            request_kwargs: dict[str, Any] = {
                "IndexName": "issuer-index",
                "KeyConditionExpression": Key("issuer").eq(issuer),
            }
        elif target is not None:
            operation = self._table.query
            request_kwargs = {
                "IndexName": "target-index",
                "KeyConditionExpression": Key("target").eq(target),
            }
        else:
            operation = self._table.scan
            request_kwargs = {}

        items: list[dict[str, Any]] = []
        while True:
            page = operation(**request_kwargs)
            items.extend(page.get("Items", []))
            last_key = page.get("LastEvaluatedKey")
            if not last_key:
                break
            request_kwargs["ExclusiveStartKey"] = last_key
        records = [
            self._record_from_item(item)
            for item in items
            if item["instruction_id"]
            not in {_CHAIN_HEAD_ID, _LEGACY_COUNTER_ID, _CHAOS_ID}
            and (issuer is None or item["issuer"] == issuer)
            and (target is None or item["target"] == target)
            and (
                time_range is None
                or time_range[0] <= int(item["timestamp"]) <= time_range[1]
            )
        ]
        return sorted(records, key=lambda record: record.timestamp)

    def verify_integrity(self) -> tuple[bool, int | None]:
        """Verify the persisted chain in numeric sequence order."""
        items: list[dict[str, Any]] = []
        scan_kwargs: dict[str, Any] = {}
        while True:
            page = self._table.scan(**scan_kwargs)
            items.extend(page.get("Items", []))
            last_key = page.get("LastEvaluatedKey")
            if not last_key:
                break
            scan_kwargs["ExclusiveStartKey"] = last_key
        records_with_sequence = [
            item
            for item in items
            if item["instruction_id"]
            not in {_CHAIN_HEAD_ID, _LEGACY_COUNTER_ID, _CHAOS_ID}
        ]
        records_with_sequence.sort(key=lambda item: int(item["sequence"]))
        return verify_chain(
            [self._record_from_item(item) for item in records_with_sequence]
        )

    def clear(self) -> int:
        """Delete every audit record and chain head for a demo-environment reset."""
        deleted = 0
        scan_kwargs: dict[str, Any] = {}
        while True:
            page = self._table.scan(**scan_kwargs)
            with self._table.batch_writer() as batch:
                for item in page.get("Items", []):
                    batch.delete_item(Key={"instruction_id": item["instruction_id"]})
                    deleted += 1
            last_key = page.get("LastEvaluatedKey")
            if not last_key:
                return deleted
            scan_kwargs["ExclusiveStartKey"] = last_key

    def set_chaos_failure(self, enabled: bool) -> None:
        """Persist the test-only fault switch for all Lambda instances."""
        try:
            self._table.put_item(
                Item={"instruction_id": _CHAOS_ID, "enabled": bool(enabled)}
            )
        except ClientError as error:
            raise AuditCommitError(
                "Unable to configure audit failure test switch"
            ) from error
