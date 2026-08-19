"""DynamoDB-backed public-key registry."""

from datetime import datetime, timezone
from typing import Any

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

_ACTIVE_VERSION = "__active__"


class DynamoKeyRegistry:
    """Persist agent public keys while preserving the KeyRegistry interface."""

    def __init__(self, table: Any) -> None:
        self._table = table

    def register(
        self, agent_id: str, public_key_b64: str, key_version: str = "v1"
    ) -> None:
        """Register a new public key version without silently overwriting it."""
        if key_version == _ACTIVE_VERSION:
            raise ValueError("Reserved key version")
        try:
            self._table.put_item(
                Item={
                    "agent_id": agent_id,
                    "key_version": key_version,
                    "public_key_b64": public_key_b64,
                    "status": "active",
                },
                ConditionExpression="attribute_not_exists(agent_id) AND attribute_not_exists(key_version)",
            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise ValueError(
                    f"Key version {key_version!r} is already registered for {agent_id!r}"
                ) from error
            raise
        self._table.put_item(
            Item={
                "agent_id": agent_id,
                "key_version": _ACTIVE_VERSION,
                "active_version": key_version,
                "status": "active",
            }
        )

    def _active_metadata(self, agent_id: str) -> dict[str, Any] | None:
        response = self._table.get_item(
            Key={"agent_id": agent_id, "key_version": _ACTIVE_VERSION},
            ConsistentRead=True,
        )
        return response.get("Item")

    def get_active_key(self, agent_id: str) -> str | None:
        """Return the active key only when its current status is active."""
        metadata = self._active_metadata(agent_id)
        if metadata is None or metadata.get("status") != "active":
            return None
        return self.get_key_for_verification(agent_id, metadata["active_version"])

    def get_key_for_verification(
        self, agent_id: str, key_version: str | None = None
    ) -> str | None:
        """Return a stored key, including revoked keys, for signature audit verification."""
        if key_version is None:
            metadata = self._active_metadata(agent_id)
            if metadata is None:
                return None
            key_version = metadata["active_version"]
        # A stale key lookup could accept a revoked credential for one verification cycle.
        response = self._table.get_item(
            Key={"agent_id": agent_id, "key_version": key_version},
            ConsistentRead=True,
        )
        item = response.get("Item")
        return None if item is None else item["public_key_b64"]

    def get_status(self, agent_id: str) -> str:
        """Return the live active-key status for an agent."""
        # A stale status read would silently reintroduce the revocation race this registry prevents.
        response = self._table.get_item(
            Key={"agent_id": agent_id, "key_version": _ACTIVE_VERSION},
            ConsistentRead=True,
        )
        return response.get("Item", {}).get("status", "unknown")

    def revoke(self, agent_id: str, reason: str) -> None:
        """Revoke the active key while preserving it for historical verification."""
        metadata = self._active_metadata(agent_id)
        if metadata is None:
            raise KeyError(f"Unknown agent: {agent_id}")
        now = datetime.now(timezone.utc).isoformat()
        for key_version in (metadata["active_version"], _ACTIVE_VERSION):
            self._table.update_item(
                Key={"agent_id": agent_id, "key_version": key_version},
                UpdateExpression="SET #status = :status, revoked_at = :revoked_at, revocation_reason = :reason",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":status": "revoked",
                    ":revoked_at": now,
                    ":reason": reason,
                },
            )

    def rotate(self, agent_id: str, new_public_key_b64: str) -> str:
        """Create the next numeric key version and mark the former version superseded."""
        metadata = self._active_metadata(agent_id)
        if metadata is None:
            raise KeyError(f"Unknown agent: {agent_id}")
        response = self._table.query(
            KeyConditionExpression=Key("agent_id").eq(agent_id), ConsistentRead=True
        )
        versions = {item["key_version"] for item in response["Items"]}
        version_number = 1
        while f"v{version_number}" in versions:
            version_number += 1
        new_version = f"v{version_number}"
        self._table.update_item(
            Key={"agent_id": agent_id, "key_version": metadata["active_version"]},
            UpdateExpression="SET #status = :status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":status": "superseded"},
        )
        self.register(agent_id, new_public_key_b64, new_version)
        return new_version
