"""DynamoDB-backed replay protection."""

from typing import Any

from botocore.exceptions import ClientError


class DynamoReplayStore:
    """Atomically consume instruction nonces using DynamoDB conditional writes."""

    def __init__(self, table: Any) -> None:
        self._table = table

    def consume(self, target_agent_id: str, nonce: str) -> bool:
        """Return True once per target/nonce pair and False for all replays."""
        nonce_key = f"{target_agent_id}:{nonce}"
        try:
            self._table.put_item(
                Item={"nonce_key": nonce_key},
                ConditionExpression="attribute_not_exists(nonce_key)",
            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise
        return True

