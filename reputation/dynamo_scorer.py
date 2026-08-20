"""DynamoDB-backed advisory reputation scoring."""

from typing import Any

from .scorer import (
    BASELINE_SCORE,
    HEIGHTENED_SCRUTINY_THRESHOLD,
    OUTCOME_WEIGHTS,
)


class DynamoReputationService:
    """Atomically track advisory scores with DynamoDB ADD updates."""

    def __init__(self, table: Any) -> None:
        self._table = table

    def _ensure_agent(self, agent_id: str) -> None:
        try:
            self._table.put_item(
                Item={"agent_id": agent_id, "score": BASELINE_SCORE},
                ConditionExpression="attribute_not_exists(agent_id)",
            )
        except self._table.meta.client.exceptions.ConditionalCheckFailedException:
            pass

    @staticmethod
    def _clamp(score: int) -> int:
        return min(BASELINE_SCORE, max(0, score))

    def get_score(self, agent_id: str) -> int:
        """Return a bounded score, initializing unseen agents at the baseline."""
        self._ensure_agent(agent_id)
        response = self._table.get_item(Key={"agent_id": agent_id}, ConsistentRead=True)
        # ADD can transiently exceed bounds under concurrency; clamp every read as a safety net.
        return self._clamp(int(response["Item"]["score"]))

    def record_outcome(self, agent_id: str, reason_code: str) -> int:
        """Apply an outcome with atomic ADD, avoiding lost read-modify-write updates."""
        delta = OUTCOME_WEIGHTS.get(reason_code, 0)
        if delta == 0:
            return self.get_score(agent_id)
        self._ensure_agent(agent_id)
        response = self._table.update_item(
            Key={"agent_id": agent_id},
            UpdateExpression="ADD score :delta",
            ExpressionAttributeValues={":delta": delta},
            ReturnValues="UPDATED_NEW",
        )
        return self._clamp(int(response["Attributes"]["score"]))

    def get_risk_level(self, agent_id: str) -> str:
        """Return the advisory risk level for the stored score."""
        return (
            "HIGH"
            if self.get_score(agent_id) < HEIGHTENED_SCRUTINY_THRESHOLD
            else "NORMAL"
        )

    def requires_review(self, agent_id: str) -> bool:
        """Return whether the agent's advisory score warrants review."""
        return self.get_risk_level(agent_id) == "HIGH"
