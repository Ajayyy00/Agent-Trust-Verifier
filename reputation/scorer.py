"""Storage-agnostic, advisory-only reputation scoring."""

from verifier.result import (
    ACCEPTED,
    FUTURE_TIMESTAMP,
    INVALID_SCHEMA,
    INVALID_SIGNATURE,
    POLICY_DENIED,
    REPLAY_DETECTED,
    STALE_INSTRUCTION,
    TOKEN_EXPIRED,
    TOKEN_SCOPE_DENIED,
    TOKEN_SIGNATURE_INVALID,
    TOKEN_SUBJECT_MISMATCH,
    UNKNOWN_KEY,
    WRONG_AUDIENCE,
)

BASELINE_SCORE = 100
HEIGHTENED_SCRUTINY_THRESHOLD = 50

OUTCOME_WEIGHTS: dict[str, int] = {
    INVALID_SIGNATURE: -40,
    TOKEN_SIGNATURE_INVALID: -40,
    TOKEN_SUBJECT_MISMATCH: -25,
    REPLAY_DETECTED: -30,
    TOKEN_SCOPE_DENIED: -20,
    POLICY_DENIED: -20,
    WRONG_AUDIENCE: -10,
    UNKNOWN_KEY: -15,
    TOKEN_EXPIRED: -5,
    STALE_INSTRUCTION: -5,
    FUTURE_TIMESTAMP: -5,
    INVALID_SCHEMA: -5,
    ACCEPTED: 1,
}


class ReputationService:
    """Track agent behavior as an advisory signal, never an authorization decision."""

    def __init__(self) -> None:
        self._scores: dict[str, int] = {}

    def get_score(self, agent_id: str) -> int:
        """Return an agent's score, initializing unseen agents at the baseline."""
        return self._scores.setdefault(agent_id, BASELINE_SCORE)

    def record_outcome(self, agent_id: str, reason_code: str) -> int:
        """Apply the configured advisory outcome weight and return the bounded score."""
        score = self.get_score(agent_id)
        weight = OUTCOME_WEIGHTS.get(reason_code, 0)
        updated_score = min(BASELINE_SCORE, max(0, score + weight))
        self._scores[agent_id] = updated_score
        return updated_score

    def get_risk_level(self, agent_id: str) -> str:
        """Return the agent's advisory risk classification."""
        if self.get_score(agent_id) < HEIGHTENED_SCRUTINY_THRESHOLD:
            return "HIGH"
        return "NORMAL"

    def requires_review(self, agent_id: str) -> bool:
        """Return whether the advisory score warrants manual review."""
        return self.get_risk_level(agent_id) == "HIGH"
