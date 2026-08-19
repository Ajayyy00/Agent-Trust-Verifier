import pytest

from reputation.scorer import (
    HEIGHTENED_SCRUTINY_THRESHOLD,
    OUTCOME_WEIGHTS,
    ReputationService,
)
from verifier.result import ACCEPTED, AGENT_REVOKED, AUDIT_FAILURE, INVALID_SIGNATURE


def test_new_agent_starts_at_baseline_score() -> None:
    assert ReputationService().get_score("agent-a") == 100


@pytest.mark.parametrize("reason_code, weight", OUTCOME_WEIGHTS.items())
def test_outcome_weights_are_applied_exactly(reason_code: str, weight: int) -> None:
    service = ReputationService()

    assert service.record_outcome("agent-a", reason_code) == min(100, 100 + weight)


def test_accepted_outcomes_never_exceed_baseline() -> None:
    service = ReputationService()

    for _ in range(10):
        service.record_outcome("agent-a", ACCEPTED)

    assert service.get_score("agent-a") == 100


def test_severe_penalties_never_drop_below_zero() -> None:
    service = ReputationService()

    for _ in range(10):
        service.record_outcome("agent-a", INVALID_SIGNATURE)

    assert service.get_score("agent-a") == 0


def test_risk_level_respects_the_exact_threshold_boundary() -> None:
    service = ReputationService()
    service.record_outcome("agent-a", INVALID_SIGNATURE)
    service.record_outcome("agent-a", "WRONG_AUDIENCE")

    assert service.get_score("agent-a") == HEIGHTENED_SCRUTINY_THRESHOLD
    assert service.get_risk_level("agent-a") == "NORMAL"
    service.record_outcome("agent-a", "FUTURE_TIMESTAMP")
    assert service.get_score("agent-a") == HEIGHTENED_SCRUTINY_THRESHOLD - 5
    assert service.get_risk_level("agent-a") == "HIGH"


def test_revocation_and_audit_failures_do_not_change_score() -> None:
    service = ReputationService()
    service.record_outcome("agent-a", INVALID_SIGNATURE)
    score_before = service.get_score("agent-a")

    assert service.record_outcome("agent-a", AGENT_REVOKED) == score_before
    assert service.record_outcome("agent-a", AUDIT_FAILURE) == score_before


def test_agents_have_independent_scores() -> None:
    service = ReputationService()
    service.record_outcome("agent-a", INVALID_SIGNATURE)
    service.record_outcome("agent-a", INVALID_SIGNATURE)

    assert service.get_risk_level("agent-a") == "HIGH"
    assert service.get_score("agent-b") == 100
