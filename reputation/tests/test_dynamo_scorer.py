"""DynamoDB-backed reputation scorer tests — interface-parity mirror of test_scorer.py,
plus a concurrency test proving atomic ADD prevents lost updates.
"""

from concurrent.futures import ThreadPoolExecutor

import pytest

from reputation.dynamo_scorer import DynamoReputationService
from reputation.scorer import (
    BASELINE_SCORE,
    HEIGHTENED_SCRUTINY_THRESHOLD,
    OUTCOME_WEIGHTS,
)
from storage.tests.helpers import create_test_tables
from verifier.result import ACCEPTED, AGENT_REVOKED, AUDIT_FAILURE, INVALID_SIGNATURE

# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def service_and_mock():
    mock, tables = create_test_tables()
    yield DynamoReputationService(tables["reputation"])
    mock.stop()


# ---------------------------------------------------------------------------
# Interface-parity tests (mirror of test_scorer.py)
# ---------------------------------------------------------------------------


def test_new_agent_starts_at_baseline_score(
    service_and_mock: DynamoReputationService,
) -> None:
    assert service_and_mock.get_score("agent-a") == 100


@pytest.mark.parametrize("reason_code, weight", OUTCOME_WEIGHTS.items())
def test_outcome_weights_are_applied_exactly(
    reason_code: str, weight: int, service_and_mock: DynamoReputationService
) -> None:
    assert service_and_mock.record_outcome("agent-a", reason_code) == min(
        BASELINE_SCORE, BASELINE_SCORE + weight
    )


def test_accepted_outcomes_never_exceed_baseline(
    service_and_mock: DynamoReputationService,
) -> None:
    service = service_and_mock
    for _ in range(10):
        service.record_outcome("agent-a", ACCEPTED)

    assert service.get_score("agent-a") == BASELINE_SCORE


def test_severe_penalties_never_drop_below_zero(
    service_and_mock: DynamoReputationService,
) -> None:
    service = service_and_mock
    for _ in range(10):
        service.record_outcome("agent-a", INVALID_SIGNATURE)

    assert service.get_score("agent-a") == 0


def test_risk_level_respects_the_exact_threshold_boundary(
    service_and_mock: DynamoReputationService,
) -> None:
    service = service_and_mock
    service.record_outcome("agent-a", INVALID_SIGNATURE)
    service.record_outcome("agent-a", "WRONG_AUDIENCE")

    assert service.get_score("agent-a") == HEIGHTENED_SCRUTINY_THRESHOLD
    assert service.get_risk_level("agent-a") == "NORMAL"
    service.record_outcome("agent-a", "FUTURE_TIMESTAMP")
    assert service.get_score("agent-a") == HEIGHTENED_SCRUTINY_THRESHOLD - 5
    assert service.get_risk_level("agent-a") == "HIGH"


def test_revocation_and_audit_failures_do_not_change_score(
    service_and_mock: DynamoReputationService,
) -> None:
    service = service_and_mock
    service.record_outcome("agent-a", INVALID_SIGNATURE)
    score_before = service.get_score("agent-a")

    assert service.record_outcome("agent-a", AGENT_REVOKED) == score_before
    assert service.record_outcome("agent-a", AUDIT_FAILURE) == score_before


def test_agents_have_independent_scores(
    service_and_mock: DynamoReputationService,
) -> None:
    service = service_and_mock
    service.record_outcome("agent-a", INVALID_SIGNATURE)
    service.record_outcome("agent-a", INVALID_SIGNATURE)

    assert service.get_risk_level("agent-a") == "HIGH"
    assert service.get_score("agent-b") == BASELINE_SCORE


def test_requires_review_reflects_risk_level(
    service_and_mock: DynamoReputationService,
) -> None:
    service = service_and_mock
    # Fresh agent should not require review
    assert not service.requires_review("agent-a")
    # Drive score below threshold
    for _ in range(10):
        service.record_outcome("agent-a", INVALID_SIGNATURE)
    assert service.requires_review("agent-a")


# ---------------------------------------------------------------------------
# Concurrency test: atomic ADD prevents lost updates
# ---------------------------------------------------------------------------


def test_concurrent_reputation_updates_have_no_lost_writes() -> None:
    """Fire many concurrent record_outcome() calls using real threads against the
    mocked DynamoDB table and assert the final score matches the exact sum of all
    applied deltas — proving that DynamoDB's atomic ADD prevents the lost-update
    race condition that a GetItem-then-PutItem pattern would silently introduce.
    """
    mock, tables = create_test_tables()
    try:
        service = DynamoReputationService(tables["reputation"])
        # Initialise the agent so the baseline is written before threads race.
        service.get_score("agent-concurrent")

        # Each ACCEPTED call applies +1; run 50 of them concurrently.
        n_calls = 50
        reason_code = ACCEPTED  # weight = +1 per call
        with ThreadPoolExecutor(max_workers=10) as executor:
            list(
                executor.map(
                    lambda _: service.record_outcome("agent-concurrent", reason_code),
                    range(n_calls),
                )
            )

        # The ACCEPTED weight is +1, but score is clamped to BASELINE_SCORE (100).
        # The agent started at 100, so every +1 is a no-op after clamping.
        # To test lost updates properly, use INVALID_SIGNATURE (weight = -40).
        # Reset and redo with a weight that actually moves the needle.
        mock.stop()

        mock2, tables2 = create_test_tables()
        try:
            service2 = DynamoReputationService(tables2["reputation"])
            # Drive below 0 to test floor clamping, but first test no-lost-update
            # with a modest penalty so the score stays in (0, 100).
            service2.get_score("agent-race")

            # Use STALE_INSTRUCTION (weight -5), 10 calls: 100 - 10*5 = 50 exactly.
            n_stale = 10
            stale_weight = OUTCOME_WEIGHTS["STALE_INSTRUCTION"]  # -5

            with ThreadPoolExecutor(max_workers=10) as executor:
                list(
                    executor.map(
                        lambda _: service2.record_outcome(
                            "agent-race", "STALE_INSTRUCTION"
                        ),
                        range(n_stale),
                    )
                )

            final_raw_score = service2._table.get_item(
                Key={"agent_id": "agent-race"}, ConsistentRead=True
            )["Item"]["score"]
            expected_unclamped = (
                BASELINE_SCORE + n_stale * stale_weight
            )  # 100 + 10*(-5) = 50

            # The raw DynamoDB value equals the exact sum — no lost updates.
            assert int(final_raw_score) == expected_unclamped, (
                f"Lost update detected: expected {expected_unclamped}, "
                f"got {final_raw_score}"
            )
            # The clamped read-side score also matches.
            assert service2.get_score("agent-race") == expected_unclamped
        finally:
            mock2.stop()
    except Exception:
        try:
            mock.stop()
        except Exception:  # noqa: S110, BLE001 - preserve the original test error
            pass
        raise
