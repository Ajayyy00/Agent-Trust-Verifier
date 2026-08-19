"""Tests for agents/business_actions.py — no LLM calls, no network."""

import pytest

from agents.business_actions import ACTIONS, UnknownActionError, execute_action


def test_generate_report_returns_expected_stub_output() -> None:
    result = execute_action(
        "finance:report:generate",
        {"period": "Q3-2024", "account_id": "ACC-001"},
    )
    assert "Q3-2024" in result
    assert "ACC-001" in result


def test_process_refund_returns_expected_stub_output() -> None:
    result = execute_action(
        "finance:payment:refund",
        {"amount": "150.00", "account_id": "ACC-002"},
    )
    assert "150.00" in result
    assert "ACC-002" in result


def test_known_actions_with_empty_params_do_not_crash() -> None:
    for action in ACTIONS:
        result = execute_action(action, {})
        assert isinstance(result, str)


def test_unknown_action_raises_loudly() -> None:
    with pytest.raises(UnknownActionError, match="not in the business-action registry"):
        execute_action("finance:report:delete", {"account_id": "ACC-001"})


def test_unknown_action_error_message_names_the_action() -> None:
    action = "admin:user:delete"
    with pytest.raises(UnknownActionError, match=action):
        execute_action(action, {})
