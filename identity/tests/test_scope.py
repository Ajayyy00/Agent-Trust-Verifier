import pytest

from identity.scope import is_action_within_scope


@pytest.mark.parametrize(
    ("action", "granted_scopes", "expected"),
    [
        ("read:financials", ["read:financials"], True),
        ("read:financials:summary", ["read:financials"], True),
        ("write:financials", ["read:financials"], False),
        ("read:financials_extra", ["read:financials"], False),
        ("read:financials:summary:daily", ["read:financials"], True),
        ("read:financials", [], False),
        ("finance:report:generate", ["finance:report:generate"], True),
        ("finance:reports:generate", ["finance:report"], False),
    ],
)
def test_action_scope_containment(
    action: str, granted_scopes: list[str], expected: bool
) -> None:
    assert is_action_within_scope(action, granted_scopes) is expected
