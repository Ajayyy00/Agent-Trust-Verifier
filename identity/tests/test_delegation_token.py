from identity.delegation_token import (
    DelegationToken,
    is_depth_valid,
    is_expired,
    to_signable_dict,
)


def _token(**overrides: object) -> DelegationToken:
    fields: dict[str, object] = {
        "token_id": "dtok_test",
        "subject_agent_id": "agent-a",
        "max_scope": ["read:financials"],
        "delegation_depth": 1,
        "max_delegation_depth": 1,
        "expiry": 2_000,
        "issuer_key_id": "root-v1",
        "issuer_signature": "signature",
    }
    fields.update(overrides)
    return DelegationToken(**fields)  # type: ignore[arg-type]


def test_expiry_boundaries() -> None:
    assert not is_expired(_token(expiry=2_000), now=1_999)
    assert is_expired(_token(expiry=2_000), now=2_000)


def test_depth_validity() -> None:
    assert is_depth_valid(_token(delegation_depth=1, max_delegation_depth=1))
    assert not is_depth_valid(_token(delegation_depth=2, max_delegation_depth=1))


def test_signable_dict_excludes_signature_and_is_stable() -> None:
    token = _token()

    first = to_signable_dict(token)
    second = to_signable_dict(token)

    assert first == second
    assert "issuer_signature" not in first
    assert first["max_scope"] == ["read:financials"]
