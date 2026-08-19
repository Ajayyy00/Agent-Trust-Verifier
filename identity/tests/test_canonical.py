from identity.canonical import canonicalize


def test_different_key_order_produces_identical_bytes() -> None:
    assert canonicalize({"b": 2, "a": 1}) == canonicalize({"a": 1, "b": 2})


def test_signature_key_is_excluded_without_mutating_payload() -> None:
    payload = {"action": "read", "signature": "untrusted"}

    assert canonicalize(payload) == b'{"action":"read"}'
    assert payload["signature"] == "untrusted"


def test_nested_dicts_are_sorted() -> None:
    assert canonicalize({"outer": {"z": 1, "a": 2}}) == b'{"outer":{"a":2,"z":1}}'
