"""Tests for the API Gateway HTTP API Lambda authorizer."""

from api.authorizer import handler


def _event(path: str, authorization: str | None = None) -> dict:
    headers = {} if authorization is None else {"Authorization": authorization}
    return {"rawPath": path, "headers": headers}


def test_public_routes_bypass_administrative_auth(monkeypatch) -> None:
    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "0")
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)

    assert handler(_event("/health"), None) == {"isAuthorized": True}
    assert handler(_event("/instruction/verify"), None) == {"isAuthorized": True}


def test_protected_route_rejects_missing_or_invalid_key(monkeypatch) -> None:
    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "0")
    monkeypatch.setenv("ADMIN_API_KEY", "admin-test-key")

    assert handler(_event("/audit"), None) == {"isAuthorized": False}
    assert handler(_event("/audit", "wrong"), None) == {"isAuthorized": False}
    assert handler(_event("/audit", "admin-test-key"), None) == {"isAuthorized": True}


def test_demo_mode_bypasses_administrative_auth(monkeypatch) -> None:
    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "1")
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)

    assert handler(_event("/audit"), None) == {"isAuthorized": True}
