import pytest

from storage.backend import (
    get_audit_service,
    get_key_registry,
    get_replay_store,
    get_reputation_service,
)
from verifier.replay_store import ReplayStore


def test_memory_is_the_default_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STORAGE_BACKEND", raising=False)

    assert isinstance(get_replay_store(), ReplayStore)
    assert get_key_registry().__class__.__name__ == "KeyRegistry"
    assert get_audit_service().__class__.__name__ == "AuditService"
    assert get_reputation_service().__class__.__name__ == "ReputationService"


def test_invalid_backend_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STORAGE_BACKEND", "invalid")

    with pytest.raises(ValueError, match="STORAGE_BACKEND"):
        get_replay_store()
