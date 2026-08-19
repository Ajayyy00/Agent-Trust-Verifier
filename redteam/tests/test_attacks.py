"""Red-team scenarios executed against FastAPI's in-process TestClient."""

import pytest
from fastapi.testclient import TestClient

from api.main import app
from redteam.attacks import ATTACKS, create_attack_context


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("ALLOW_TEST_BOOTSTRAP", "1")
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda attack: attack.__name__)
def test_attack_is_caught(client: TestClient, attack) -> None:
    context = create_attack_context(client, app.state.trust_verifier.agent_id)

    result = attack(context)

    assert result["passed"] is True, result
