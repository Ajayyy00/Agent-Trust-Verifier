from concurrent.futures import ThreadPoolExecutor

from storage.tests.helpers import create_test_tables
from verifier.dynamo_replay_store import DynamoReplayStore


def test_dynamo_replay_store_consumes_a_nonce_once() -> None:
    mock, tables = create_test_tables()
    try:
        store = DynamoReplayStore(tables["replay"])

        assert store.consume("agent-b", "nonce-1")
        assert not store.consume("agent-b", "nonce-1")
        assert store.consume("agent-b", "nonce-2")
        assert store.consume("agent-c", "nonce-1")
    finally:
        mock.stop()


def test_concurrent_dynamo_nonce_consumption_has_exactly_one_winner() -> None:
    mock, tables = create_test_tables()
    try:
        store = DynamoReplayStore(tables["replay"])
        with ThreadPoolExecutor(max_workers=8) as executor:
            outcomes = list(executor.map(lambda _: store.consume("agent-b", "same"), range(16)))

        assert outcomes.count(True) == 1
        assert outcomes.count(False) == 15
    finally:
        mock.stop()
