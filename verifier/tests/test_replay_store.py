from verifier.replay_store import ReplayStore


def test_first_nonce_consumption_succeeds_then_replay_fails() -> None:
    store = ReplayStore()

    assert store.consume("agent-b", "nonce-1")
    assert not store.consume("agent-b", "nonce-1")


def test_different_nonces_for_same_target_succeed() -> None:
    store = ReplayStore()

    assert store.consume("agent-b", "nonce-1")
    assert store.consume("agent-b", "nonce-2")


def test_nonce_is_namespaced_by_target() -> None:
    store = ReplayStore()

    assert store.consume("agent-b", "nonce-1")
    assert store.consume("agent-c", "nonce-1")
