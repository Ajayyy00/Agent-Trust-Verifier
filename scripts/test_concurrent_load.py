"""Live-only replay-concurrency validation for a deployed Agent Trust Verifier.

This is intentionally not part of pytest: it provisions a temporary identity
through the deployment's gated ``/test/bootstrap`` route, then sends the exact
same signed instruction concurrently to the real API. It asserts that exactly
one request is accepted and every other request is rejected as a replay.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from redteam.attacks import _instruction_payload, create_attack_context
from verifier.result import ACCEPTED, REPLAY_DETECTED

_TRANSIENT_STATUS_CODES = {429, 503, 504}
_MAX_TRANSPORT_ATTEMPTS = 5


async def post_with_transient_retry(
    client: httpx.AsyncClient, payload: dict
) -> httpx.Response:
    """Retry API/Lambda capacity failures without changing the signed payload."""
    response: httpx.Response | None = None
    for attempt in range(_MAX_TRANSPORT_ATTEMPTS):
        response = await client.post("/instruction/verify", json=payload)
        if response.status_code not in _TRANSIENT_STATUS_CODES:
            return response
        if attempt < _MAX_TRANSPORT_ATTEMPTS - 1:
            await asyncio.sleep(0.15 * (2**attempt))
    assert response is not None
    return response


async def run(base_url: str, requests: int) -> None:
    """Submit one signed instruction concurrently and assert replay invariants."""
    with httpx.Client(base_url=base_url, timeout=20.0) as bootstrap_client:
        context = create_attack_context(bootstrap_client)
        instruction = context.new_instruction()
        payload = _instruction_payload(instruction)

    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
        responses = await asyncio.gather(
            *(post_with_transient_retry(client, payload) for _ in range(requests))
        )

    bodies = [response.json() for response in responses]
    accepted = sum(
        response.status_code == 200 and body.get("reason_code") == ACCEPTED
        for response, body in zip(responses, bodies)
    )
    replays = sum(
        response.status_code == 200 and body.get("reason_code") == REPLAY_DETECTED
        for response, body in zip(responses, bodies)
    )
    unexpected = [
        {"status": response.status_code, "reason_code": body.get("reason_code")}
        for response, body in zip(responses, bodies)
        if body.get("reason_code") not in {ACCEPTED, REPLAY_DETECTED}
        or response.status_code != 200
    ]

    print(f"Concurrent submissions: {requests}")
    print(f"Accepted: {accepted}")
    print(f"Replay detected: {replays}")
    if unexpected:
        print(f"Unexpected responses: {unexpected}")
    if accepted != 1 or replays != requests - 1 or unexpected:
        raise AssertionError("Replay protection invariant failed")
    print("PASS: exactly one nonce consumer won; all others were rejected as replays.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run live replay-concurrency validation"
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--requests", type=int, default=20)
    args = parser.parse_args()
    if args.requests < 2:
        parser.error("--requests must be at least 2")
    asyncio.run(run(args.base_url.rstrip("/"), args.requests))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
