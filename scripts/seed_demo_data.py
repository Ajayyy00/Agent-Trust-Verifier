"""Provision demo Agent A/B identities through a deployed API's gated bootstrap route."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from identity.keygen import generate_keypair, serialize_public_key


def bootstrap(client: httpx.Client, subject_agent_id: str) -> dict:
    """Register a public key and receive the root-issued demo delegation token."""
    keypair = generate_keypair()
    response = client.post(
        "/test/bootstrap",
        json={
            "public_key": serialize_public_key(keypair.public_key),
            "subject_agent_id": subject_agent_id,
        },
    )
    response.raise_for_status()
    result = response.json()
    return {
        "agent_id": subject_agent_id,
        "key_version": result["key_version"],
        "delegation_token": result["delegation_token"],
        "public_key": serialize_public_key(keypair.public_key),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed demo identities through a deployed API"
    )
    parser.add_argument("--base-url", required=True, help="Deployed API base URL")
    args = parser.parse_args()

    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=15.0) as client:
        health = client.get("/health")
        health.raise_for_status()
        if health.json().get("status") != "healthy":
            raise RuntimeError(f"Deployment is not healthy: {health.json()}")

        try:
            agent_a = bootstrap(client, "agent_a")
            agent_b = bootstrap(client, "agent_b")
        except httpx.HTTPStatusError as error:
            if error.response.status_code == 403:
                raise RuntimeError(
                    "Bootstrap is disabled. Redeploy with AllowTestBootstrap=1 for this demo."
                ) from error
            raise

    print(f"Deployed API: {args.base_url.rstrip('/')}")
    print("Health: healthy")
    print("Agent A and Agent B public keys registered.")
    print("Agent A root-issued delegation token:")
    print(json.dumps(agent_a["delegation_token"], indent=2))
    print(f"Agent A key version: {agent_a['key_version']}")
    print(f"Agent B key version: {agent_b['key_version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
