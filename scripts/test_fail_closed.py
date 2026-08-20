"""Live-only fail-closed audit validation for a deployed demo API.

This is intentionally not part of pytest. It uses the gated test-only audit
chaos route to simulate an unavailable audit backend, then proves a valid
instruction returns an HTTP 200 security rejection with ``AUDIT_FAILURE``.
The route is always reset in ``finally``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from verifier.result import AUDIT_FAILURE


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run live fail-closed audit validation"
    )
    parser.add_argument("--base-url", required=True)
    args = parser.parse_args()

    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=30.0) as client:
        try:
            enable = client.post("/test/chaos/audit", json={"fail_next": True})
            enable.raise_for_status()
            response = client.post("/demo/send-valid")
            body = response.json()
        finally:
            disable = client.post("/test/chaos/audit", json={"fail_next": False})
            disable.raise_for_status()

    print(f"HTTP status: {response.status_code}")
    print(f"accepted: {body.get('accepted')}")
    print(f"reason_code: {body.get('reason_code')}")
    if (
        response.status_code != 200
        or body.get("accepted") is not False
        or body.get("reason_code") != AUDIT_FAILURE
    ):
        raise AssertionError("Fail-closed audit invariant failed")
    print(
        "PASS: audit backend failure was returned as AUDIT_FAILURE, not a 500 or acceptance."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
