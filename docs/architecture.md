# Agent Trust Verifier Architecture

This document outlines the cryptographic invariants and fail-safe defaults underpinning the Agent Trust Verifier.

## Core Guarantees
The system acts as a stateless validation boundary ensuring all agent-driven actions are cryptographically authenticated, authorized within bounded scopes, and durably audited before execution.

## Fail-Safe Defaults

The system is designed to fail closed. In the event of a component failure, anomaly, or ambiguity, the verifier defaults to rejection.

| Failure Mode | Default Action | Reason Code |
| :--- | :--- | :--- |
| Missing or malformed signature | Reject | `INVALID_SIGNATURE` |
| Token expired or not yet valid | Reject | `TOKEN_EXPIRED` / `FUTURE_TIMESTAMP` |
| Action outside delegated scope | Reject | `TOKEN_SCOPE_DENIED` |
| Agent revocation or key mismatch | Reject | `AGENT_REVOKED` / `UNKNOWN_KEY` |
| Duplicate instruction nonce | Reject | `REPLAY_DETECTED` |
| Audit backend unreachable/failure | Reject | `AUDIT_FAILURE` |

## Final Invariant
**No instruction shall be executed unless it has been cryptographically proven authentic, strictly within its delegated scope, and durably recorded in the immutable audit ledger.**

## What This Project Does Not Claim

- It does not make an LLM safe, truthful, or immune to prompt injection.
- It does not decide whether an authorized business action is wise, correct, or compliant with every policy.
- It does not replace application authentication, authorization, secret management, monitoring, or human approval where those controls are needed.
- It does not claim production-scale availability, a complete compliance programme, or interoperability with every agent framework.
- It demonstrates a verification boundary: it proves who signed a structured instruction, what scope was delegated, and whether the decision was durably recorded before execution.
