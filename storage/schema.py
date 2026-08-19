"""DynamoDB table names and key-schema definitions."""

import os

REPLAY_TABLE = os.getenv("REPLAY_TABLE", "agent-trust-replay")
IDENTITY_TABLE = os.getenv("IDENTITY_TABLE", "agent-trust-identity")
AUDIT_TABLE = os.getenv("AUDIT_TABLE", "agent-trust-audit")
REPUTATION_TABLE = os.getenv("REPUTATION_TABLE", "agent-trust-reputation")

REPLAY_KEY_SCHEMA = [{"AttributeName": "nonce_key", "KeyType": "HASH"}]
IDENTITY_KEY_SCHEMA = [
    {"AttributeName": "agent_id", "KeyType": "HASH"},
    {"AttributeName": "key_version", "KeyType": "RANGE"},
]
AUDIT_KEY_SCHEMA = [{"AttributeName": "instruction_id", "KeyType": "HASH"}]
AUDIT_GLOBAL_SECONDARY_INDEXES = [
    {
        "IndexName": "issuer-index",
        "KeySchema": [{"AttributeName": "issuer", "KeyType": "HASH"}],
        "Projection": {"ProjectionType": "ALL"},
    },
    {
        "IndexName": "target-index",
        "KeySchema": [{"AttributeName": "target", "KeyType": "HASH"}],
        "Projection": {"ProjectionType": "ALL"},
    },
]
REPUTATION_KEY_SCHEMA = [{"AttributeName": "agent_id", "KeyType": "HASH"}]
