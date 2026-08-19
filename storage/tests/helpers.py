"""Moto table setup shared by DynamoDB backend tests."""

from typing import Any

import boto3
from moto import mock_aws

from storage.schema import AUDIT_TABLE, IDENTITY_TABLE, REPLAY_TABLE, REPUTATION_TABLE


def create_test_tables() -> tuple[Any, dict[str, Any]]:
    """Start Moto and return its resource plus every required DynamoDB table."""
    mock = mock_aws()
    mock.start()
    resource = boto3.resource("dynamodb", region_name="us-east-1")
    replay = resource.create_table(
        TableName=REPLAY_TABLE,
        KeySchema=[{"AttributeName": "nonce_key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "nonce_key", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    identity = resource.create_table(
        TableName=IDENTITY_TABLE,
        KeySchema=[
            {"AttributeName": "agent_id", "KeyType": "HASH"},
            {"AttributeName": "key_version", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "agent_id", "AttributeType": "S"},
            {"AttributeName": "key_version", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    audit = resource.create_table(
        TableName=AUDIT_TABLE,
        KeySchema=[{"AttributeName": "instruction_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "instruction_id", "AttributeType": "S"},
            {"AttributeName": "issuer", "AttributeType": "S"},
            {"AttributeName": "target", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
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
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    reputation = resource.create_table(
        TableName=REPUTATION_TABLE,
        KeySchema=[{"AttributeName": "agent_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "agent_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    return mock, {
        "replay": replay,
        "identity": identity,
        "audit": audit,
        "reputation": reputation,
    }
