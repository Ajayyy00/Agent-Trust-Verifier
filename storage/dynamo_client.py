"""Shared DynamoDB client and resource setup."""

import os
from typing import Any

import boto3


def get_dynamodb_resource() -> Any:
    """Return the configured DynamoDB resource for the selected AWS region."""
    return boto3.resource("dynamodb", region_name=os.getenv("AWS_REGION", "us-east-1"))
