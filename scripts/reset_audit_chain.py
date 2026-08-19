"""Destructively reset the deployed demo audit table.

This manual integration utility is not part of pytest. It resolves the
``AuditTable`` CloudFormation resource for the selected stack and deletes every
item from only that table. Pass ``--yes`` to acknowledge the deletion.
"""

from __future__ import annotations

import argparse
import os

import boto3


def resolve_audit_table_name(cloudformation, stack_name: str) -> str:
    """Resolve the physical audit table from its CloudFormation logical ID."""
    paginator = cloudformation.get_paginator("list_stack_resources")
    for page in paginator.paginate(StackName=stack_name):
        for resource in page["StackResourceSummaries"]:
            if resource["LogicalResourceId"] == "AuditTable":
                return resource["PhysicalResourceId"]
    raise RuntimeError(f"AuditTable resource not found in stack {stack_name!r}")


def delete_all_items(table) -> int:
    """Scan all pages and batch-delete exact audit-table primary keys."""
    deleted = 0
    scan_kwargs: dict[str, object] = {}
    while True:
        page = table.scan(**scan_kwargs)
        with table.batch_writer() as batch:
            for item in page.get("Items", []):
                batch.delete_item(Key={"instruction_id": item["instruction_id"]})
                deleted += 1
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return deleted
        scan_kwargs["ExclusiveStartKey"] = last_key


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset the deployed demo audit chain")
    parser.add_argument("--stack-name", default="agent-trust-verifier")
    parser.add_argument("--region", default=os.getenv("AWS_REGION", "eu-north-1"))
    parser.add_argument("--yes", action="store_true", help="Confirm deletion of every audit record")
    args = parser.parse_args()
    if not args.yes:
        parser.error("Refusing to delete audit data without --yes")

    session = boto3.session.Session(region_name=args.region)
    table_name = resolve_audit_table_name(session.client("cloudformation"), args.stack_name)
    deleted = delete_all_items(session.resource("dynamodb").Table(table_name))
    print(f"Reset audit table {table_name}: deleted {deleted} item(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
