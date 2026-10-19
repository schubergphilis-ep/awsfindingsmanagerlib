"""Lazily-created, cached boto3 clients shared across Lambda handlers.

Creating these lazily (rather than as module-level constants) means importing a handler module
never requires AWS credentials or network access, which keeps the handlers unit-testable.
"""

from functools import cache

import boto3
from botocore.client import BaseClient


@cache
def get_securityhub_client() -> BaseClient:
    """Return a cached boto3 Security Hub client, created on first use."""
    return boto3.client("securityhub")


@cache
def get_s3_client() -> BaseClient:
    """Return a cached boto3 S3 client, created on first use."""
    return boto3.client("s3")


@cache
def get_sqs_client() -> BaseClient:
    """Return a cached boto3 SQS client, created on first use."""
    return boto3.client("sqs")
