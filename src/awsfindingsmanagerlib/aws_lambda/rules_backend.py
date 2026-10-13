"""Load suppression rules for AWS Lambda use."""

import os
from pathlib import Path
from typing import Any

from botocore.client import BaseClient

try:
    from yaml import safe_load
except ImportError as error:
    msg = (
        "pyyaml is required to use awsfindingsmanagerlib.aws_lambda handlers. "
        "Install it with the 'lambda' extra, e.g. `uv add 'awsfindingsmanagerlib[lambda]'` "
        "or `pip install 'awsfindingsmanagerlib[lambda]'`."
    )
    raise ImportError(msg) from error


def load_rules(s3_client: BaseClient | None = None) -> dict[str, Any]:
    """Load the rules document, from S3 if configured, otherwise from a local file.

    If both the `S3_BUCKET_NAME` and `S3_OBJECT_NAME` environment variables are set, the rules
    document is loaded from that S3 object. Otherwise, it is loaded from the local file at
    `RULES_PATH` (defaults to `rules.yaml`).

    Parameters
    ----------
    s3_client : BaseClient, optional
        The boto3 S3 client to use when loading rules from S3. Only used (and required) when
        `S3_BUCKET_NAME` and `S3_OBJECT_NAME` are both set. Accepting it as a parameter, rather
        than creating one internally, keeps this function free of AWS calls in unit tests.

    Returns
    -------
    dict[str, Any]
        The parsed rules document, expected to contain a top-level `Rules` key and optionally a
        `ManagerConfig` key. See `awsfindingsmanagerlib.Manager.from_rules_document` for turning this into a
        ready-to-use `Manager`.

    Raises
    ------
    ValueError
        If S3 loading is configured but no `s3_client` was provided.
    """
    bucket_name = os.environ.get("S3_BUCKET_NAME")
    object_name = os.environ.get("S3_OBJECT_NAME")

    if bucket_name and object_name:
        if s3_client is None:
            msg = (
                "S3_BUCKET_NAME and S3_OBJECT_NAME are set, but no s3_client was provided "
                "to load_rules()."
            )
            raise ValueError(msg)
        response = s3_client.get_object(Bucket=bucket_name, Key=object_name)
        return safe_load(response["Body"].read())

    rules_path = os.environ.get("RULES_PATH", "rules.yaml")
    with Path(rules_path).open() as file:
        return safe_load(file)
