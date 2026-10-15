"""Standalone scheduled Lambda handler.

Loads the configured rules (from S3, or a local file bundled in the deployment package) and
applies all of them against every currently matching Security Hub finding. Intended to be run on
a schedule (e.g. via an EventBridge rule) rather than triggered by individual finding or rules
events; see `awsfindingsmanagerlib.aws_lambda.events`, `.trigger` and `.worker` for the event-driven pipeline
used by `terraform-aws-mcaf-securityhub-findings-manager`.
"""

from typing import Any

from awsfindingsmanagerlib import Manager
from awsfindingsmanagerlib.aws_lambda.clients import (
    get_s3_client,
    get_securityhub_client,
)
from awsfindingsmanagerlib.aws_lambda.logging import get_logger
from awsfindingsmanagerlib.aws_lambda.rules_backend import load_rules

LOGGER = get_logger()


@LOGGER.inject_lambda_context()
def lambda_handler(_event: dict[str, Any], _context: object) -> None:
    """Apply all configured suppression rules to every currently matching Security Hub finding.

    Raises
    ------
    RuntimeError
        If not all matched findings could be successfully processed. Check the logged warnings
        above the raised error for which finding(s)/rule(s) were affected.
    """
    manager = Manager.from_rules_document(
        load_rules(s3_client=get_s3_client()), get_securityhub_client()
    )

    if not manager.get_and_update_all():
        msg = (
            "Not all findings were processed successfully; "
            "see the warnings logged above for details."
        )
        raise RuntimeError(msg)
