"""S3-triggered Lambda handler.

Fired when the rules document is uploaded to S3. Loads the rules and fans each one out as its
own message on SQS, carrying the shared `ManagerConfig` alongside it, so that the worker Lambda
(`awsfindingsmanagerlib.aws_lambda.worker`) can build an equivalent single-rule Manager for it.

Unlike `events.lambda_handler`, failures here are raised rather than swallowed: there is no
downstream Step Function branching on this handler's result, and a failure to queue rules should
be visible (e.g. via a Lambda error metric alarm) rather than silently skipped.
"""

import json
import os
from typing import Any

from awsfindingsmanagerlib.aws_lambda.clients import get_s3_client, get_sqs_client
from awsfindingsmanagerlib.aws_lambda.logging import get_logger
from awsfindingsmanagerlib.aws_lambda.rules_backend import load_rules

LOGGER = get_logger()


@LOGGER.inject_lambda_context()
def lambda_handler(_event: dict[str, Any], _context: object) -> None:
    """Load the configured rules and place each one on SQS for the worker Lambda to apply.

    Reads the destination queue URL from the `SQS_QUEUE_URL` environment variable.

    Raises
    ------
    Exception
        Re-raises any failure to load the rules or send a message to SQS, after logging it.
    """
    try:
        rules = load_rules(s3_client=get_s3_client())
        manager_config = rules.get("ManagerConfig", {})
        queue_url = os.environ.get("SQS_QUEUE_URL")
        sqs = get_sqs_client()

        for rule in rules.get("Rules", []):
            message_body = json.dumps(
                {"ManagerConfig": manager_config, "Rules": [rule]}
            )
            LOGGER.info("Putting rule on SQS. Rule details: %s", message_body)
            sqs.send_message(QueueUrl=queue_url, MessageBody=message_body)
    except Exception:
        LOGGER.exception("Failed putting rule(s) on SQS.")
        raise
