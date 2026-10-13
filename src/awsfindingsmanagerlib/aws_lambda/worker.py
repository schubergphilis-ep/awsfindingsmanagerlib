"""SQS-triggered Lambda handler.

Each SQS record carries a single-rule rules document (as produced by
`awsfindingsmanagerlib.aws_lambda.trigger`): applies that rule against all currently matching Security Hub
findings.

Failures are reported per record via SQS's partial batch response contract
(`{"batchItemFailures": [...]}`), not by raising: a failed record becomes visible again after the
queue's visibility timeout and is retried (and eventually sent to the dead-letter queue per the
queue's redrive policy) without the whole batch, including already-successful records, being
reprocessed. This requires `function_response_types = ["ReportBatchItemFailures"]` to be set on
the event source mapping; without it, Lambda ignores this return value and deletes the entire
batch regardless of these results.
"""

import json
from typing import Any

from awsfindingsmanagerlib import Manager
from awsfindingsmanagerlib.aws_lambda.clients import get_securityhub_client
from awsfindingsmanagerlib.aws_lambda.logging import get_logger

LOGGER = get_logger()


@LOGGER.inject_lambda_context()
def lambda_handler(
    event: dict[str, Any], _context: object
) -> dict[str, list[dict[str, str]]]:
    """Apply the suppression rule carried by each SQS record to matching Security Hub findings.

    Parameters
    ----------
    event : dict[str, Any]
        The SQS event. Each `event["Records"]` entry's `body` is expected to be a JSON-encoded
        rules document with exactly one rule in its `Rules` list.
    _context : object
        The Lambda context object (unused).

    Returns
    -------
    dict[str, list[dict[str, str]]]
        `{"batchItemFailures": [{"itemIdentifier": <messageId>}, ...]}`, naming only the records
        that failed to process. Requires `function_response_types = ["ReportBatchItemFailures"]`
        on the SQS event source mapping to take effect.
    """
    batch_item_failures: list[dict[str, str]] = []

    for record in event.get("Records", []):
        try:
            rule = json.loads(record["body"])
            manager = Manager.from_rules_document(rule, get_securityhub_client())
            manager.get_and_update_all()
        except Exception:
            LOGGER.exception(
                "Failed to process rule from SQS record %s.", record.get("messageId")
            )
            batch_item_failures.append({"itemIdentifier": record["messageId"]})

    return {"batchItemFailures": batch_item_failures}
