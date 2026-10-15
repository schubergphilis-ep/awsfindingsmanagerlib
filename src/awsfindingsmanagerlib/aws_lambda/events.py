"""EventBridge-triggered Lambda handler.

Suppresses findings carried by a "Security Hub Findings - Imported" EventBridge event.

Returns `{"finding_state": "suppressed"}` or `{"finding_state": "skipped"}` and never raises, so
that a Step Function orchestrating this handler ahead of a ticketing integration can branch on
the result: `terraform-aws-mcaf-securityhub-findings-manager` relies on exactly this contract to
decide whether a finding still needs a Jira ticket after this handler has run.
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
def lambda_handler(event: dict[str, Any], _context: object) -> dict[str, str]:
    """Suppress the findings carried by an EventBridge "Security Hub Findings - Imported" event.

    Parameters
    ----------
    event : dict[str, Any]
        The EventBridge event. `event["detail"]["findings"]` is expected to be a list of Security
        Hub finding dicts.
    _context : object
        The Lambda context object (unused).

    Returns
    -------
    dict[str, str]
        `{"finding_state": "suppressed"}` if at least one finding matched a rule and all matching
        updates were processed successfully, `{"finding_state": "skipped"}` otherwise (no rule
        matched, the manager could not be initialized, or an update failed).
    """
    findings = event.get("detail", {}).get("findings", [])

    try:
        manager = Manager.from_rules_document(
            load_rules(s3_client=get_s3_client()), get_securityhub_client()
        )
    except Exception:
        LOGGER.exception("Failed to initialize the findings manager; skipping.")
        return {"finding_state": "skipped"}

    matched_any = False
    processed_all = True

    for finding in findings:
        try:
            result = manager.process_finding(finding)
        except Exception:
            LOGGER.exception("Failed to process a finding; skipping it.")
            processed_all = False
            continue

        matched_any = matched_any or result.matched_rules > 0
        processed_all = processed_all and result.all_processed

    if matched_any and processed_all:
        LOGGER.info("Successfully suppressed matching finding(s).")
        return {"finding_state": "suppressed"}

    LOGGER.info(
        "No finding(s) were suppressed (no rule matched, or an update could not be processed)."
    )
    return {"finding_state": "skipped"}
