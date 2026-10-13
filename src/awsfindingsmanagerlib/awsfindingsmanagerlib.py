"""The main module of awsfindingsmanagerlib."""

import botocore.session
from botocore.client import BaseClient

from .boto_utils import (
    BotoStubCall,
    validate_call_params,
)


def _validate_call_params(
    stub_responses: list[BotoStubCall],
    session_client: BaseClient | None = None,
) -> None:
    if not session_client:
        session_client = botocore.session.get_session().create_client("securityhub")

    validate_call_params(stub_responses, session_client)


def validate_filters(filters: dict, session_client: BaseClient | None = None) -> None:
    """Validate AWS SecurityHub filters to get findings.

    Parameters
    ----------
    filters : dict
        The filters to validate
    session_client : BaseClient, optional
        A boto session BaseClient for AWS SecurityHub
        Tries to create one if not provided

    Raises
    ------
    botocore.exceptions.ParamValidationError
        If the filters contain invalid values
    """
    _validate_call_params(
        [
            BotoStubCall(
                method="get_findings",
                service_response={"Findings": []},
                expected_params={"Filters": filters},
            )
        ],
        session_client,
    )


def validate_updates(updates: dict, session_client: BaseClient | None = None) -> None:
    """Validate AWS SecurityHub updates to findings.

    Parameters
    ----------
    updates : dict
        The updates to make to (a set of) findings
    session_client : BaseClient, optional
        A boto session BaseClient for AWS SecurityHub
        Tries to create one if not provided

    Raises
    ------
    botocore.exceptions.ParamValidationError
        If the updates contain invalid values
    """
    _validate_call_params(
        [
            BotoStubCall(
                method="batch_update_findings",
                service_response={"ProcessedFindings": [], "UnprocessedFindings": []},
                expected_params=updates,
            )
        ],
        session_client,
    )
