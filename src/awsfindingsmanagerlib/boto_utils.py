"""Boto-related utilities for awsfindingsmanagerlib."""

import sys
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Any

from botocore.client import BaseClient
from botocore.stub import Stubber
from jmespath import compile as jmespath_compile

# This only contains the special cases that are still relevant for the current finding format
# The network block and some severity members in the finding format are retired
# Sample member is also not included, because it is unlikely to be used in production
SPECIAL_CASES = {
    "Type": "Types[]",
    "SeverityLabel": "Severity.Label",
    "RecommendationText": "Remediation.Recommendation.Text",
    "MalwareName": "Malware[].Name",
    "MalwareType": "Malware[].Type",
    "MalwarePath": "Malware[].Path",
    "MalwareState": "Malware[].State",
    "ProcessName": "Process[].Name",
    "ProcessPath": "Process[].Path",
    "ProcessPid": "Process[].Pid",
    "ProcessParentPid": "Process[].ParentPid",
    "ProcessLaunchedAt": "Process[].LaunchedAt",
    "ProcessTerminatedAt": "Process[].TerminatedAt",
    "ThreatIntelIndicatorType": "ThreatIntelIndicators[].Type",
    "ThreatIntelIndicatorValue": "ThreatIntelIndicators[].Value",
    "ThreatIntelIndicatorCategory": "ThreatIntelIndicators[].Category",
    "ThreatIntelIndicatorLastObservedAt": "ThreatIntelIndicators[].LastObservedAt",
    "ThreatIntelIndicatorSource": "ThreatIntelIndicators[].Source",
    "ThreatIntelIndicatorSourceUrl": "ThreatIntelIndicators[].SourceUrl",
    "ResourceType": "Resources[].Type",
    "ResourceId": "Resources[].Id",
    "ResourcePartition": "Resources[].Partition",
    "ResourceRegion": "Resources[].Region",
    "ResourceTags": "Resources[].Tags",
    "ResourceAwsEc2InstanceType": "Resources[].Details.AwsEc2Instance.Type",
    "ResourceAwsEc2InstanceImageId": "Resources[].Details.AwsEc2Instance.ImageId",
    "ResourceAwsEc2InstanceIpV4Addresses": "Resources[].Details.AwsEc2Instance.IpV4Addresses[]",
    "ResourceAwsEc2InstanceIpV6Addresses": "Resources[].Details.AwsEc2Instance.IpV6Addresses[]",
    "ResourceAwsEc2InstanceKeyName": "Resources[].Details.AwsEc2Instance.KeyName",
    "ResourceAwsEc2InstanceIamInstanceProfileArn": "Resources[].Details.AwsEc2Instance.IamInstanceProfileArn",
    "ResourceAwsEc2InstanceVpcId": "Resources[].Details.AwsEc2Instance.VpcId",
    "ResourceAwsEc2InstanceSubnetId": "Resources[].Details.AwsEc2Instance.SubnetId",
    "ResourceAwsEc2InstanceLaunchedAt": "Resources[].Details.AwsEc2Instance.LaunchedAt",
    "ResourceAwsS3BucketOwnerId": "Resources[].Details.AwsS3Bucket.OwnerId",
    "ResourceAwsS3BucketOwnerName": "Resources[].Details.AwsS3Bucket.OwnerName",
    "ResourceAwsIamAccessKeyUserName": "Resources[].Details.AwsIamAccessKey.UserName",
    "ResourceAwsIamAccessKeyPrincipalName": "Resources[].Details.AwsIamAccessKey.PrincipalName",
    "ResourceAwsIamAccessKeyStatus": "Resources[].Details.AwsIamAccessKey.Status",
    "ResourceAwsIamAccessKeyCreatedAt": "Resources[].Details.AwsIamAccessKey.CreatedAt",
    "ResourceAwsIamUserUserName": "Resources[].Details.AwsIamUser.UserName",
    "ResourceContainerName": "Resources[].Details.Container.Name",
    "ResourceContainerImageId": "Resources[].Details.Container.ImageId",
    "ResourceContainerImageName": "Resources[].Details.Container.ImageName",
    "ResourceContainerLaunchedAt": "Resources[].Details.Container.LaunchedAt",
    "ResourceDetailsOther": "Resources[].Details.Other",
    "ComplianceStatus": "Compliance.Status",
    "WorkflowStatus": "Workflow.Status",
    "RelatedFindingsProductArn": "RelatedFindings[].ProductArn",
    "RelatedFindingsId": "RelatedFindings[].Id",
    "NoteText": "Note.Text",
    "NoteUpdatedAt": "Note.UpdatedAt",
    "NoteUpdatedBy": "Note.UpdatedBy",
    "FindingProviderFieldsConfidence": "FindingProviderFields.Confidence",
    "FindingProviderFieldsCriticality": "FindingProviderFields.Criticality",
    "FindingProviderFieldsRelatedFindingsId": "FindingProviderFields.RelatedFindings[].Id",
    "FindingProviderFieldsRelatedFindingsProductArn": "FindingProviderFields.RelatedFindings[].ProductArn",
    "FindingProviderFieldsSeverityLabel": "FindingProviderFields.Severity.Label",
    "FindingProviderFieldsSeverityOriginal": "FindingProviderFields.Severity.Original",
    "FindingProviderFieldsTypes": "FindingProviderFields.Types[]",
    "ComplianceSecurityControlId": "Compliance.SecurityControlId",
    "ComplianceAssociatedStandardsId": "Compliance.AssociatedStandards[].StandardsId",
    "VulnerabilitiesExploitAvailable": "Vulnerabilities[].ExploitAvailable",
    "VulnerabilitiesFixAvailable": "Vulnerabilities[].FixAvailable",
    "ComplianceSecurityControlParametersName": "Compliance.SecurityControlParameters[].Name",
    "ComplianceSecurityControlParametersValue": "Compliance.SecurityControlParameters[].Value[]",
    "ResourceApplicationName": "Resources[].ApplicationName",
    "ResourceApplicationArn": "Resources[].ApplicationArn",
}


SPECIAL_CASE_EXPRESSIONS = {
    name: jmespath_compile(path) for name, path in SPECIAL_CASES.items()
}


def _normalize_values(value: object) -> list[Any]:
    """Normalize to a list with only truthy values."""
    if isinstance(value, list):
        return [item for item in value if item]
    return [value] if value else []


def get_values_by_boto_argument(finding: dict, name: str) -> list[Any]:
    """Get the values in a finding for a given boto argument name.

    Some arguments in:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub/client/get_findings.html
    do not directly map to finding fields as per:
    https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
    Therefore, this method handles those special cases.
    The method returns a list to handle both single-value and multi-value fields.

    Parameters
    ----------
    finding : dict
        The finding to get the values from
    name : str
        The name to get the values for

    Returns
    -------
    list[Any]
        The values from the finding for the given name
    """
    if expression := SPECIAL_CASE_EXPRESSIONS.get(name):
        return _normalize_values(expression.search(finding))
    return _normalize_values(finding.get(name))


@dataclass
class BotoStubCall:
    """Dataclass representing the inputs needed to stub a boto call."""

    method: str
    service_response: Any
    expected_params: Any | None = None


@contextmanager
def stub_boto_client(
    boto_session_client: BaseClient, calls: list[BotoStubCall]
) -> Generator[Stubber, None, None]:
    """Generate a context in which a boto client is stubbed with the specified calls.

    This function saves you from writing the boilerplate code to create a Stubber like:
    https://botocore.amazonaws.com/v1/documentation/api/latest/reference/stubber.html.

    Use like this:
    ```python
    boto_client = botocore.session.get_session().create_client("servicename")
    call = BotoStubCall(
        method="get_resources",
        service_response={"Resources": {"arn": "abc"}},
        expected_params={"Filters": "filters"},
    )
    with stub_boto_client(boto_client, [call]) as _:
        boto_client.get_resources(Filters="filters")
    ```

    Or the last part slightly more dynamically like this:
    ```python
    with stub_boto_client(boto_client, [call]) as _:
        getattr(boto_client, call.method)(**call.expected_params)
    ```

    Parameters
    ----------
    boto_session_client : BaseClient
        The boto session BaseClient that will be stubbed
    calls : list[BotoStubCall]
        The list of BotoStubCall instances representing the calls to add to the stubber

    Yields
    ------
    Generator[Stubber, None, None]
        A generator yielding a Stubber instance with the specified calls added.
        Usually not needed to be used directly,
        because the stubbing is active on the original session client within the context as a side effect.
    """
    stubber = Stubber(boto_session_client)
    for call in calls:
        stubber.add_response(**asdict(call))
    stubber.activate()
    try:
        yield stubber
    finally:
        # Preserve the original exception raised inside the context (for example,
        # boto ParamValidationError) instead of masking it with pending stubs.
        if sys.exc_info()[0] is None:
            stubber.assert_no_pending_responses()
        stubber.deactivate()


def validate_call_params(
    boto_stub_calls: list[BotoStubCall],
    boto_session_client: BaseClient,
) -> None:
    """Validate boto call parameters by attempting to call the methods with the expected parameters in a stubbed context.

    Parameters
    ----------
    boto_stub_calls : list[BotoStubCall]
        The list of BotoStubCall instances representing the calls to validate
    boto_session_client : BaseClient
        The boto session BaseClient that will be used for validation

    Raises
    ------
    botocore.exceptions.ParamValidationError
        If any of the boto parameters contain invalid values
    """
    with stub_boto_client(
        boto_session_client,
        boto_stub_calls,
    ) as _:
        for response in boto_stub_calls:
            getattr(boto_session_client, response.method)(
                **(response.expected_params or {})
            )
