# Welcome to awsfindingsmanagerlib

Rule-based Python library for managing and suppressing findings in AWS Security Hub and its integrated services

This library tries to stay as close to the boto3/API specifications as possible.
See [their documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html) for more information on low-level specifics.

Some quirks about the API worth mentioning for the usability of this library:

- This library uses the original `get_findings` boto3/API call, because it is the most versatile one.
  As such, string filters can only be `"EQUALS"|"PREFIX"|"NOT_EQUALS"|"PREFIX_NOT_EQUALS"`
  and map filters can only be `"EQUALS"|"NOT_EQUALS"`.
  See [the string filter API specs](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StringFilter.html)
  and [the map filter API specs](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_MapFilter.html)
  for more information.
- The boto3/API arguments don't always exactly match with finding fields.
  For example, the finding field `{"Severity":{"Label":"string"}}` becomes simply `SeverityLabel` as a filter field.
  Compare [the API specs](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html#API_GetFindings_RequestBody)
  with [the finding specs](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html)
  for more details.
- The `Cidr` attribute of the [IpFilter](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_IpFilter.html) works like a [StringFilter](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StringFilter.html) with `Value` set to the value for `Cidr` and `Comparison` set to `EQUALS`.

Things worth noting about the library itself.

- To make big rule files a little smaller and more readable rules can be create via a rule manager.
  The rule manager can have a default config for all rules created by it.
- Individual rules can still override the defaults set by the manager.
- All string filter fields can also filter values on regexes when set under `ExtraFeatures` > `RegexStringFilters`.
  This is not supported by the API, so it always happens in the logic of this library.
  See the code examples below on how to use it.
- Setting `jsonUpdate` mode under `ExtraFeatures` > `NoteTextConfig` enables a more structured way of storing notes.
  It allows for note preservation from other processes by merging existing JSON formatted note metadata.
  This requires setting a key under which to store the data in the JSON object.
  This is particularly useful when integrating with ticketing systems or when multiple teams manage findings.
  When a note is empty, this mode will create a new JSON note like: `{"Note":"Suppress SSM.7 findings"}`.
  Existing notes in plain text (non-JSON-formatted) will be overwritten, the previous note will be captured in the logs.
  When there is an existing JSON-formatted note, this mode will update only the key it manages in that note like: `{"jiraIssue":"PROJ-123","Note":"Suppress SSM.7 findings"}`.
  See the code examples below on how to activate it.
- Often the note is the only specific input to what you want to update with a rule.
  To trim some boilerplate config per rule, the feature `QuickNote` can be used.
  See the code examples below on how to use it.

## Example usage

```yaml
Rules:
- Filters:
    Region:
    - Value: eu-west-1
      Comparison: EQUALS
    WorkflowStatus:
    - Value: NEW
      Comparison: EQUALS
  UpdatesToFilteredFindings:
    Workflow:
      Status: SUPPRESSED
    Note:
      Text: Test
      UpdatedBy: awsfindingsmanagerlib
  ExtraFeatures:
    RegexStringFilters:
      ResourceId:
      - .*-dev$
      - .*-test$
      Description:
      - .*non-critical.*
    NoteTextConfig:
      Mode: jsonUpdate
      Key: suppressionReason
```

```Python
from pathlib import Path

import boto3
import yaml

from awsfindingsmanagerlib import Rule


with Path("rules.yaml").open() as file:
    rules = yaml.safe_load(file)["Rules"]

client = boto3.client("securityhub")

rule = Rule(**rules[0], client=client)
rule.get_and_update()
```

### Condensing big rule sets

```yaml
ManagerConfig:
  DefaultRuleInput:
    Filters:
      WorkflowStatus:
      - Value: NEW
        Comparison: EQUALS
      - Value: NOTIFIED
        Comparison: EQUALS
    UpdatesToFilteredFindings:
      Workflow:
        Status: SUPPRESSED
      Note:
        UpdatedBy: awsfindingsmanagerlib
    ExtraFeatures:
      NoteTextConfig:
        Mode: jsonUpdate
        Key: suppressionReason
Rules:
- Filters:
    ResourceId:
    - Value: arn:aws:s3:::test-awsfindingsmanagerlib
      Comparison: EQUALS
  UpdatesToFilteredFindings:
    Note:
      Text: Test
- Filters:
    ResourceId:
    - Value: arn:aws:s3:::test-awsfindingsmanagerlib-2
      Comparison: EQUALS
  ExtraFeatures:
    NoteTextConfig:
      Mode: plaintext
    QuickNote: Test-2
```

```Python
from pathlib import Path

import boto3
import yaml

from awsfindingsmanagerlib import Manager


with Path("rules.yaml").open() as file:
    rules = yaml.safe_load(file)

client = boto3.client("securityhub")

manager = Manager.from_rules_document(rules, client)
manager.get_and_update_all()
```

## Running in AWS Lambda

Installing the `lambda` extra (`awsfindingsmanagerlib[lambda]`, pulling in `aws-lambda-powertools` and
`pyyaml`) provides `awsfindingsmanagerlib.aws_lambda`, four ready-made Lambda handlers built on top of
`Manager`/`Rule`:

- `awsfindingsmanagerlib.aws_lambda.scheduled.lambda_handler`: applies all configured rules to every
  currently matching finding. Intended to run on a schedule (e.g. an EventBridge rule).
  Raises `RuntimeError` if any matched finding could not be processed, so the invocation is
  reported as failed.
- `awsfindingsmanagerlib.aws_lambda.events.lambda_handler`: intended as the target of an EventBridge rule
  matching `"Security Hub Findings - Imported"` events. Suppresses the finding(s) carried by the
  event and returns `{"finding_state": "suppressed"}` or `{"finding_state": "skipped"}` instead of
  raising, so that a Step Function (or any other orchestration) placed after it can branch on
  whether the finding still needs further handling, such as a ticket.
- `awsfindingsmanagerlib.aws_lambda.trigger.lambda_handler`: intended as the target of an S3 `ObjectCreated`
  notification on the rules file. Loads the rules and places one SQS message per rule (carrying
  the shared `ManagerConfig` alongside it) on the queue URL given by the `SQS_QUEUE_URL`
  environment variable, for `awsfindingsmanagerlib.aws_lambda.worker` to apply.
- `awsfindingsmanagerlib.aws_lambda.worker.lambda_handler`: intended as the target of an SQS event source
  mapping consuming the queue that `awsfindingsmanagerlib.aws_lambda.trigger` writes to. Rebuilds a manager
  from the single rule carried by each record and applies it against every currently matching
  finding. Logs and continues on a per-record failure, relying on the queue's own redrive policy
  for retries rather than on the Lambda invocation failing.

### Rules source

All four handlers load rules through the same logic: if both the `S3_BUCKET_NAME` and
`S3_OBJECT_NAME` environment variables are set (`awsfindingsmanagerlib.aws_lambda.trigger` and `.scheduled`
and `.events` all read rules this way), the rules document is loaded from that S3 object;
otherwise it is loaded from the local file named by `RULES_PATH` (defaulting to `rules.yaml`,
relative to the Lambda's working directory), which must be bundled into the deployment package.
`awsfindingsmanagerlib.aws_lambda.worker` never loads rules itself: it receives its single rule directly in
the SQS message body.

### IAM permissions

At minimum, the execution role needs `securityhub:GetFindings` and
`securityhub:BatchUpdateFindings` on the Security Hub resource. Depending on which handlers are
deployed, also add `s3:GetObject` on the rules object (`events`, `trigger`, `scheduled`) and
`sqs:SendMessage`/`sqs:ReceiveMessage`/`sqs:DeleteMessage`/`sqs:GetQueueAttributes` on the queue
(`trigger` and `worker` respectively).

### Region behaviour

Each handler queries Security Hub in the boto3 client's own region only; unlike some other
findings-management libraries, it does not enumerate finding aggregators or other regions. Deploy
the Lambda(s) in the Region where Security Hub findings are aggregated (typically the
organization's Security Hub home Region) so this default is correct.

### Deployment package

Download `lambda_package.zip` from the awsfindingsmanagerlib GitHub release; it is built by the release
workflow with `uv export --all-extras --no-dev` and contains `awsfindingsmanagerlib` and its dependencies with
a flat, importable layout. Add your `rules.yaml` (if not loading from S3) at the root of the zip
alongside the `awsfindingsmanagerlib` package before uploading it.

## Upgrading from 1.x

2.0 is a complete rewrite and is not compatible with 1.x: rules are no longer written under `match_on`, but map
directly onto the `get_findings`/`batch_update_findings` boto3 API, and the Python API changed accordingly.
See [UPGRADING.md](https://github.com/schubergphilis-ep/awsfindingsmanagerlib/blob/main/UPGRADING.md)
for a field-by-field mapping, a script converting a 1.x `rules.yaml`, and the behavioural differences.

Behaviours that 1.x applied implicitly (the default `WorkflowStatus` filter, the note author and the note format)
are set once for all rules via `ManagerConfig.DefaultRuleInput`, for instance:

```yaml
ManagerConfig:
  DefaultRuleInput:
    Filters:
      WorkflowStatus:
      - Value: NEW
        Comparison: EQUALS
      - Value: NOTIFIED
        Comparison: EQUALS
    UpdatesToFilteredFindings:
      Workflow:
        Status: SUPPRESSED
      Note:
        UpdatedBy: awsfindingsmanagerlib
    ExtraFeatures:
      NoteTextConfig:
        Mode: jsonUpdate
        Key: Note
```
