# Upgrading Notes

This document captures required refactoring on your part when upgrading to a version that contains breaking changes.

## Upgrading to v2.0.0

### Key Changes v2.0.0

awsfindingsmanagerlib 2.0.0 is a complete rewrite. Nothing from 1.x carries over unchanged: the rules file,
the Python API and the dependencies are all different.

- **Rules map directly onto the Security Hub API.** A rule consists of `Filters` (the `Filters` argument of
  boto3's `get_findings`) and `UpdatesToFilteredFindings` (the arguments of `batch_update_findings`), so everything the
  API supports as a filter or update is available. There is no longer a custom, narrower `match_on` schema.
  Rules are validated eagerly, against botocore's own service model, when they are created.
- **Python >= 3.12 is required** (1.x: >= 3.10).
- **Dependencies.** `boto3` is the only hard dependency. `opnieuw`, `python-dateutil`, `schema` and `requests` are gone.
  `pyyaml` and `aws-lambda-powertools` are only installed with the `lambda` extra
  (`pip install 'awsfindingsmanagerlib[lambda]'`).
- **Documentation** moved from Read the Docs to [GitHub Pages](https://schubergphilis-ep.github.io/awsfindingsmanagerlib/).
- **New:** ready-made AWS Lambda handlers, regex matching on any string field, and JSON-merging notes
  (see [Behaviour](#behaviour-v200) below).

### Rules file (v2.0.0)

Every key of the old `match_on` has an equivalent:

| 1.x | 2.0 |
|---|---|
| `note` | `UpdatesToFilteredFindings.Note.Text` (or `ExtraFeatures.QuickNote`) |
| `action: SUPPRESSED` | `UpdatesToFilteredFindings.Workflow.Status: SUPPRESSED` |
| `match_on.security_control_id` | `Filters.ComplianceSecurityControlId` |
| `match_on.rule_or_control_id` | `Filters.ProductFields`, with two entries: `Key: ControlId` and `Key: RuleId`, both with the id as `Value` (matched as "any of", as the old library did) |
| `match_on.title` | `Filters.Title` |
| `match_on.product_name` | `Filters.ProductName` |
| `match_on.regions` | `Filters.Region` |
| `match_on.tags` (a list of `{key, value}`) | `Filters.ResourceTags` (a list of `{Key, Value, Comparison: EQUALS}`) |
| `match_on.resource_id_regexps` | `ExtraFeatures.RegexStringFilters.ResourceId` |

Every filter entry is a `{Value, Comparison}` pair. Entries within one filter are matched as "any of", and different
filters are combined with "and", like in 1.x.
Regexes are evaluated by this library itself rather than by Security Hub, and are still matched with `re.search`.

#### Defaults that must now be explicit

1.x applied a few things to every rule implicitly. If you rely on them, set them once under
`ManagerConfig.DefaultRuleInput`:

- The default filter `WorkflowStatus` in `NEW` or `NOTIFIED`.
- `Note.UpdatedBy`, which Security Hub requires whenever a note is set. 1.x used `FindingsManager`
  (or the `suppress_label` argument). Keep the old value if anything of yours filters on `NoteUpdatedBy`.
- The note format: `NoteTextConfig(format="text")` is `Mode: plaintext`, and
  `NoteTextConfig(format="json", key="Note")` is `Mode: jsonUpdate` with `Key: Note`.
  Only set the `jsonUpdate` mode if you used the JSON format in 1.x, for instance because a ticketing integration
  stores metadata such as `jiraIssue` in the finding's note.

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
      Note:
        UpdatedBy: FindingsManager
    ExtraFeatures:
      NoteTextConfig:
        Mode: plaintext
```

Individual rules can override anything set there.

#### Conversion script

The script below converts a 1.x `rules.yaml` to a complete 2.0 document, including the `ManagerConfig` above.
It declares its own dependencies ([PEP 723](https://peps.python.org/pep-0723/)), so with
[uv](https://docs.astral.sh/uv/) you can save it as `convert.py` and run it directly:

```shell
uv run convert.py rules.yaml > rules-v2.yaml
```

The input path is optional (default: `rules.yaml`). The converted document goes to stdout, and it is validated with
`awsfindingsmanagerlib` itself before it is printed, so a failure means the result is not a valid 2.0 document.
No AWS credentials are needed. Review the `ManagerConfig` block it prints and adjust it to the defaults you relied on.

```python
# /// script
# requires-python = ">=3.12,<3.13"  # awsfindingsmanagerlib 2.0.0 does not yet run on 3.13
# dependencies = ["awsfindingsmanagerlib>=2,<3", "pyyaml"]
# ///
import sys
from pathlib import Path

import boto3
import yaml

from awsfindingsmanagerlib import Manager

SUPPORTED_MATCH_ON_KEYS = {
    "security_control_id",
    "rule_or_control_id",
    "title",
    "product_name",
    "regions",
    "tags",
    "resource_id_regexps",
}


def equals(values):
    return [{"Value": value, "Comparison": "EQUALS"} for value in values]


def convert(rule):
    match_on = rule.get("match_on", {})
    unknown_keys = set(match_on) - SUPPORTED_MATCH_ON_KEYS
    if unknown_keys:
        # Fail rather than silently drop a condition and suppress too much.
        msg = f"Unsupported match_on key(s) {sorted(unknown_keys)} in rule: {rule}"
        raise ValueError(msg)

    filters = {}

    if "security_control_id" in match_on:
        filters["ComplianceSecurityControlId"] = equals(
            [match_on["security_control_id"]]
        )
    if "rule_or_control_id" in match_on:
        # The old library matched either field, depending on the standard.
        filters["ProductFields"] = [
            {
                "Key": key,
                "Value": match_on["rule_or_control_id"],
                "Comparison": "EQUALS",
            }
            for key in ("ControlId", "RuleId")
        ]
    if "title" in match_on:
        filters["Title"] = equals([match_on["title"]])
    if "product_name" in match_on:
        filters["ProductName"] = equals([match_on["product_name"]])
    if "regions" in match_on:
        filters["Region"] = equals(match_on["regions"])
    if "tags" in match_on:
        filters["ResourceTags"] = [
            {"Key": tag["key"], "Value": tag["value"], "Comparison": "EQUALS"}
            for tag in match_on["tags"]
        ]

    new_rule = {
        "Filters": filters,
        "UpdatesToFilteredFindings": {
            "Workflow": {"Status": rule["action"]},
            "Note": {"Text": rule["note"]},
        },
    }

    if "resource_id_regexps" in match_on:
        new_rule["ExtraFeatures"] = {
            "RegexStringFilters": {"ResourceId": match_on["resource_id_regexps"]}
        }

    return new_rule


input_path = Path(sys.argv[1] if len(sys.argv) > 1 else "rules.yaml")
with input_path.open() as file:
    old_document = yaml.safe_load(file)

if "Rules" not in old_document:
    sys.exit(f"{input_path} has no top-level 'Rules' key. Is it a 1.x rules file?")

document = {
    "ManagerConfig": {
        "DefaultRuleInput": {
            "Filters": {
                "WorkflowStatus": equals(["NEW", "NOTIFIED"]),
            },
            "UpdatesToFilteredFindings": {
                "Note": {"UpdatedBy": "FindingsManager"},
            },
            "ExtraFeatures": {
                "NoteTextConfig": {"Mode": "plaintext"},
            },
        },
    },
    "Rules": [convert(rule) for rule in old_document["Rules"]],
}

# Validate against botocore's service model. This makes no AWS calls and needs no
# credentials; the region is only required to create the client.
client = boto3.client("securityhub", region_name="us-east-1")
Manager.from_rules_document(document, client)

print(yaml.safe_dump(document, sort_keys=False, indent=2))
print(
    f"Converted {len(document['Rules'])} rules; the result is a valid 2.0 rules document.",
    file=sys.stderr,
)
```

See `docs/examples/rules.yaml` in this repository for a complete, converted file.

### Python API (v2.0.0)

| 1.x | 2.0 |
|---|---|
| `FindingsManager(...)` | `Manager.from_rules_document(rules_document, client)`, or `Manager(client=client, DefaultRuleInput=...)` |
| `FindingsManager(region=...)` | The region of the boto3 Security Hub `client` you pass in |
| `allowed_regions` / `denied_regions` | `Filters.Region` with `EQUALS` / `NOT_EQUALS` |
| `allowed_account_ids` / `denied_account_ids` | `Filters.AwsAccountId` with `EQUALS` / `NOT_EQUALS` |
| `suppress_label` | `UpdatesToFilteredFindings.Note.UpdatedBy` |
| `note_text=NoteTextConfig(...)` | `ExtraFeatures.NoteTextConfig` (`Mode`, `Key`) |
| `strict_mode` | Removed. Rules are always validated on creation, and a failed update is reported through the returned `bool`. |
| `register_rule(s)` | `Rule(...)`, `Manager.set_rules(...)` or `Manager.from_rules_document(...)` |
| `suppress_matching_findings()` | `Manager.get_and_update_all()`, which returns a `bool` rather than `(bool, payloads)` |
| `suppress_finding(s)_on_matching_rules(...)` | `Manager.match_and_update(finding)`, or `Manager.process_finding(finding)` to also get the number of matching rules; both take a single finding |
| `validate_finding_on_matching_rules(...)` | `Rule.match(finding)` |
| `Finding` | Findings are plain ASFF dictionaries |
| `backends.Local` / `Http` / `S3` | Load the YAML yourself, or use `awsfindingsmanagerlib.aws_lambda.rules_backend.load_rules` |
| `awsfindingsmanagerlibexceptions` | Removed. Invalid rules raise `ValueError` or `botocore.exceptions.ParamValidationError`. |

A 1.x script that suppressed all findings matching a rules file translates to:

```python
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

### Behaviour (v2.0.0)

- **One region.** Only the region of the client you pass in is queried. 1.x looked up the finding aggregator and
  otherwise iterated over all opted-in regions. Create the client in the region where your findings are aggregated, or
  create one client and `Manager` per region.
- **All matching rules apply.** When a single finding is matched against the rules, every matching rule is applied in
  order. 1.x only applied the first match.
- **Retries.** The `opnieuw` retry around `get_findings` is gone. Configure retries on the boto3 client instead
  (`botocore.config.Config(retries={...})`).
- **Dry-run.** The `FINDINGS_MANAGER_DRY_RUN_MODE` environment variable is no longer supported.
- **Unmanaged suppressions.** `get_unmanaged_suppressed_findings` and `unsuppress_unmanaged_findings` are removed.
  The same can be expressed as a rule that matches suppressed findings not updated by you and moves them back to `NEW`:

  ```yaml
  Rules:
  - Filters:
      WorkflowStatus:
      - Value: SUPPRESSED
        Comparison: EQUALS
      NoteUpdatedBy:
      - Value: FindingsManager
        Comparison: NOT_EQUALS
    UpdatesToFilteredFindings:
      Workflow:
        Status: NEW
  ```

  Use this rule on its own: it must not inherit a `DefaultRuleInput` that filters on `WorkflowStatus: NEW`.
- **Notes.** In `jsonUpdate` mode an existing plain-text note is overwritten (the previous note is logged), and an
  existing JSON note is updated only on the key you configure.

### AWS Lambda (v2.0.0)

If you ran 1.x in your own Lambda, you can now use the handlers in `awsfindingsmanagerlib.aws_lambda` instead
(`scheduled`, `events`, `trigger` and `worker`); see "Running in AWS Lambda" in the documentation. The `lambda_package.zip`
attached to each GitHub release contains the library with its dependencies.

If you use [terraform-aws-mcaf-securityhub-findings-manager](https://github.com/schubergphilis-ep/terraform-aws-mcaf-securityhub-findings-manager),
follow that module's own upgrade notes for the version that switches to this library.
