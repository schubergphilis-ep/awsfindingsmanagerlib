import datetime
import json
import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

import botocore.session
import yaml
from botocore.exceptions import ParamValidationError

from awsfindingsmanagerlib import (
    Manager,
    Rule,
    validate_filters,
    validate_updates,
)
from awsfindingsmanagerlib.boto_utils import (
    BotoStubCall,
    get_values_by_boto_argument,
    stub_boto_client,
)

os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"
# Not strictly needed, but speeds up boto client creation
os.environ["AWS_ACCESS_KEY_ID"] = "ASIA000AAA"
os.environ["AWS_SECRET_ACCESS_KEY"] = "abc123"  # noqa: S105
os.environ["AWS_SESSION_TOKEN"] = "abc123token"  # noqa: S105


with Path("tests/fixtures/rules/correct_rules.yaml").open() as file:
    CORRECT_RULES = yaml.safe_load(file)["Rules"]
with Path("tests/fixtures/rules/broken_rules.yaml").open() as file:
    BROKEN_RULES = yaml.safe_load(file)["Rules"]
with Path("tests/fixtures/rules/condensed_rules.yaml").open() as file:
    CONDENSED_RULES = yaml.safe_load(file)
with Path("tests/fixtures/rules/all_filter_types_match_rules.yaml").open() as file:
    ALL_FILTER_TYPES_MATCH_RULES = yaml.safe_load(file)["Rules"]
with Path("tests/fixtures/rules/all_filter_types_no_match_rules.yaml").open() as file:
    ALL_FILTER_TYPES_NO_MATCH_RULES = yaml.safe_load(file)["Rules"]
with Path("tests/fixtures/rules/json_update_rules.yaml").open() as file:
    JSON_RULES = yaml.safe_load(file)["Rules"]

with Path("tests/fixtures/calls/filters.json").open() as file:
    FILTERS = json.load(file)
with Path("tests/fixtures/responses/findings_trimmed.json").open() as file:
    FINDINGS = json.load(file)
with Path("tests/fixtures/responses/finding_groomed.json").open() as file:
    FINDING_GROOMED = json.load(file)
with Path("tests/fixtures/calls/updates.json").open() as file:
    UPDATES = json.load(file)
with Path("tests/fixtures/responses/processed.json").open() as file:
    PROCESSED = json.load(file)
with Path("tests/fixtures/responses/unprocessed.json").open() as file:
    UNPROCESSED = json.load(file)
with Path("tests/fixtures/calls/json_updates.json").open() as file:
    JSON_UPDATES = json.load(file)
with Path("tests/fixtures/calls/json_grouped_updates.json").open() as file:
    JSON_GROUPED_UPDATES = json.load(file)
with Path("tests/fixtures/responses/json_update_grouped_findings.json").open() as file:
    JSON_UPDATE_GROUPED_FINDINGS = json.load(file)

SECURITYHUB_SESSION_CLIENT = botocore.session.get_session().create_client("securityhub")


class TestSmoke(TestCase):
    def test_sanity(self):
        self.assertTrue(expr=True)


class TestValidateFilters(TestCase):
    def test_valid_filters(self):
        self.assertIsNone(validate_filters(CORRECT_RULES[0]["Filters"]))

    def test_invalid_filters(self):
        self.assertRaises(
            ParamValidationError, validate_filters, BROKEN_RULES[0]["Filters"]
        )


class TestValidateUpdates(TestCase):
    def test_valid_updates(self):
        first_rule_updates = CORRECT_RULES[0]["UpdatesToFilteredFindings"]
        first_rule_updates["FindingIdentifiers"] = [
            {
                "Id": "SomeFindingId",
                "ProductArn": "SomeProductArn",
            }
        ]
        self.assertIsNone(validate_updates(first_rule_updates))

    def test_invalid_updates(self):
        self.assertRaises(
            ParamValidationError,
            validate_updates,
            BROKEN_RULES[0]["UpdatesToFilteredFindings"],
        )


class TestGetValuesByBotoArgument(TestCase):
    def test_regular_field_returns_single_value(self):
        finding = {"Title": "Some title"}
        self.assertEqual(get_values_by_boto_argument(finding, "Title"), ["Some title"])

    def test_regular_missing_field_returns_empty_list(self):
        finding = {"Title": "Some title"}
        self.assertEqual(get_values_by_boto_argument(finding, "Description"), [])

    def test_special_case_nested_list_path(self):
        finding = {
            "Resources": [
                {"Id": "res-1", "Type": "AwsS3Bucket"},
                {"Id": "res-2", "Type": "AwsEc2Instance"},
            ]
        }
        self.assertEqual(
            get_values_by_boto_argument(finding, "ResourceId"),
            ["res-1", "res-2"],
        )

    def test_special_case_ignores_missing_and_none_values(self):
        finding = {
            "Resources": [
                {"Id": "res-1"},
                {"Id": None},
                {},
            ]
        }
        self.assertEqual(get_values_by_boto_argument(finding, "ResourceId"), ["res-1"])

    def test_empty_tags(self):
        finding = {"Tags": {}}
        self.assertEqual(get_values_by_boto_argument(finding, "Tags"), [])

    def test_empty_resource_tags(self):
        finding = {
            "Resources": [
                {"Tags": {}},
            ]
        }
        self.assertEqual(get_values_by_boto_argument(finding, "ResourceTags"), [])

    def test_empty_types(self):
        finding = {"Types": []}
        self.assertEqual(get_values_by_boto_argument(finding, "Type"), [])

    def test_nested_lists(self):
        finding = {
            "Compliance": {
                "SecurityControlParameters": [
                    {
                        "Value": [
                            "param1",
                            "param2",
                        ]
                    },
                    {},
                    {"Value": []},
                    {
                        "Value": [
                            "param3",
                        ]
                    },
                ]
            }
        }
        self.assertEqual(
            get_values_by_boto_argument(
                finding, "ComplianceSecurityControlParametersValue"
            ),
            ["param1", "param2", "param3"],
        )


class TestRuleDataclass(TestCase):
    def setUp(self):
        self.fixed_now = datetime.datetime(2026, 1, 1, 12, 0, 0, 0, datetime.UTC)
        patcher = patch(
            "awsfindingsmanagerlib.filters.DateCriterion._now_utc",
            return_value=self.fixed_now,
        )
        self.addCleanup(patcher.stop)
        self.mock_now = patcher.start()

    def _test_multiple_valid_rules(self, rules: list[dict]):
        for rule_dict in rules:
            with self.subTest(rule=rule_dict):
                Rule(**rule_dict, client=SECURITYHUB_SESSION_CLIENT)

    def test_valid_rule(self):
        self._test_multiple_valid_rules(CORRECT_RULES)

    def test_all_type_match_rules(self):
        self._test_multiple_valid_rules(ALL_FILTER_TYPES_MATCH_RULES)

    def test_all_type_no_match_rules(self):
        self._test_multiple_valid_rules(ALL_FILTER_TYPES_NO_MATCH_RULES)

    def test_invalid_rule_boto(self):
        self.assertRaises(
            ParamValidationError,
            Rule,
            **BROKEN_RULES[0],
            client=SECURITYHUB_SESSION_CLIENT,
        )

    def test_invalid_rule_business_logic(self):
        self.assertRaises(
            ValueError,
            Rule,
            **BROKEN_RULES[1],
            client=SECURITYHUB_SESSION_CLIENT,
        )

    def test_invalid_regex_rule_boto(self):
        self.assertRaises(
            ParamValidationError,
            Rule,
            **BROKEN_RULES[2],
            client=SECURITYHUB_SESSION_CLIENT,
        )

    def test_apply(self):
        rule = Rule(**CORRECT_RULES[0], client=SECURITYHUB_SESSION_CLIENT)
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", FINDINGS, FILTERS),
                BotoStubCall("batch_update_findings", PROCESSED, UPDATES),
            ],
        ):
            self.assertTrue(rule.get_and_update())

    def test_apply_paginates_beyond_first_page(self):
        """Regression test: get_and_update must not cap pagination to a single page.

        A real "total findings > 100" scenario doesn't fit in a fixture-driven Stubber test, so
        this asserts directly on the paginator call: no 'MaxItems' cap is passed (only
        'PageSize'), and every page yielded by the paginator is processed, by faking the
        paginator itself rather than relying on find volume.
        """
        rule = Rule(**CORRECT_RULES[0], client=SECURITYHUB_SESSION_CLIENT)

        all_matched_ids = {
            identifier["Id"] for identifier in UPDATES["FindingIdentifiers"]
        }
        all_findings = FINDINGS["Findings"]
        pages = [
            {"Findings": all_findings[:12]},
            {"Findings": all_findings[12:]},
        ]

        fake_paginator = MagicMock()
        fake_paginator.paginate.return_value = iter(pages)

        with (
            patch.object(
                rule.client, "get_paginator", return_value=fake_paginator
            ) as get_paginator,
            patch.object(
                rule.client, "batch_update_findings", return_value=PROCESSED
            ) as batch_update_findings,
        ):
            self.assertTrue(rule.get_and_update())

        get_paginator.assert_called_once_with("get_findings")
        _, pagination_kwargs = fake_paginator.paginate.call_args
        self.assertNotIn("MaxItems", pagination_kwargs["PaginationConfig"])

        # Both pages must have produced their own batch_update_findings call.
        self.assertEqual(batch_update_findings.call_count, 2)
        processed_ids = {
            identifier["Id"]
            for call in batch_update_findings.call_args_list
            for identifier in call.kwargs["FindingIdentifiers"]
        }
        self.assertEqual(processed_ids, all_matched_ids)

    def test_apply_logs_a_distinct_page_number_per_empty_page(self):
        """Regression test: the "no findings matched" log line must identify which page it's
        about, so multiple occurrences in one invocation are distinguishable from genuine
        repeated invocations (e.g. SQS redelivery) without having to cross-reference CloudWatch
        request IDs.
        """
        rule = Rule(**CORRECT_RULES[0], client=SECURITYHUB_SESSION_CLIENT)

        pages = [{"Findings": []}, {"Findings": []}]
        fake_paginator = MagicMock()
        fake_paginator.paginate.return_value = iter(pages)

        with (
            patch.object(rule.client, "get_paginator", return_value=fake_paginator),
            self.assertLogs("awsfindingsmanagerlib.rule", level="INFO") as logs,
        ):
            self.assertTrue(rule.get_and_update())

        self.assertIn("page 1", logs.output[0])
        self.assertIn("page 2", logs.output[1])

    def test_manager_rule_can_override_note_text_config_mode_to_plaintext(self):
        """Regression test: mirrors docs/index.md's "Condensing big rule sets" example.

        A manager default of NoteTextConfig(Mode="jsonUpdate", Key=...) merged with a rule that
        only overrides Mode back to "plaintext" used to raise ValueError at Rule construction,
        because the merged Key survived from the default.
        """
        manager = Manager(
            client=SECURITYHUB_SESSION_CLIENT,
            DefaultRuleInput={
                "Filters": {},
                "UpdatesToFilteredFindings": {
                    "Note": {"UpdatedBy": "awsfindingsmanagerlib"}
                },
                "ExtraFeatures": {
                    "NoteTextConfig": {"Mode": "jsonUpdate", "Key": "suppressionReason"}
                },
            },
        )
        rules = manager.set_rules(
            [
                {
                    "Filters": {},
                    "ExtraFeatures": {
                        "NoteTextConfig": {"Mode": "plaintext"},
                        "QuickNote": "Test-2",
                    },
                }
            ]
        )
        self.assertEqual(rules[0]._note_text_config.Mode, "plaintext")  # noqa: SLF001
        self.assertEqual(rules[0]._note_text_config.Key, "")  # noqa: SLF001

    def test_manager_apply(self):
        manager = Manager(
            **CONDENSED_RULES["ManagerConfig"], client=SECURITYHUB_SESSION_CLIENT
        )
        manager.set_rules(CONDENSED_RULES["Rules"])
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", FINDINGS, FILTERS),
                BotoStubCall("batch_update_findings", PROCESSED, UPDATES),
            ],
        ):
            self.assertTrue(manager.get_and_update_all())

    def test_apply_unprocessed(self):
        rule = Rule(**CORRECT_RULES[0], client=SECURITYHUB_SESSION_CLIENT)
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", FINDINGS, FILTERS),
                BotoStubCall("batch_update_findings", UNPROCESSED, UPDATES),
            ],
        ):
            self.assertFalse(rule.get_and_update())

    def test_json_apply(self):
        rule = Rule(**JSON_RULES[0], client=SECURITYHUB_SESSION_CLIENT)
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("get_findings", {"Findings": [FINDING_GROOMED]}, FILTERS),
                BotoStubCall("batch_update_findings", PROCESSED, JSON_UPDATES),
            ],
        ):
            self.assertTrue(rule.get_and_update())

    def test_json_apply_groups_updates_by_resulting_note_text(self):
        rule = Rule(**JSON_RULES[0], client=SECURITYHUB_SESSION_CLIENT)

        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall(
                    "get_findings",
                    JSON_UPDATE_GROUPED_FINDINGS,
                    FILTERS,
                ),
                *[
                    BotoStubCall("batch_update_findings", PROCESSED, grouped_update)
                    for grouped_update in JSON_GROUPED_UPDATES
                ],
            ],
        ):
            self.assertTrue(rule.get_and_update())

    def test_manager_json_apply(self):
        manager = Manager(client=SECURITYHUB_SESSION_CLIENT)
        manager.set_rules(JSON_RULES)
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("batch_update_findings", PROCESSED, JSON_UPDATES),
            ],
        ):
            self.assertTrue(manager.match_and_update(FINDING_GROOMED))

    def test_process_finding_reports_matched_rule_count(self):
        manager = Manager(client=SECURITYHUB_SESSION_CLIENT)
        manager.set_rules(JSON_RULES)
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("batch_update_findings", PROCESSED, JSON_UPDATES),
            ],
        ):
            result = manager.process_finding(FINDING_GROOMED)
        self.assertEqual(result.matched_rules, 1)
        self.assertTrue(result.all_processed)

    def test_process_finding_reports_no_matched_rules(self):
        manager = Manager(client=SECURITYHUB_SESSION_CLIENT)
        manager.set_rules(JSON_RULES)
        non_matching_finding = {**FINDING_GROOMED, "Resources": []}

        result = manager.process_finding(non_matching_finding)

        self.assertEqual(result.matched_rules, 0)
        self.assertTrue(result.all_processed)

    def test_process_finding_reports_unprocessed_updates(self):
        manager = Manager(client=SECURITYHUB_SESSION_CLIENT)
        manager.set_rules(JSON_RULES)
        with stub_boto_client(
            SECURITYHUB_SESSION_CLIENT,
            [
                BotoStubCall("batch_update_findings", UNPROCESSED, JSON_UPDATES),
            ],
        ):
            result = manager.process_finding(FINDING_GROOMED)
        self.assertEqual(result.matched_rules, 1)
        self.assertFalse(result.all_processed)

    def test_match(self):
        for all_filter_type_match_rule in ALL_FILTER_TYPES_MATCH_RULES:
            with self.subTest(all_filter_type_match_rule=all_filter_type_match_rule):
                rule = Rule(
                    **all_filter_type_match_rule,
                    client=SECURITYHUB_SESSION_CLIENT,
                )
                self.assertTrue(rule.match(FINDING_GROOMED))

    def test_no_match(self):
        for all_filter_type_no_match_rule in ALL_FILTER_TYPES_NO_MATCH_RULES:
            with self.subTest(
                all_filter_type_no_match_rule=all_filter_type_no_match_rule
            ):
                rule = Rule(
                    **all_filter_type_no_match_rule,
                    client=SECURITYHUB_SESSION_CLIENT,
                )
                self.assertFalse(rule.match(FINDING_GROOMED))
