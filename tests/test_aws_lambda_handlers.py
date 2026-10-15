import json
import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import botocore.session
import yaml

# Quiet the powertools JSON logger so `unittest` output stays readable; it's already exercised
# indirectly by these tests calling into decorated handlers. Must be set before importing the
# handler modules below, since each constructs its module-level Logger at import time.
os.environ.setdefault("POWERTOOLS_LOG_LEVEL", "CRITICAL")
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-1")
# Not strictly needed, but speeds up boto client creation
os.environ.setdefault("AWS_ACCESS_KEY_ID", "ASIA000AAA")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "abc123")
os.environ.setdefault("AWS_SESSION_TOKEN", "abc123token")

from awsfindingsmanagerlib import Manager
from awsfindingsmanagerlib.aws_lambda import events, scheduled, trigger, worker
from awsfindingsmanagerlib.boto_utils import BotoStubCall, stub_boto_client

with Path("tests/fixtures/rules/correct_rules.yaml").open() as file:
    CORRECT_RULES_DOCUMENT = yaml.safe_load(file)
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
with Path("tests/fixtures/calls/json_updates.json").open() as file:
    JSON_UPDATES = json.load(file)
with Path("tests/fixtures/responses/processed.json").open() as file:
    PROCESSED = json.load(file)
with Path("tests/fixtures/responses/unprocessed.json").open() as file:
    UNPROCESSED = json.load(file)

SECURITYHUB_SESSION_CLIENT = botocore.session.get_session().create_client("securityhub")
SQS_SESSION_CLIENT = botocore.session.get_session().create_client("sqs")


class _FakeLambdaContext:
    """A minimal stand-in for the Lambda context object.

    aws-lambda-powertools' `inject_lambda_context` reads a handful of attributes off it to build
    structured log fields; `None` (a valid `_context` value for the handlers themselves, since
    they don't use it) doesn't satisfy that.
    """

    function_name = "test-function"
    memory_limit_in_mb = 128
    invoked_function_arn = (
        "arn:aws:lambda:eu-west-1:123456789012:function:test-function"
    )
    aws_request_id = "test-request-id"


FAKE_CONTEXT = _FakeLambdaContext()


def _built_manager(rules: list) -> Manager:
    """Build a real Manager with its rules registered.

    Must be called before any `stub_boto_client(SECURITYHUB_SESSION_CLIENT, ...)` context is
    entered: Rule construction validates itself against the client via its own internal,
    self-contained stub cycle, which conflicts with an already-active outer Stubber holding
    queued responses for the same client.
    """
    manager = Manager(client=SECURITYHUB_SESSION_CLIENT)
    manager.set_rules(rules)
    return manager


class TestEventsHandler(TestCase):
    def test_returns_suppressed_when_a_finding_matched_and_was_processed(self):
        event = {"detail": {"findings": [FINDING_GROOMED]}}
        manager = _built_manager(JSON_RULES)
        with (
            patch.object(events, "load_rules", return_value={}),
            patch.object(Manager, "from_rules_document", return_value=manager),
            stub_boto_client(
                SECURITYHUB_SESSION_CLIENT,
                [BotoStubCall("batch_update_findings", PROCESSED, JSON_UPDATES)],
            ),
        ):
            result = events.lambda_handler(event, FAKE_CONTEXT)
        self.assertEqual(result, {"finding_state": "suppressed"})

    def test_returns_skipped_when_no_finding_matched(self):
        non_matching_finding = {**FINDING_GROOMED, "Resources": []}
        event = {"detail": {"findings": [non_matching_finding]}}
        manager = _built_manager(JSON_RULES)
        with (
            patch.object(events, "load_rules", return_value={}),
            patch.object(Manager, "from_rules_document", return_value=manager),
        ):
            result = events.lambda_handler(event, FAKE_CONTEXT)
        self.assertEqual(result, {"finding_state": "skipped"})

    def test_returns_skipped_and_does_not_raise_when_initialization_fails(self):
        event = {"detail": {"findings": [FINDING_GROOMED]}}
        with patch.object(events, "load_rules", side_effect=RuntimeError("boom")):
            result = events.lambda_handler(event, FAKE_CONTEXT)
        self.assertEqual(result, {"finding_state": "skipped"})

    def test_returns_skipped_when_an_update_is_unprocessed(self):
        event = {"detail": {"findings": [FINDING_GROOMED]}}
        manager = _built_manager(JSON_RULES)
        with (
            patch.object(events, "load_rules", return_value={}),
            patch.object(Manager, "from_rules_document", return_value=manager),
            stub_boto_client(
                SECURITYHUB_SESSION_CLIENT,
                [BotoStubCall("batch_update_findings", UNPROCESSED, JSON_UPDATES)],
            ),
        ):
            result = events.lambda_handler(event, FAKE_CONTEXT)
        self.assertEqual(result, {"finding_state": "skipped"})


class TestTriggerHandler(TestCase):
    def test_sends_one_message_per_rule_with_the_manager_config(self):
        manager_config = {"DefaultRuleInput": {"UpdatesToFilteredFindings": {}}}
        rules = [{"Filters": {}}, {"Filters": {"ResourceId": []}}]
        expected_calls = [
            BotoStubCall(
                "send_message",
                {"MessageId": "1", "MD5OfMessageBody": "x"},
                {
                    "QueueUrl": "https://sqs.example/q",
                    "MessageBody": json.dumps(
                        {"ManagerConfig": manager_config, "Rules": [rule]}
                    ),
                },
            )
            for rule in rules
        ]
        with (
            patch.dict(
                "os.environ", {"SQS_QUEUE_URL": "https://sqs.example/q"}, clear=False
            ),
            patch.object(
                trigger,
                "load_rules",
                return_value={"ManagerConfig": manager_config, "Rules": rules},
            ),
            patch.object(trigger, "get_sqs_client", return_value=SQS_SESSION_CLIENT),
            stub_boto_client(SQS_SESSION_CLIENT, expected_calls),
        ):
            trigger.lambda_handler({}, FAKE_CONTEXT)

    def test_raises_on_failure(self):
        with (
            patch.object(trigger, "load_rules", side_effect=RuntimeError("boom")),
            self.assertRaises(RuntimeError),
        ):
            trigger.lambda_handler({}, FAKE_CONTEXT)


class TestWorkerHandler(TestCase):
    def test_applies_the_rule_carried_by_each_record(self):
        event = {
            "Records": [
                {
                    "messageId": "msg-1",
                    "body": json.dumps({"ManagerConfig": {}, "Rules": [JSON_RULES[0]]}),
                }
            ]
        }
        manager = _built_manager(JSON_RULES[:1])
        with (
            patch.object(Manager, "from_rules_document", return_value=manager),
            stub_boto_client(
                SECURITYHUB_SESSION_CLIENT,
                [
                    BotoStubCall(
                        "get_findings", {"Findings": [FINDING_GROOMED]}, FILTERS
                    ),
                    BotoStubCall("batch_update_findings", PROCESSED, JSON_UPDATES),
                ],
            ),
        ):
            result = worker.lambda_handler(event, FAKE_CONTEXT)
        self.assertEqual(result, {"batchItemFailures": []})

    def test_reports_only_the_failed_record_as_a_batch_item_failure(self):
        # A batch of two records: the first fails, the second must still be processed and must
        # not be reported as failed (only the failed record's batchItemFailures entry should
        # cause it, specifically, to be retried/redriven).
        event = {
            "Records": [
                {"messageId": "msg-bad", "body": json.dumps({"Rules": []})},
                {
                    "messageId": "msg-good",
                    "body": json.dumps({"ManagerConfig": {}, "Rules": [JSON_RULES[0]]}),
                },
            ]
        }
        good_manager = _built_manager(JSON_RULES[:1])
        with (
            patch.object(
                Manager,
                "from_rules_document",
                side_effect=[ValueError("boom"), good_manager],
            ),
            stub_boto_client(
                SECURITYHUB_SESSION_CLIENT,
                [
                    BotoStubCall(
                        "get_findings", {"Findings": [FINDING_GROOMED]}, FILTERS
                    ),
                    BotoStubCall("batch_update_findings", PROCESSED, JSON_UPDATES),
                ],
            ),
        ):
            result = worker.lambda_handler(event, FAKE_CONTEXT)  # must not raise
        self.assertEqual(result, {"batchItemFailures": [{"itemIdentifier": "msg-bad"}]})


class TestScheduledHandler(TestCase):
    def test_applies_all_rules_successfully(self):
        manager = _built_manager(CORRECT_RULES_DOCUMENT["Rules"])
        with (
            patch.object(scheduled, "load_rules", return_value={}),
            patch.object(Manager, "from_rules_document", return_value=manager),
            stub_boto_client(
                SECURITYHUB_SESSION_CLIENT,
                [
                    BotoStubCall("get_findings", FINDINGS, FILTERS),
                    BotoStubCall("batch_update_findings", PROCESSED, UPDATES),
                ],
            ),
        ):
            scheduled.lambda_handler({}, FAKE_CONTEXT)  # must not raise

    def test_raises_when_not_all_findings_were_processed(self):
        manager = _built_manager(CORRECT_RULES_DOCUMENT["Rules"])
        with (
            patch.object(scheduled, "load_rules", return_value={}),
            patch.object(Manager, "from_rules_document", return_value=manager),
            stub_boto_client(
                SECURITYHUB_SESSION_CLIENT,
                [
                    BotoStubCall("get_findings", FINDINGS, FILTERS),
                    BotoStubCall("batch_update_findings", UNPROCESSED, UPDATES),
                ],
            ),
            self.assertRaises(RuntimeError),
        ):
            scheduled.lambda_handler({}, FAKE_CONTEXT)
