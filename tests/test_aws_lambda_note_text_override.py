import copy
import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import botocore.session
import yaml

os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-1")
# Not strictly needed, but speeds up boto client creation
os.environ.setdefault("AWS_ACCESS_KEY_ID", "ASIA000AAA")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "abc123")
os.environ.setdefault("AWS_SESSION_TOKEN", "abc123token")

from awsfindingsmanagerlib import Manager
from awsfindingsmanagerlib.aws_lambda.note_text_override import (
    apply_note_text_config_override,
    get_note_text_config_override,
)

with Path("tests/fixtures/rules/correct_rules.yaml").open() as file:
    CORRECT_RULES_DOCUMENT = yaml.safe_load(file)
with Path("tests/fixtures/rules/json_update_rules.yaml").open() as file:
    JSON_RULES_DOCUMENT = yaml.safe_load(file)

SECURITYHUB_SESSION_CLIENT = botocore.session.get_session().create_client("securityhub")

JSON_UPDATE_ENV = {"NOTE_TEXT_CONFIG_MODE": "jsonUpdate"}


def _without_override_env():
    return patch.dict(
        "os.environ",
        {"NOTE_TEXT_CONFIG_MODE": "", "NOTE_TEXT_CONFIG_KEY": ""},
        clear=False,
    )


class TestGetNoteTextConfigOverride(TestCase):
    def test_returns_none_when_mode_is_not_set(self):
        with _without_override_env():
            self.assertIsNone(get_note_text_config_override())

    def test_json_update_defaults_the_key_to_note(self):
        with _without_override_env(), patch.dict("os.environ", JSON_UPDATE_ENV):
            override = get_note_text_config_override()
        self.assertEqual((override.Mode, override.Key), ("jsonUpdate", "Note"))

    def test_json_update_uses_the_configured_key(self):
        with patch.dict(
            "os.environ",
            {"NOTE_TEXT_CONFIG_MODE": "jsonUpdate", "NOTE_TEXT_CONFIG_KEY": "Reason"},
        ):
            override = get_note_text_config_override()
        self.assertEqual((override.Mode, override.Key), ("jsonUpdate", "Reason"))

    def test_plaintext_has_no_key(self):
        with (
            _without_override_env(),
            patch.dict("os.environ", {"NOTE_TEXT_CONFIG_MODE": "plaintext"}),
        ):
            override = get_note_text_config_override()
        self.assertEqual((override.Mode, override.Key), ("plaintext", ""))

    def test_rejects_an_unsupported_mode(self):
        with (
            patch.dict("os.environ", {"NOTE_TEXT_CONFIG_MODE": "json"}),
            self.assertRaises(ValueError),
        ):
            get_note_text_config_override()


class TestApplyNoteTextConfigOverride(TestCase):
    def test_returns_the_document_unchanged_when_mode_is_not_set(self):
        with _without_override_env():
            result = apply_note_text_config_override(CORRECT_RULES_DOCUMENT)
        self.assertIs(result, CORRECT_RULES_DOCUMENT)

    def test_sets_the_default_and_overrides_every_rule(self):
        document = {
            "ManagerConfig": {
                "DefaultRuleInput": {
                    "ExtraFeatures": {"NoteTextConfig": {"Mode": "plaintext"}}
                }
            },
            "Rules": [
                {"Filters": {}},
                {
                    "Filters": {},
                    "ExtraFeatures": {"NoteTextConfig": {"Mode": "plaintext"}},
                },
                {
                    "Filters": {},
                    "ExtraFeatures": {"NoteTextConfig": {"Key": "jiraIssue"}},
                },
            ],
        }
        original = copy.deepcopy(document)
        forced = {"Mode": "jsonUpdate", "Key": "Note"}

        with (
            _without_override_env(),
            patch.dict("os.environ", JSON_UPDATE_ENV),
            self.assertLogs(
                "awsfindingsmanagerlib.aws_lambda.note_text_override", "WARNING"
            ) as logs,
        ):
            result = apply_note_text_config_override(document)

        self.assertEqual(
            result["ManagerConfig"]["DefaultRuleInput"]["ExtraFeatures"][
                "NoteTextConfig"
            ],
            forced,
        )
        self.assertNotIn("ExtraFeatures", result["Rules"][0])
        self.assertEqual(result["Rules"][1]["ExtraFeatures"]["NoteTextConfig"], forced)
        self.assertEqual(result["Rules"][2]["ExtraFeatures"]["NoteTextConfig"], forced)
        self.assertEqual(len(logs.records), 2)
        self.assertEqual(document, original)

    def test_creates_the_manager_config_when_missing(self):
        with _without_override_env(), patch.dict("os.environ", JSON_UPDATE_ENV):
            result = apply_note_text_config_override({"Rules": []})
        self.assertEqual(
            result["ManagerConfig"],
            {
                "DefaultRuleInput": {
                    "ExtraFeatures": {
                        "NoteTextConfig": {"Mode": "jsonUpdate", "Key": "Note"}
                    }
                }
            },
        )

    def test_every_rule_of_the_built_manager_uses_the_forced_config(self):
        document = copy.deepcopy(JSON_RULES_DOCUMENT)
        document["Rules"].append(copy.deepcopy(CORRECT_RULES_DOCUMENT["Rules"][0]))

        with _without_override_env(), patch.dict("os.environ", JSON_UPDATE_ENV):
            manager = Manager.from_rules_document(
                apply_note_text_config_override(document), SECURITYHUB_SESSION_CLIENT
            )

        note_text_configs = {
            (rule._note_text_config.Mode, rule._note_text_config.Key)  # noqa: SLF001
            for rule in manager._rules  # noqa: SLF001
        }
        self.assertEqual(note_text_configs, {("jsonUpdate", "Note")})
