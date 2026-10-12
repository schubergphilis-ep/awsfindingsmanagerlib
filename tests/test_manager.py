import os
from pathlib import Path
from unittest import TestCase

import botocore.session
import yaml

from awsfindingsmanagerlib import Manager

os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-1")
# Not strictly needed, but speeds up boto client creation
os.environ.setdefault("AWS_ACCESS_KEY_ID", "ASIA000AAA")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "abc123")
os.environ.setdefault("AWS_SESSION_TOKEN", "abc123token")


with Path("tests/fixtures/rules/correct_rules.yaml").open() as file:
    CORRECT_RULES_DOCUMENT = yaml.safe_load(file)
with Path("tests/fixtures/rules/condensed_rules.yaml").open() as file:
    CONDENSED_RULES_DOCUMENT = yaml.safe_load(file)

SECURITYHUB_SESSION_CLIENT = botocore.session.get_session().create_client("securityhub")


class TestFromRulesDocument(TestCase):
    def test_without_manager_config(self):
        manager = Manager.from_rules_document(
            CORRECT_RULES_DOCUMENT, SECURITYHUB_SESSION_CLIENT
        )
        self.assertIsInstance(manager, Manager)
        registered_rules = manager._rules  # noqa: SLF001
        self.assertEqual(len(registered_rules), len(CORRECT_RULES_DOCUMENT["Rules"]))

    def test_with_manager_config(self):
        manager = Manager.from_rules_document(
            CONDENSED_RULES_DOCUMENT, SECURITYHUB_SESSION_CLIENT
        )
        self.assertIsInstance(manager, Manager)
        registered_rules = manager._rules  # noqa: SLF001
        self.assertEqual(len(registered_rules), len(CONDENSED_RULES_DOCUMENT["Rules"]))

    def test_requires_a_rules_key(self):
        with self.assertRaises(ValueError):
            Manager.from_rules_document({}, SECURITYHUB_SESSION_CLIENT)

    def test_rejects_unknown_manager_config_keys(self):
        # The common mistake: putting ExtraFeatures next to, rather than inside,
        # DefaultRuleInput.
        rules = {
            "ManagerConfig": {
                "DefaultRuleInput": {},
                "ExtraFeatures": {"NoteTextConfig": {"Mode": "jsonUpdate", "Key": "x"}},
            },
            "Rules": [],
        }
        with self.assertRaises(ValueError):
            Manager.from_rules_document(rules, SECURITYHUB_SESSION_CLIENT)


class TestSetRulesDoesNotShareMutableState(TestCase):
    """Regression test for a data-corruption bug found in post-merge review.

    `Manager._merge_inputs` used a shallow `dict.copy()`, so a rule that didn't override a given
    branch of `DefaultRuleInput` (e.g. `UpdatesToFilteredFindings`) shared that nested dict, by
    object identity, with `Manager.DefaultRuleInput` itself and with every other such rule.
    `Rule._apply_quick_note` then mutated `UpdatesToFilteredFindings["Note"]["Text"]` in place,
    so the *last* rule's `QuickNote` silently overwrote every earlier rule's note, and
    permanently corrupted `Manager.DefaultRuleInput` too. This is exactly the configuration
    pattern documented for condensing big rule sets (a shared `DefaultRuleInput.
    UpdatesToFilteredFindings.Note` with per-rule `QuickNote` overrides), so it was reachable by
    real usage, not just a theoretical edge case.
    """

    def test_quick_note_does_not_leak_between_rules_sharing_a_default(self):
        manager = Manager(
            client=SECURITYHUB_SESSION_CLIENT,
            DefaultRuleInput={
                "Filters": {},
                "UpdatesToFilteredFindings": {
                    "Note": {
                        "Text": "placeholder",
                        "UpdatedBy": "awsfindingsmanagerlib",
                    }
                },
            },
        )

        rules = manager.set_rules(
            [
                {"Filters": {}, "ExtraFeatures": {"QuickNote": "note A"}},
                {"Filters": {}, "ExtraFeatures": {"QuickNote": "note B"}},
            ]
        )

        self.assertEqual(rules[0].UpdatesToFilteredFindings["Note"]["Text"], "note A")
        self.assertEqual(rules[1].UpdatesToFilteredFindings["Note"]["Text"], "note B")
        self.assertEqual(
            manager.DefaultRuleInput["UpdatesToFilteredFindings"]["Note"]["Text"],
            "placeholder",
        )
        self.assertIsNot(
            rules[0].UpdatesToFilteredFindings, rules[1].UpdatesToFilteredFindings
        )
