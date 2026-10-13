"""The domain model that simplifies rule management."""

import copy
import logging
from dataclasses import dataclass, field
from typing import Any

from botocore.client import BaseClient

from awsfindingsmanagerlib.rule import Rule

LOGGER = logging.getLogger(__name__)

ALLOWED_MANAGER_CONFIG_KEYS = {"DefaultRuleInput"}


@dataclass(frozen=True)
class MatchAndUpdateResult:
    """The outcome of matching and updating a single finding against all configured rules.

    Attributes
    ----------
    matched_rules : int
        The number of rules that matched the finding.
    all_processed : bool
        True if there were no unprocessed findings for any of the matched rules'
        updates, False otherwise. Vacuously True when no rule matched.
    """

    matched_rules: int
    all_processed: bool


@dataclass
class Manager:
    """Dataclass managing rule creation."""

    client: BaseClient
    DefaultRuleInput: dict[str, Any] = field(default_factory=dict)
    _rules: list[Rule] = field(default_factory=list)

    @classmethod
    def from_rules_document(
        cls, rules: dict[str, Any], client: BaseClient
    ) -> "Manager":
        """Build a Manager with its rules registered from a parsed rules document.

        Parameters
        ----------
        rules : dict[str, Any]
            The parsed rules document. Must contain a top-level `Rules` key, and may contain a
            `ManagerConfig` key with a `DefaultRuleInput` sub-key.
        client : BaseClient
            The boto3 Security Hub client to use for the manager and its rules.

        Returns
        -------
        Manager
            A Manager with its rules already registered via `Manager.set_rules`.

        Raises
        ------
        ValueError
            If the rules document has no top-level `Rules` key, or if `ManagerConfig` contains
            keys other than `DefaultRuleInput` (most commonly caused by putting `ExtraFeatures`
            next to, rather than inside, `DefaultRuleInput`).
        """
        if "Rules" not in rules:
            msg = "The rules document must contain a top-level 'Rules' key."
            raise ValueError(msg)

        manager_config = rules.get("ManagerConfig", {})
        unknown_keys = set(manager_config) - ALLOWED_MANAGER_CONFIG_KEYS
        if unknown_keys:
            msg = (
                f"Unsupported 'ManagerConfig' key(s): {sorted(unknown_keys)}. "
                f"Allowed keys are: {sorted(ALLOWED_MANAGER_CONFIG_KEYS)}. "
                "'ExtraFeatures' and other rule fields belong inside 'DefaultRuleInput', "
                "not next to it."
            )
            raise ValueError(msg)

        manager = cls(**manager_config, client=client)
        manager.set_rules(rules["Rules"])
        return manager

    def _merge_inputs(
        self,
        default_input: dict[str, Any],
        rule_input: dict[str, Any],
    ) -> dict[str, Any]:
        """Recursively merge default and rule input dictionaries.

        Deep-copies `default_input` so the merged result (and anything nested in it, including
        branches a given `rule_input` doesn't override) never shares a mutable object with
        `self.DefaultRuleInput` or with the merge result for any other rule. Without this, a rule
        that mutates its own merged input in place (e.g. `Rule._apply_quick_note`) would silently
        corrupt `DefaultRuleInput` itself and leak into every other rule that also didn't override
        that branch.
        """
        merged: dict[str, Any] = copy.deepcopy(default_input)
        for key, value in rule_input.items():
            if (
                key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                merged[key] = self._merge_inputs(merged[key], value)
            else:
                merged[key] = copy.deepcopy(value)
        return merged

    def set_rules(self, rules_input: list[dict[str, Any]]) -> list[Rule]:
        """Create rules based on the provided input and the default rule input.

        Parameters
        ----------
        rules_input : list[dict[str, Any]]
            A list of dictionaries containing the rule input. Each dictionary will be merged with the DefaultRuleInput to create a complete rule input.

        Returns
        -------
        list[Rule]
            A list of Rule instances created from the input.
        """
        self._rules = []
        for rule_input in rules_input:
            merged_input = self._merge_inputs(self.DefaultRuleInput, rule_input)
            self._rules.append(Rule(**merged_input, client=self.client))
        return self._rules

    def get_and_update_all(self) -> bool:
        """Get all the findings matching the rules' filters from AWS SecurityHub and update them according to the rules' updates.

        Returns
        -------
        bool
            True if all findings were processed successfully, False otherwise
        """
        all_success = True
        for index, rule in enumerate(self._rules):
            LOGGER.info("Updating findings for rule no. %d", index + 1)
            success = rule.get_and_update()
            if not success:
                all_success = False
        return all_success

    def process_finding(self, finding: dict[str, Any]) -> MatchAndUpdateResult:
        """Match one finding against all configured rules and apply updates for each match.

        Unlike `match_and_update`, this also reports how many rules matched, so callers can
        distinguish "nothing matched" from "everything matched and was processed successfully".

        Parameters
        ----------
        finding : dict[str, Any]
            The finding to match and update.

        Returns
        -------
        MatchAndUpdateResult
            The number of rules that matched and whether all matching updates were processed.
        """
        any_unprocessed = False
        matched_rules = 0

        for index, rule in enumerate(self._rules):
            if not rule.match(finding):
                continue

            matched_rules += 1
            LOGGER.info("Finding matched rule no. %d", index + 1)

            any_unprocessed = rule.batch_update_findings([finding]) or any_unprocessed

        if matched_rules == 0:
            LOGGER.info("Finding did not match any rules; nothing to update.")

        return MatchAndUpdateResult(
            matched_rules=matched_rules, all_processed=not any_unprocessed
        )

    def match_and_update(self, finding: dict[str, Any]) -> bool:
        """Match one finding against all configured rules and apply updates for each match.

        Parameters
        ----------
        finding : dict[str, Any]
            The finding to match and update.

        Returns
        -------
        bool
            True if all matching updates were processed, False otherwise.
        """
        return self.process_finding(finding).all_processed
