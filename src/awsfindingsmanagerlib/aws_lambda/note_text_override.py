"""Force a note text configuration on a rules document from the Lambda's environment.

Some deployments must not let a rules document choose its own note handling. A ticketing
integration that stores metadata such as `jiraIssue` in a finding's note, for instance, depends
on every suppression merging into that note rather than overwriting it. Setting the
`NOTE_TEXT_CONFIG_MODE` environment variable (and optionally `NOTE_TEXT_CONFIG_KEY`) makes the
handlers in `awsfindingsmanagerlib.aws_lambda` apply that configuration to every rule, whatever the
rules document says.
"""

import copy
import logging
import os
from typing import Any

from awsfindingsmanagerlib.note_text_config import NoteTextConfig

LOGGER = logging.getLogger(__name__)

NOTE_TEXT_CONFIG_MODE_ENV = "NOTE_TEXT_CONFIG_MODE"
NOTE_TEXT_CONFIG_KEY_ENV = "NOTE_TEXT_CONFIG_KEY"
DEFAULT_JSON_UPDATE_KEY = "Note"


def get_note_text_config_override() -> NoteTextConfig | None:
    """Get the note text configuration forced by the environment, if any.

    Reads `NOTE_TEXT_CONFIG_MODE` (`plaintext` or `jsonUpdate`) and, for `jsonUpdate`,
    `NOTE_TEXT_CONFIG_KEY`, which defaults to `Note`.

    Returns
    -------
    NoteTextConfig | None
        The forced configuration, or None if `NOTE_TEXT_CONFIG_MODE` is not set.

    Raises
    ------
    ValueError
        If `NOTE_TEXT_CONFIG_MODE` is set to an unsupported value.
    """
    mode = os.environ.get(NOTE_TEXT_CONFIG_MODE_ENV)
    if not mode:
        return None

    key = os.environ.get(NOTE_TEXT_CONFIG_KEY_ENV) or (
        DEFAULT_JSON_UPDATE_KEY if mode == "jsonUpdate" else ""
    )
    return NoteTextConfig(Mode=mode, Key=key)


def apply_note_text_config_override(rules_document: dict[str, Any]) -> dict[str, Any]:
    """Apply the note text configuration forced by the environment to a rules document.

    Sets `ManagerConfig.DefaultRuleInput.ExtraFeatures.NoteTextConfig` to the forced
    configuration and replaces any rule's own `ExtraFeatures.NoteTextConfig` with it, logging a
    warning for every rule whose configuration differed. The input document is not modified.

    Parameters
    ----------
    rules_document : dict[str, Any]
        The parsed rules document, as passed to `awsfindingsmanagerlib.Manager.from_rules_document`.

    Returns
    -------
    dict[str, Any]
        The rules document with the forced configuration applied, or the input document itself
        if `NOTE_TEXT_CONFIG_MODE` is not set.
    """
    override = get_note_text_config_override()
    if override is None:
        return rules_document

    forced = {"Mode": override.Mode}
    if override.Key:
        forced["Key"] = override.Key

    document = copy.deepcopy(rules_document)
    default_input = document.setdefault("ManagerConfig", {}).setdefault(
        "DefaultRuleInput", {}
    )
    default_input.setdefault("ExtraFeatures", {})["NoteTextConfig"] = dict(forced)

    for index, rule in enumerate(document.get("Rules", []), start=1):
        extra_features = rule.get("ExtraFeatures", {})
        if "NoteTextConfig" not in extra_features:
            continue
        if extra_features["NoteTextConfig"] != forced:
            LOGGER.warning(
                "Rule no. %d sets NoteTextConfig %s, which is overridden by %s from the "
                "environment.",
                index,
                extra_features["NoteTextConfig"],
                forced,
            )
        extra_features["NoteTextConfig"] = dict(forced)

    return document
