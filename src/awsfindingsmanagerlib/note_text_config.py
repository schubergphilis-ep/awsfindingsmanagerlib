"""Domain model for note text configuration."""

import logging
from dataclasses import dataclass

LOGGER = logging.getLogger(__name__)

NOTE_TEXT_CONFIG_MODE_VALUES = {"plaintext", "jsonUpdate"}


@dataclass
class NoteTextConfig:
    """Configuration for note text handling.

    Raises
    ------
    ValueError
        If the Mode is not one of the allowed values.
    ValueError
        If the Key is not a string when Mode is 'jsonUpdate'.
    """

    Mode: str
    Key: str = ""

    def __post_init__(self) -> None:
        """Validate the NoteTextConfig upon initialization."""
        if self.Mode not in NOTE_TEXT_CONFIG_MODE_VALUES:
            msg = (
                "'ExtraFeatures.NoteTextConfig.Mode' should be one of "
                "'plaintext' or 'jsonUpdate'"
            )
            raise ValueError(msg)

        if self.Mode == "jsonUpdate":
            if not isinstance(self.Key, str) or not self.Key:
                msg = (
                    "'ExtraFeatures.NoteTextConfig.Key' should be a non-empty string "
                    "when mode is 'jsonUpdate'"
                )
                raise ValueError(msg)
        elif self.Key:
            # A rule commonly only overrides Mode (e.g. back to 'plaintext') while the manager's
            # DefaultRuleInput sets a Key for its own 'jsonUpdate' default; since Manager merges
            # rule input into the default dict-wise, Key survives the merge even though it is
            # meaningless once Mode is 'plaintext'. Ignore it instead of rejecting an otherwise
            # valid rule.
            LOGGER.debug(
                "'ExtraFeatures.NoteTextConfig.Key' (%r) is ignored when mode is 'plaintext'.",
                self.Key,
            )
            self.Key = ""
