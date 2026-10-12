"""AWS SecurityHub custom regex string filters."""

import re
from dataclasses import dataclass, field
from typing import ClassVar

from .filters_interface import Criterion, Filter


@dataclass
class RegexStringCriterion(Criterion[str]):
    """Dataclass representing a regex string criterion.

    Parameters
    ----------
    Value : str
        The regex string to search for
    """

    Value: str
    _pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Compile the regex pattern from Value."""
        try:
            self._pattern = re.compile(self.Value)
        except re.error as exc:
            raise ValueError(str(exc)) from exc

    def match(self, finding_value: str) -> bool:
        """Check if the regex pattern matches a finding string value."""
        return bool(self._pattern.search(finding_value))


@dataclass
class RegexStringFilter(Filter[str, RegexStringCriterion]):
    """Dataclass representing regex string filters for a finding field."""

    criterion_type: ClassVar[type] = RegexStringCriterion
    criterions: tuple[RegexStringCriterion, ...]
