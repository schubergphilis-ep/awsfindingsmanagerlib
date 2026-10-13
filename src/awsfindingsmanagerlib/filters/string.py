"""AWS SecurityHub Finding String Filters."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import ClassVar

from .filters_interface import Criterion, Filter


def _str_prefix_ne_func(a: str, b: str) -> bool:
    return not str.startswith(a, b)


class StringComparisons(Enum):
    """The available string comparison operations linked to their functions."""

    EQUALS = partial(str.__eq__)
    PREFIX = partial(str.startswith)
    NOT_EQUALS = partial(str.__ne__)
    PREFIX_NOT_EQUALS = partial(_str_prefix_ne_func)


@dataclass
class _StringLikeCriterion(Criterion):
    """Dataclass representing a SecurityHub StringLike Criterion.

    Parameters
    ----------
    Comparison : str
        The comparison operation to use
    Value : str
        The value to compare against
    """

    Comparison: str
    Value: str


@dataclass
class StringCriterion(_StringLikeCriterion):
    """Dataclass representing a SecurityHub String Criterion.

    Parameters
    ----------
    Comparison : str
        The comparison operation to use
    Value : str
        The value to compare against
    """

    def __post_init__(self) -> None:
        """Get the comparison function based on the Comparison attribute."""
        self.comparison_func = StringComparisons[self.Comparison].value

    def match(self, finding_value: str) -> bool:
        """Check if a string from a finding matches this string criterion.

        Parameters
        ----------
        finding_value : str
            The string from the finding to compare against

        Returns
        -------
        bool
            True if the finding_value matches the criterion, False otherwise
        """
        return self.comparison_func(finding_value, self.Value)


def _get_combined_comparison(criterions: tuple[_StringLikeCriterion, ...]) -> Callable:
    negatives = tuple("NOT" in criterion.Comparison for criterion in criterions)
    if not any(negatives):
        return any
    if all(negatives):
        return all
    msg = """
            Mixed positive and negative string/map criterions are not supported:
            https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StringFilter.html
            https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_MapFilter.html
            """
    raise ValueError(msg)


@dataclass
class StringFilter(Filter[str, StringCriterion]):
    """Dataclass representing a SecurityHub StringFilter to be applied on a single finding attribute."""

    criterion_type: ClassVar[type] = StringCriterion
    criterions: tuple[StringCriterion, ...]

    def __post_init__(self) -> None:
        """Initialize the combined comparison function based on the types of criterions.

        All criterions must be either positive or negative.
        Raise ValueError if mixed criterions are found.
        """
        self.combined_comparison = _get_combined_comparison(self.criterions)
