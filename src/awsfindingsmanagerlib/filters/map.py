"""AWS SecurityHub Finding String Filters."""

from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import ClassVar

from .filters_interface import Filter
from .string import _get_combined_comparison, _StringLikeCriterion


class MapStringComparisons(Enum):
    """The available map string comparison operations linked to their functions."""

    EQUALS = partial(str.__eq__)
    NOT_EQUALS = partial(str.__ne__)


@dataclass
class MapCriterion(_StringLikeCriterion):
    """Dataclass representing a SecurityHub Map Criterion.

    Parameters
    ----------
    Comparison : str
        The comparison operation to use
    Key : str
        The key in the map to compare against
    Value : str
        The value to compare against
    """

    Key: str

    def __post_init__(self) -> None:
        """Get the comparison function based on the Comparison attribute."""
        self.comparison_func = MapStringComparisons[self.Comparison].value

    def match(self, finding_value: dict[str, str]) -> bool:
        """Check if a string from a map in the finding matches this string criterion.

        Parameters
        ----------
        finding_value : dict[str, str]
            The map from the finding to compare against

        Returns
        -------
        bool
            True if the finding_value matches the criterion, False otherwise
        """
        return self.Key in finding_value and self.comparison_func(
            finding_value[self.Key], self.Value
        )


@dataclass
class MapFilter(Filter[dict[str, str], MapCriterion]):
    """Dataclass representing a SecurityHub MapFilter to be applied on a single finding attribute."""

    criterion_type: ClassVar[type] = MapCriterion
    criterions: tuple[MapCriterion, ...]

    def __post_init__(self) -> None:
        """Initialize the combined comparison function based on the types of criterions.

        All criterions must be either positive or negative.
        Raise ValueError if mixed criterions are found.
        """
        self.combined_comparison = _get_combined_comparison(self.criterions)
