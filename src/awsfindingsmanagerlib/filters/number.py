"""AWS SecurityHub Finding String Filters."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import ClassVar

from .filters_interface import Criterion, Filter


class NumberComparisons(Enum):
    """The available number comparison operations linked to their functions."""

    Eq = partial(float.__eq__)
    Gt = partial(float.__gt__)
    Gte = partial(float.__ge__)
    Lt = partial(float.__lt__)
    Lte = partial(float.__le__)


def _set_second_argument(
    func: Callable[[float, float], bool], b: float
) -> Callable[[float], bool]:
    return lambda a: func(a, b)


@dataclass
class NumberCriterion(Criterion):
    """Dataclass representing a SecurityHub Number Criterion.

    Parameters
    ----------
    Eq : float
        The value to compare for equality
    Gt : float
        The value to compare for greater than
    Gte : float
        The value to compare for greater than or equal to
    Lt : float
        The value to compare for less than
    Lte : float
        The value to compare for less than or equal to
    """

    Eq: float | None = None
    Gt: float | None = None
    Gte: float | None = None
    Lt: float | None = None
    Lte: float | None = None

    def __post_init__(self) -> None:
        """Get the comparison functions based on which attributes are set."""
        self.comparison_functions = tuple(
            _set_second_argument(number_comparison.value, comparison_value)
            for number_comparison in NumberComparisons
            if (comparison_value := getattr(self, number_comparison.name)) is not None
        )
        if not self.comparison_functions:
            msg = "At least one comparison operation must be specified."
            raise ValueError(msg)

    def match(self, finding_value: float) -> bool:
        """Check if a number from a finding matches this number criterion.

        Parameters
        ----------
        finding_value : float
            The number from the finding to compare against

        Returns
        -------
        bool
            True if the finding_value matches the criterion, False otherwise
        """
        return all(
            # duck typing int to float does not work when using partial on float methods
            # therefore explicitly cast finding_value to float
            comparison_function(float(finding_value))
            for comparison_function in self.comparison_functions
        )


@dataclass
class NumberFilter(Filter[float, NumberCriterion]):
    """Dataclass representing a SecurityHub NumberFilter to be applied on a single finding attribute."""

    criterion_type: ClassVar[type] = NumberCriterion
    criterions: tuple[NumberCriterion, ...]
