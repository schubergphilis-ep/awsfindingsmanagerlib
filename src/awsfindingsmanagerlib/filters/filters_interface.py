"""The shared functionality of all AWS SecurityHub Finding Filters."""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

TInput = TypeVar("TInput")


@dataclass
class Criterion[TInput](ABC):
    """Abstract base class for AWS Security Finding Filter criterion.

    Criterions are the individual filter conditions that make up a Filter.
    """

    @abstractmethod
    def match(self, finding_value: TInput) -> bool:
        """Check if a finding value matches this criterion.

        Parameters
        ----------
        finding_value : TInput
            The value from the finding to compare against the criterion

        Returns
        -------
        bool
            True if the finding_value matches the criterion, False otherwise
        """


TFilter = TypeVar("TFilter", bound=Criterion)


@dataclass
class Filter[TInput, TFilter: Criterion](ABC):
    """Abstract base class for an AWS Security Finding Filter.

    A Filter is made up of one or more single-typed Criterions combined with a logical operation
    Criterions are more strictly defined than a Filter.
    Therefore, a filter has a criterion_type attribute to indicate which type of Criterion it contains.
    """

    criterions: tuple[TFilter, ...]
    combined_comparison: Callable = any

    @property
    @abstractmethod
    def criterion_type(self) -> type:
        """The type of criterion this class relates to."""

    def match(self, finding_value: TInput) -> bool:
        """
        Check if a finding value matches the filter's criterions.

        Parameters
        ----------
        finding_value : TInput
            The value from the finding to compare against the criterions

        Returns
        -------
        bool
            True if the finding_value matches the combined criterions, False otherwise
        """
        return self.combined_comparison(
            criterion.match(finding_value) for criterion in self.criterions
        )
