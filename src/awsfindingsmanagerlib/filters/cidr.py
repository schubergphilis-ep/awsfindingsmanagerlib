"""AWS SecurityHub Finding Cidr Filters."""

from dataclasses import dataclass
from typing import ClassVar

from .filters_interface import Criterion, Filter


@dataclass
class CidrCriterion(Criterion):
    """Dataclass representing a SecurityHub Cidr Criterion.

    Parameters
    ----------
    Cidr : str
        The CIDR to match against
    """

    Cidr: str = ""

    def match(self, finding_value: str) -> bool:
        """Check if a CIDR string from a finding matches this CIDR criterion.

        Parameters
        ----------
        finding_value : str
            The CIDR string from the finding to compare against

        Returns
        -------
        bool
            True if the finding_value matches the criterion, False otherwise
        """
        return self.Cidr == finding_value


@dataclass
class CidrFilter(Filter[str, CidrCriterion]):
    """Dataclass representing a SecurityHub CidrFilter to be applied on a single finding attribute."""

    criterion_type: ClassVar[type] = CidrCriterion
    criterions: tuple[CidrCriterion, ...]
