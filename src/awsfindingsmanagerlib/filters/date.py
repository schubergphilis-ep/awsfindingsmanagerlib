"""AWS SecurityHub Finding Date Filters."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import ClassVar

from awsfindingsmanagerlib.utils import TimeRange

from .filters_interface import Criterion, Filter


@dataclass
class DateCriterion(Criterion):
    """Dataclass representing a SecurityHub Date Criterion.

    Either DateRange, or Start or End must be specified.

    Parameters
    ----------
    DateRange : dict[str, str]
        Optionally specify a relative date range with a 'Value' key indicating the number of days
    End : str
        Optionally specify an absolute end date in ISO format
    Start : str
        Optionally specify an absolute start date in ISO format
    """

    DateRange: dict[str, str] = field(default_factory=dict)
    End: str = ""
    Start: str = ""

    def _now_utc(self) -> datetime:
        """Having this method allows for easier mocking in tests."""
        return datetime.now(UTC)

    def __post_init__(self) -> None:
        """Initialize the date criterion on DateRange or Start/End."""
        self.time_range = (
            TimeRange(
                self._now_utc() - timedelta(days=int(self.DateRange["Value"])),
                None,
            )
            if self.DateRange
            else TimeRange.from_str(self.Start, self.End)
        )

    def match(self, finding_value: str) -> bool:
        """Check if a datetime string from a finding matches this date criterion.

        Parameters
        ----------
        finding_value : str
            The string from the finding to compare against

        Returns
        -------
        bool
            True if the finding_value matches the criterion, False otherwise
        """
        return self.time_range.is_timestamp_str_in_range(finding_value)


@dataclass
class DateFilter(Filter[str, DateCriterion]):
    """Dataclass representing a SecurityHub DateFilter to be applied on a single finding attribute."""

    criterion_type: ClassVar[type] = DateCriterion
    criterions: tuple[DateCriterion, ...]
