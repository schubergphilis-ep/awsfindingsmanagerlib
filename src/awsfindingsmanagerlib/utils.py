"""Utilities for awsfindingsmanagerlib."""

from collections.abc import Callable, Collection
from dataclasses import dataclass, fields
from datetime import datetime


def is_valid_against_reference(
    candidate: object | None,
    reference: object,
    validator: Callable[..., bool],
) -> bool:
    """Check if 'reference' is falsy or whether it passes the 'validator' check against 'reference'."""
    return not reference or validator(candidate, reference)


def parse_timestamp_str_if_set(timestamp_str: str) -> datetime | None:
    """Parse an ISO format timestamp string to a datetime object if it is set.

    Parameters
    ----------
    timestamp_str : str
        The timestamp string in ISO format

    Returns
    -------
    datetime | None
        The parsed datetime object if the string is set, None otherwise
    """
    return datetime.fromisoformat(timestamp_str) if timestamp_str else None


@dataclass
class TimeRange:
    """Dataclass representing a time range with optional start or end."""

    start: datetime | None = None
    end: datetime | None = None

    def __post_init__(self) -> None:
        """Validate that at least one of start or end is set.

        Raises
        ------
        ValueError
            If neither start nor end is set.
        """
        if not self.start and not self.end:
            msg = "At least one of start or end must be set."
            raise ValueError(msg)

    @classmethod
    def from_str(cls, start_str: str, end_str: str) -> "TimeRange":
        """Create a TimeRange instance from ISO format timestamp strings.

        Parameters
        ----------
        start_str : str
            The start timestamp string in ISO format
        end_str : str
            The end timestamp string in ISO format

        Returns
        -------
        TimeRange
            The created TimeRange instance
        """
        start = parse_timestamp_str_if_set(start_str)
        end = parse_timestamp_str_if_set(end_str)
        return cls(start=start, end=end)

    def is_timestamp_in_range(self, timestamp: datetime) -> bool:
        """Check if a datetime timestamp is within the time range.

        Parameters
        ----------
        timestamp : datetime
            The datetime timestamp to check

        Returns
        -------
        bool
            True if the timestamp is within the range, False otherwise
        """
        return is_valid_against_reference(
            timestamp, self.start, datetime.__ge__
        ) and is_valid_against_reference(timestamp, self.end, datetime.__le__)

    def is_timestamp_str_in_range(self, timestamp_str: str) -> bool:
        """Check if a timestamp string is within the time range.

        Parameters
        ----------
        timestamp_str : str
            The timestamp string in ISO format to check

        Returns
        -------
        bool
            True if the timestamp string is within the time range, False otherwise
        """
        timestamp = datetime.fromisoformat(timestamp_str)
        return self.is_timestamp_in_range(timestamp)


def are_keys_in_collection(dict_: dict, collection: Collection) -> bool:
    """Check if all keys in a dict are in a collection.

    Parameters
    ----------
    dict_ : dict
        The dict to check
    collection : Collection
        The collection to check against

    Returns
    -------
    bool
        True if all keys in the dict are in the collection, False otherwise
    """
    return all(key in collection for key in dict_)


def are_keys_in_dataclass_fields(dict_: dict, dataclass_: type) -> bool:
    """Check if all keys in a dict are fields in a dataclass.

    Parameters
    ----------
    dict_ : dict
        The dict to check
    dataclass_ : type
        The dataclass to check against

    Returns
    -------
    bool
        True if all keys in the dict are fields in the dataclass, False otherwise
    """
    return are_keys_in_collection(dict_, {field.name for field in fields(dataclass_)})
