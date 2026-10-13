"""Convenient functionality to create AWS SecurityHub Finding Filters in a dynamic way."""

from enum import Enum
from typing import Any

from botocore.client import BaseClient

from awsfindingsmanagerlib.awsfindingsmanagerlib import validate_filters
from awsfindingsmanagerlib.utils import are_keys_in_dataclass_fields

from .cidr import CidrFilter
from .date import DateFilter
from .filters_interface import Filter
from .map import MapFilter
from .number import NumberFilter
from .regex_string import RegexStringFilter
from .string import StringFilter


class AllFilters(Enum):
    """Enum representing all available AwsSecurityFindingFilters types."""

    NUMBER_FILTERS = NumberFilter
    DATE_FILTERS = DateFilter
    STRING_FILTERS = StringFilter
    # StringFilter must be before MapFilter in the enum,
    # otherwise string filter dicts would match to MapFilter,
    # since all of their keys are also in MapFilter's criterion type
    MAP_FILTERS = MapFilter
    CIDR_FILTERS = CidrFilter


def match_to_filter_type(
    filter_dict: dict[str, Any],
) -> type[Filter]:
    """Match a filters dict to an AwsSecurityFindingFilters type.

    Parameters
    ----------
    filter_dict : dict[str, Any]
        The filters dict to match

    Returns
    -------
    type[Filter]
        The matched AwsSecurityFindingFilters type
    """
    return next(
        filter_type.value
        for filter_type in AllFilters
        if are_keys_in_dataclass_fields(filter_dict, filter_type.value.criterion_type)
    )


def create_filters(
    filters_dicts: list[dict[str, Any]],
) -> Filter:
    """Create an AwsSecurityFindingFilters instance from a list of filters dicts.

    Filters dicts must all correspond to the same AwsSecurityFindingFilters type.

    Parameters
    ----------
    filters_dicts : list[dict[str, Any]]
        The filters dicts to create the AwsSecurityFindingFilters instance from

    Returns
    -------
    Filter
        The created AwsSecurityFindingFilters instance
    """
    filter_type = match_to_filter_type(filters_dicts[0])
    return filter_type(
        criterions=tuple(
            filter_type.criterion_type(**comparison) for comparison in filters_dicts
        )
    )


def create_regex_string_filters(
    regex_string_filters: dict[str, list[str]], client: BaseClient
) -> dict[str, RegexStringFilter]:
    """Create regex string filters from ExtraFeatures.RegexStringFilters."""
    if not isinstance(regex_string_filters, dict):
        msg = "'ExtraFeatures.RegexStringFilters' should be a dictionary"
        raise TypeError(msg)

    compiled_filters: dict[str, RegexStringFilter] = {}
    for field_name, patterns in regex_string_filters.items():
        # Validate the regex string filter name with boto3 to ensure they indeed relate to a string-valued field in a finding
        validate_filters(
            {field_name: [{"Value": "dummy", "Comparison": "EQUALS"}]}, client
        )
        if not isinstance(patterns, list):
            msg = "Each value in 'ExtraFeatures.RegexStringFilters' should be a list of regex strings"
            raise TypeError(msg)
        if not all(isinstance(pattern, str) for pattern in patterns):
            msg = (
                "Each pattern in 'ExtraFeatures.RegexStringFilters' should be a string"
            )
            raise TypeError(msg)

        criterions = []
        for pattern in patterns:
            try:
                criterions.append(RegexStringFilter.criterion_type(Value=pattern))
            except ValueError as exc:
                msg = f"Invalid regex pattern '{pattern}' for '{field_name}': {exc}"
                raise ValueError(msg) from exc

        compiled_filters[field_name] = RegexStringFilter(criterions=tuple(criterions))

    return compiled_filters
