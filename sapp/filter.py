# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from __future__ import annotations

import json
import sys
from json import JSONEncoder
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union

from sqlalchemy import Column, String

from .models import Base

if TYPE_CHECKING:
    from .ui.schema import FeatureCondition, MatchesIsField

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict


class NewMatchesIsAlias(TypedDict):
    operation: str
    value: List[str]


# Previously the field contained values in form of a list, maintain Union for
# backward compatibility.
MatchesIsAlias = Union[NewMatchesIsAlias, List[str]]


class FilterRecord(Base):
    __tablename__ = "filters"

    name: Column[str] = Column(
        String(length=255), nullable=False, unique=True, primary_key=True
    )
    description: Column[Optional[str]] = Column(String(length=1024), nullable=True)

    json: Column[str] = Column(
        String(length=1024), nullable=False, doc="JSON representation of the filter"
    )


class FilterValidationException(Exception):
    pass


class Filter:
    def __init__(self, **kwargs: Any) -> None:
        self.features: List[Dict[str, Union[str, List[str]]]] = kwargs.get(
            "features", []
        )
        self.codes: List[int] = kwargs.get("codes", [])
        self.paths: List[str] = kwargs.get("paths", [])
        self.callables: MatchesIsAlias = kwargs.get("callables", [])
        self.statuses: List[str] = kwargs.get("statuses", [])
        self.source_names: MatchesIsAlias = kwargs.get("source_names", [])
        self.source_kinds: MatchesIsAlias = kwargs.get("source_kinds", [])
        self.sink_names: MatchesIsAlias = kwargs.get("sink_names", [])
        self.sink_kinds: MatchesIsAlias = kwargs.get("sink_kinds", [])
        self.traceLengthFromSources: Optional[List[int]] = kwargs.get(
            "traceLengthFromSources", None
        )
        self.traceLengthToSinks: Optional[List[int]] = kwargs.get(
            "traceLengthToSinks", None
        )
        self.is_new_issue: Optional[bool] = kwargs.get("is_new_issue", None)

        missing_filtering_condition: bool = all(
            getattr(self, key) in (None, []) for key in self._json_filtering_keys()
        )

        if missing_filtering_condition:
            filtering_conditions: List[str] = self._json_filtering_keys()
            raise FilterValidationException(
                f"Error: The filter must have at least one of the following keys: f{filtering_conditions}"
            )

    def _json_filtering_keys(self) -> List[str]:
        return [
            attribute
            for attribute in self.__dict__.keys()
            if not attribute.startswith("__")
            and not callable(attribute)
            and attribute != "name"
            and attribute != "description"
        ]

    def to_json(self) -> str:
        return json.dumps(self, cls=FilterEncoder)

    def format_features_for_query(self) -> List[Tuple[str, List[str]]]:
        formatted_features = []
        if self.features is not None:
            for feature in self.features:
                formatted_features.append((feature["mode"], feature["features"]))
        return formatted_features

    @staticmethod
    def from_query(
        codes: List[int],
        paths: List[str],
        callables: Optional[MatchesIsField],
        statuses: List[str],
        source_names: Optional[MatchesIsField],
        source_kinds: Optional[MatchesIsField],
        sink_names: Optional[MatchesIsField],
        sink_kinds: Optional[MatchesIsField],
        features: Optional[List[FeatureCondition]],
        min_trace_length_to_sinks: Optional[int],
        max_trace_length_to_sinks: Optional[int],
        min_trace_length_to_sources: Optional[int],
        max_trace_length_to_sources: Optional[int],
        is_new_issue: Optional[bool],
    ) -> Filter:

        restructured_features: List[Dict[str, Union[str, List[str]]]] = []
        for filtering_condition in features or []:
            feature_entry = {}
            feature_entry["mode"] = filtering_condition.mode
            feature_entry["features"] = list(filtering_condition.features)
            restructured_features.append(feature_entry)

        traceLengthFromSources: Optional[List[int]] = None
        if (
            min_trace_length_to_sources is not None
            or max_trace_length_to_sources is not None
        ):
            traceLengthFromSources = [
                min_trace_length_to_sources or 0,
                max_trace_length_to_sources or 31,
            ]

        traceLengthToSinks: Optional[List[int]] = None
        if (
            min_trace_length_to_sinks is not None
            or max_trace_length_to_sinks is not None
        ):
            traceLengthToSinks = [
                min_trace_length_to_sinks or 0,
                max_trace_length_to_sinks or 31,
            ]

        return Filter(
            features=restructured_features,
            codes=codes,
            paths=paths,
            callables=callables,
            statuses=statuses,
            source_names=source_names,
            source_kinds=source_kinds,
            sink_names=sink_names,
            sink_kinds=sink_kinds,
            traceLengthFromSources=traceLengthFromSources,
            traceLengthToSinks=traceLengthToSinks,
            is_new_issue=is_new_issue,
        )


class FilterEncoder(JSONEncoder):
    def default(
        self, o: Filter
    ) -> Dict[str, Union[bool, List[int], List[str], Dict[str, Union[str, List[str]]]]]:
        filtering_conditions: Dict[str, Any] = {
            attribute: value
            for attribute, value in o.__dict__.items()
            if value and value != ["%"]
        }
        filtering_conditions.pop("name", None)
        filtering_conditions.pop("description", None)
        return filtering_conditions


class StoredFilter(Filter):
    def __init__(self, name: str, description: str = "", **kwargs: Any) -> None:
        self.name = name
        if self.name is None:
            raise FilterValidationException("Error: A StoredFilter must have a name")
        self.description = description
        if self.description is None:
            raise FilterValidationException(
                "Error: A StoredFilter description cannot be `None`"
            )
        super(StoredFilter, self).__init__(**kwargs)

    @staticmethod
    def from_file(input_path: Path) -> StoredFilter:
        json_blob: Dict[str, Any] = json.loads(input_path.read_text())
        return StoredFilter(**json_blob)

    @staticmethod
    def from_record(record: FilterRecord) -> StoredFilter:
        return StoredFilter(
            record.name, record.description or "", **json.loads(record.json)
        )

    def to_record(self) -> FilterRecord:
        return FilterRecord(
            name=self.name,
            description=self.description,
            json=self.to_json(),
        )

    def to_file(self) -> str:
        output_json: Dict[str, Any] = {
            attribute: value
            for attribute, value in self.__dict__.items()
            if value and value != ["%"]
        }
        return json.dumps(output_json, indent=4)
