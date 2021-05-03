# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from __future__ import annotations

import json
from json import JSONEncoder
from pathlib import Path
from typing import Dict, Union, List, Optional, Any, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .ui.schema import FeatureCondition


class FilterValidationException(Exception):
    pass


class Filter:
    def __init__(self, **kwargs: Any) -> None:
        self.features: List[Dict[str, Union[str, List[str]]]] = kwargs.get(
            "features", []
        )
        self.codes: List[int] = kwargs.get("codes", [])
        self.paths: List[str] = kwargs.get("paths", [])
        self.callables: List[str] = kwargs.get("callables", [])
        self.traceLengthFromSources: Optional[List[int]] = kwargs.get(
            "traceLengthFromSources", None
        )
        self.traceLengthToSinks: Optional[List[int]] = kwargs.get(
            "traceLengthToSinks", None
        )
        self.is_new_issue: Optional[bool] = kwargs.get("is_new_issue", None)

        missing_filtering_condition: bool = all(
            self.__getattribute__(key) is None or self.__getattribute__(key) == []
            for key in self._json_filtering_keys()
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
        callables: List[str],
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
            # pyre-ignore [6] You can use list() to convert graphene.List to Python list
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
