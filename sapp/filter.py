# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import json
from json import JSONEncoder
from typing import Dict, Union, List, Optional, Any


class FilterValidationException(Exception):
    pass


class Filter:
    def __init__(self, **kwargs: Any) -> None:
        self.features: Optional[List[Dict[str, Union[str, List[str]]]]] = kwargs.get(
            "features", None
        )
        self.codes: Optional[List[int]] = kwargs.get("codes", None)
        self.paths: Optional[List[str]] = kwargs.get("paths", None)
        self.callables: Optional[List[str]] = kwargs.get("callables", None)
        self.traceLengthFromSources: Optional[List[int]] = kwargs.get(
            "traceLengthFromSources", None
        )
        self.traceLengthToSinks: Optional[List[int]] = kwargs.get(
            "traceLengthToSinks", None
        )
        self.is_new_issue: Optional[bool] = kwargs.get("is_new_issue", None)

        missing_filtering_condition: bool = all(
            self.__getattribute__(key) is None for key in self._json_filtering_keys()
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


class FilterEncoder(JSONEncoder):
    def default(
        self, o: Filter
    ) -> Dict[str, Union[bool, List[int], List[str], Dict[str, Union[str, List[str]]]]]:
        filtering_conditions: Dict[str, Any] = {
            attribute: value
            for attribute, value in o.__dict__.items()
            if value is not None
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
