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


class JSONFilter:
    def __init__(self, **kwargs: Any) -> None:
        self.name: str = kwargs.get("name", None)
        self.description: str = kwargs.get("description", "")
        self.features: Optional[List[Dict[str, Union[str, List[str]]]]] = kwargs.get(
            "features", None
        )
        self.code: Optional[List[int]] = kwargs.get("code", None)
        self.path: Optional[List[str]] = kwargs.get("path", None)
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

        if self.name is None:
            raise FilterValidationException(
                "Error: The JSON input is missing a name for the filter"
            )

        if missing_filtering_condition:
            filtering_conditions: List[str] = self._json_filtering_keys()
            raise FilterValidationException(
                f"Error: The JSON input must have at least one of the following keys: f{filtering_conditions}"
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
        self, o: JSONFilter
    ) -> Dict[str, Union[bool, List[int], List[str], Dict[str, Union[str, List[str]]]]]:
        filtering_conditions: Dict[str, Any] = {
            attribute: value
            for attribute, value in o.__dict__.items()
            if value is not None
        }
        filtering_conditions.pop("name", None)
        filtering_conditions.pop("description", None)
        return filtering_conditions
