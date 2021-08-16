# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import json
from dataclasses import dataclass, field
from json import JSONEncoder
from typing import Set, Dict, Union, List, Tuple

from sqlalchemy.orm import Session
from typing_extensions import TypeAlias

from .queries import get_warning_message_range
from .sarif_types import SARIFResult
from .ui.issues import IssueQueryResult


SARIFOutput: TypeAlias = Dict[
    str,
    Union[
        List[
            Dict[
                str,
                Union[
                    Dict[str, Dict[str, Union[List[Dict[str, str]], str]]],
                    List[SARIFResult],
                ],
            ]
        ],
        str,
    ],
]


@dataclass
class SARIF:
    version: str = "2.1.0"
    schema: str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"  # noqa
    _tool_warning_code_ranges: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    driver: Dict[str, Union[str, List[Dict[str, str]]]] = field(default_factory=dict)
    results: List[SARIFResult] = field(default_factory=list)

    def __init__(
        self, tool: str, session: Session, filtered_issues: Set[IssueQueryResult]
    ) -> None:
        self._tool_warning_code_ranges = {
            "mariana-trench": (4000, 5000),
            "pysa": (5000, 6000),
        }
        driver_json = {}
        if tool == "pysa":
            driver_json["name"] = "Pysa"
            driver_json["informationUri"] = "https://github.com/facebook/pyre-check/"

            tool_warning_messages = get_warning_message_range(
                session,
                self._tool_warning_code_ranges[tool][0],
                self._tool_warning_code_ranges[tool][1],
            )
            rules_json = []
            for rule in tool_warning_messages:
                rules_json.append({"id": str(rule.code), "name": rule.message})
            driver_json["rules"] = rules_json
        else:
            raise NotImplementedError

        self.driver = driver_json
        self.results = [issue.to_sarif() for issue in filtered_issues]

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self, cls=SARIFEncoder, indent=indent)


class SARIFEncoder(JSONEncoder):
    def default(self, o: SARIF) -> SARIFOutput:
        return {
            "version": o.version,
            "$schema": o.schema,
            "runs": [
                {
                    "tool": {"driver": o.driver},
                    "results": o.results,
                }
            ],
        }
