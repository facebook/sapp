# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import json
from json import JSONEncoder
from typing import Dict, List, Set, Tuple, Union

from sapp.models import SharedTextKind
from sapp.pipeline import SourceLocation

from sqlalchemy.orm import Session
from typing_extensions import TypeAlias

from .queries import get_warning_message_range
from .sarif_types import (
    SARIFCodeflowLocationInnerObject,
    SARIFCodeflowLocationObject,
    SARIFCodeflowsObject,
    SARIFRegionObject,
    SARIFResult,
    SARIFSeverityLevel,
    SARIFThreadFlowObject,
)
from .ui import trace
from .ui.issues import IssueQueryResult
from .ui.trace import TraceFrameQueryResult, TraceKind


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


class SARIF:
    version: str = "2.1.0"
    schema: str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"  # noqa

    def __init__(
        self, tool: str, session: Session, filtered_issues: Set[IssueQueryResult]
    ) -> None:
        self._tool_warning_code_ranges = {
            "mariana-trench": (4000, 5000),
            "pysa": (5000, 6000),
        }
        driver_json = {}
        self.tool = tool
        if self.tool == "pysa":
            driver_json["name"] = "Pysa"
            driver_json["informationUri"] = "https://github.com/facebook/pyre-check/"
        elif self.tool == "mariana-trench":
            driver_json["name"] = "Mariana Trench"
            driver_json[
                "informationUri"
            ] = "https://github.com/facebook/mariana-trench/"
        else:
            raise NotImplementedError

        tool_warning_messages = get_warning_message_range(
            session,
            self._tool_warning_code_ranges[self.tool][0],
            self._tool_warning_code_ranges[self.tool][1],
        )
        rules_json = []
        for rule in tool_warning_messages:
            rules_json.append({"id": str(rule.code), "name": rule.message})
        driver_json["rules"] = rules_json
        self.driver = driver_json
        self.results = [
            self.issue_to_sarif(session, issue) for issue in filtered_issues
        ]

    def issue_to_sarif(
        self,
        session: Session,
        issue: IssueQueryResult,
        severity_level: str = "warning",
    ) -> SARIFResult:
        location: SARIFCodeflowLocationInnerObject = {
            "physicalLocation": {
                "artifactLocation": {"uri": issue.filename},
                "region": self.source_location_to_sarif(issue.location),
            }
        }
        result: SARIFResult = {
            "ruleId": str(issue.code),
            "level": str(SARIFSeverityLevel(severity_level)),
            "message": {
                "text": issue.message,
            },
            "locations": [location],
            "codeFlows": self.trace_to_sarif(session, issue, output_features=True),
        }
        return result

    def trace_to_sarif(
        self,
        session: Session,
        issue: IssueQueryResult,
        output_features: bool = False,
    ) -> SARIFCodeflowsObject:
        postcondition_initial_frames = trace.initial_frames(
            session,
            issue.issue_instance_id,
            TraceKind.POSTCONDITION,
        )
        precondition_initial_frames = trace.initial_frames(
            session,
            issue.issue_instance_id,
            TraceKind.PRECONDITION,
        )
        postcondition_navigation = trace.navigate_trace_frames(
            session,
            postcondition_initial_frames,
            set(issue.source_kinds),
            set(issue.sink_kinds),
        )
        precondition_navigation = trace.navigate_trace_frames(
            session,
            precondition_initial_frames,
            set(issue.source_kinds),
            set(issue.sink_kinds),
        )
        trace_tuples = trace.create_trace_tuples(
            reversed(postcondition_navigation)
        ) + trace.create_trace_tuples(precondition_navigation)
        codeflows: List[SARIFCodeflowLocationObject] = []
        nesting_level = 0
        for trace_tuple in trace_tuples:
            location = self._sarif_codeflow_location_from_trace_tuple(
                trace_tuple.trace_frame, nesting_level, output_features
            )
            codeflows.append(location)
            nesting_level += 1
        threadflow: SARIFThreadFlowObject = {"locations": codeflows}
        return [{"threadFlows": [threadflow]}]

    def source_location_to_sarif(self, location: SourceLocation) -> SARIFRegionObject:
        region: SARIFRegionObject = {
            "startLine": location.line_no,
            "startColumn": location.begin_column,
        }
        if location.end_column:
            region["endColumn"] = location.end_column + 1
        return region

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self, cls=SARIFEncoder, indent=indent)

    def _sarif_codeflow_location_from_trace_tuple(
        self,
        trace_frame: TraceFrameQueryResult,
        nesting_level: int = 1,
        output_features: bool = False,
    ) -> SARIFCodeflowLocationObject:
        features_str = titos = ""
        if output_features:
            frame_features = [
                text.contents
                for text in trace_frame.shared_texts
                if text.kind is SharedTextKind.FEATURE
            ]
            if frame_features:
                features_str = f"features: {frame_features}"
            if trace_frame.titos and len(trace_frame.titos.split(";")) > 0:
                titos = f"via {len(trace_frame.titos.split(';'))} propagators"
        trace_region = {}
        if trace_frame.callee_location:
            trace_region = self.source_location_to_sarif(trace_frame.callee_location)
        return {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": trace_frame.filename,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": trace_region,
                },
                "message": {
                    "text": (
                        f"flow from {trace_frame.get_human_readable_caller(self.tool)}"
                        f"(...{trace_frame.caller_port}...)"
                        f" -[into]-> {trace_frame.get_human_readable_callee(self.tool)}"
                        f"(...{trace_frame.callee_port}...)"
                        f" {titos} {features_str}".strip()
                    )
                },
            },
            "nestingLevel": nesting_level,
        }


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
