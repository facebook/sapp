# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import json
import logging
import re
import sys

from collections import defaultdict
from typing import (
    Any,
    Dict,
    IO,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from .. import pipeline as sapp
from ..analysis_output import AnalysisOutput, Metadata
from .base_parser import BaseParser

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


log: logging.Logger = logging.getLogger()
UNKNOWN_PATH: str = "unknown"
UNKNOWN_LINE: int = -1


class Method(NamedTuple):
    name: str

    @staticmethod
    def from_json(method: Union[str, Dict[str, Any]]) -> "Method":
        if isinstance(method, str):
            return Method(method)

        canonical_name = method["name"]

        parameter_type_overrides = method.get("parameter_type_overrides")
        if parameter_type_overrides:
            parameter_type_overrides = (
                f"{override['parameter']}: {override['type']}"
                for override in parameter_type_overrides
            )
            canonical_name += "[%s]" % ", ".join(parameter_type_overrides)

        return Method(canonical_name)


class Port(NamedTuple):
    value: str

    def is_leaf(self) -> bool:
        return (
            self.value in ("source", "sink")
            or self.value.startswith("anchor:")
            or self.value.startswith("producer:")
        )

    @staticmethod
    def to_crtex(port: str) -> str:
        """Converts 'argument(n)' to 'formal(n)'. Other CRTEX tools use 'formal'
        to denote argument positions."""
        return re.sub(r"argument\((-?\d+)\)", r"formal(\1)", port)

    @staticmethod
    def from_json(port: str, leaf_kind: str) -> "Port":
        elements = port.split(".")

        if len(elements) == 0:
            raise sapp.ParseError(f"Invalid port: `{port}`.")

        elements[0] = elements[0].lower()
        if elements[0] == "leaf":
            elements[0] = leaf_kind
        elif elements[0] == "return":
            elements[0] = "result"
        elif elements[0] == "anchor":
            # Anchor port is of the form Anchor.<MT port, e.g. Argument(0)>
            # SAPP/CRTEX expects: "anchor:formal(0)"
            canonical_port = Port.from_json(
                ".".join(elements[1:]), "unreachable_leaf_kind_anchor"
            )
            return Port(f"{elements[0]}:{Port.to_crtex(canonical_port.value)}")
        elif elements[0] == "producer" and len(elements) >= 3:
            # Producer port is of the form Producer.<producer_id>.<MT port>.
            # SAPP/CRTEX expects: "producer:<producer_id>:<canonical_port>".
            root = elements[0]
            producer_id = elements[1]
            canonical_port = Port.from_json(
                ".".join(elements[2:]), "unreachable_leaf_kind_producer"
            )
            return Port(f"{root}:{producer_id}:{Port.to_crtex(canonical_port.value)}")

        return Port(".".join(elements))


class Position(NamedTuple):
    path: str
    line: int
    start: int
    end: int

    @staticmethod
    def default() -> "Position":
        return Position(UNKNOWN_PATH, UNKNOWN_LINE, 0, 0)

    @staticmethod
    def from_json(position: Dict[str, Any], method: Optional[Method]) -> "Position":
        path = position.get("path", UNKNOWN_PATH)
        line = position.get("line", UNKNOWN_LINE)
        start = position.get("start", 0) + 1
        end = max(position.get("end", 0) + 1, start)
        if path == UNKNOWN_PATH and method:
            path = method.name.split(";")[0]
            path = path.split("$")[0]
            path = path[1:]
        return Position(path, line, start, end)

    def to_sapp(self) -> sapp.SourceLocation:
        return sapp.SourceLocation(
            line_no=self.line,
            begin_column=self.start,
            end_column=self.end,
        )


class Origin(NamedTuple):
    callee_name: Method
    callee_port: Port

    @staticmethod
    def from_json(leaf_json: Dict[str, Any], leaf_kind: str) -> "Origin":
        """
        Depending on the origin kind, the json keys will vary:

        Method origin (most common): { "method" : ... , "port" : ... }
        Field origin: { "field" : ... }
          No port for field origins. Always assumed to be "Leaf".
        Crtex origin : { "canonical_name" : ... , "port" : ... }
        """
        callee = leaf_json.get(
            "method", leaf_json.get("field", leaf_json.get("canonical_name"))
        )
        if not callee:
            raise sapp.ParseError(f"No callee found in origin {leaf_json}.")
        callee_name = Method.from_json(callee)

        # The origin represents a call to a leaf/terminal trace. Its port should
        # indicate that, so that downstream trace reachability computation knows
        # when it has reached the end. See trace_graph.is_leaf_port(). Non-CRTEX
        # ports should always be <leaf_kind> regardless of the JSON (e.g. method
        # origins could indicate that the sink comes from "argument(1)"", but it
        # needs to be "sink" in sapp).
        callee_port = Port.from_json("leaf", leaf_kind)
        if "canonical_name" in leaf_json:
            # All CRTEX ports are considered leaf ports.
            callee_port = Port.from_json(leaf_json["port"], leaf_kind)

        if not callee_port.is_leaf():
            raise sapp.ParseError(f"Encountered non-leaf port in origin {leaf_json}")

        return Origin(callee_name, callee_port)


class CallInfo(NamedTuple):
    """Mirrors the CallInfo object in the analysis"""

    call_kind: str
    method: Optional[Method]
    port: Port
    position: Position

    @staticmethod
    def from_json(
        taint_json: Dict[str, Any], leaf_kind: str, caller_position: Position
    ) -> "CallInfo":
        call_kind = taint_json["call_kind"]

        callee = taint_json.get("resolves_to")
        method = Method.from_json(callee) if callee else None
        port = Port.from_json(taint_json.get("port", "leaf"), leaf_kind)

        position_json = taint_json.get("position")
        position = (
            caller_position
            if not position_json
            else Position.from_json(position_json, method)
        )
        return CallInfo(call_kind, method, port, position)

    def is_declaration(self) -> bool:
        """Can can be a declaration for a source/sink (call_kind == Declaration)
        or a propagation (call_kind == PropagationWithTrace:Declaration)"""
        return "Declaration" in self.call_kind

    def is_origin(self) -> bool:
        return "Origin" in self.call_kind

    def is_propagation_without_trace(self) -> bool:
        return "Propagation" == self.call_kind


class LocalPositions(NamedTuple):
    positions: List[Position]

    @staticmethod
    def from_json(positions: List[Dict[str, Any]], method: Method) -> "LocalPositions":
        return LocalPositions(
            [Position.from_json(position, method) for position in positions]
        )

    @staticmethod
    def from_taint_json(
        taint: Dict[str, Any], caller_method: Method
    ) -> "LocalPositions":
        """The `taint` json should be of the following form:
        {
            "call": {...},  --> Optional field in `taint`
            "kinds": [
                { "kind": "Source", "local_positions": [ { <position> } ] },
                ...
            ]
        }
        """
        return LocalPositions.from_json(
            taint.get("local_positions", []),
            caller_method,
        )

    def to_sapp(self) -> List[sapp.SourceLocation]:
        return [position.to_sapp() for position in sorted(self.positions)]


class Features(NamedTuple):
    features: Set[str]

    @staticmethod
    def from_json(features: Dict[str, Any]) -> "Features":
        may_features = set(features.get("may_features", []))
        always_features = {
            f"always-{feature}" for feature in features.get("always_features", [])
        }
        return Features(may_features | always_features)

    @staticmethod
    def from_taint_json(taint: Dict[str, Any]) -> "Features":
        """Similar to `LocalPositions.from_taint_json`."""
        # User-declared features are stored in "local_user_features" and should
        # be reported as local features in order to show up in the trace frame
        # on the UI.
        user_features = Features.from_json(taint.get("local_user_features", {}))
        local_features = Features.from_json(taint.get("local_features", {}))
        return Features(user_features.features | local_features.features)

    def to_sapp(self) -> List[str]:
        return sorted(self.features)

    def to_sapp_as_parsetracefeature(self) -> List[sapp.ParseTraceFeature]:
        return [
            sapp.ParseTraceFeature(feature, []) for feature in sorted(self.features)
        ]


class ExtraTrace(NamedTuple):
    kind: str
    callee: CallInfo

    @staticmethod
    def from_json(
        extra_trace: Dict[str, Any], caller_position: Position
    ) -> "ExtraTrace":
        return ExtraTrace(
            kind=extra_trace["kind"],
            callee=CallInfo.from_json(
                extra_trace["call_info"], "sink", caller_position
            ),
        )

    def to_sapp(self) -> sapp.ParseTraceAnnotation:
        subtraces = (
            [
                sapp.ParseTraceAnnotationSubtrace(
                    callee=self.callee.method.name,
                    port=self.callee.port.value,
                    position=self.callee.position.to_sapp(),
                )
            ]
            if self.callee.method
            else []
        )

        return sapp.ParseTraceAnnotation(
            location=self.callee.position.to_sapp(),
            kind="tito_transform",
            msg=f"Propagation through {self.kind}",
            leaf_kind=self.kind,
            leaf_depth=0,
            type_interval=None,
            link=None,
            trace_key=None,
            titos=[],
            subtraces=subtraces,
        )


class Kind(NamedTuple):
    name: str
    distance: int
    origins: List[Origin]
    extra_traces: List[ExtraTrace]
    callee_interval: Optional[Tuple[int, int]]
    preserves_type_context: bool

    @staticmethod
    def from_json(
        kind: Dict[str, Any], leaf_kind: str, caller_position: Position
    ) -> "Kind":
        origins = []
        for origin in kind.get("origins", []):
            origins.append(Origin.from_json(origin, leaf_kind))
        extra_traces = []
        for extra_trace in kind.get("extra_traces", []):
            extra_traces.append(ExtraTrace.from_json(extra_trace, caller_position))
        interval = kind.get("callee_interval")
        return Kind(
            name=kind["kind"],
            distance=kind.get("distance", 0),
            origins=origins,
            extra_traces=extra_traces,
            callee_interval=(interval[0], interval[1]) if interval else None,
            preserves_type_context=kind.get("preserves_type_context", False),
        )

    @staticmethod
    def partition_by_interval(
        kinds: List["Kind"],
    ) -> Dict[Optional["ConditionTypeInterval"], List["Kind"]]:
        kinds_by_interval = defaultdict(list)
        for kind in kinds:
            if kind.callee_interval is None:
                kinds_by_interval[None].append(kind)
            else:
                interval = ConditionTypeInterval.from_kind(kind)
                kinds_by_interval[interval].append(kind)
        return kinds_by_interval


class ConditionLeaf(NamedTuple):
    kind: str
    distance: int

    @staticmethod
    def from_kind(kind: Kind) -> "ConditionLeaf":
        return ConditionLeaf(kind=kind.name, distance=kind.distance)

    def to_sapp(self) -> Tuple[str, int]:
        return (self.kind, self.distance)


class ConditionCall(NamedTuple):
    """Represents a caller/callee in a [pre|post]Condition"""

    method: Method
    port: Port
    position: Position

    @staticmethod
    def from_call_info(call_info: CallInfo) -> "ConditionCall":
        if call_info.method is None:
            raise sapp.ParseError(
                f"Cannot construct a ConditionCall without a valid method {call_info}"
            )
        return ConditionCall(call_info.method, call_info.port, call_info.position)

    @staticmethod
    def from_origin(origin: Origin, call_info: CallInfo) -> "ConditionCall":
        return ConditionCall(
            method=origin.callee_name,
            port=origin.callee_port,
            position=call_info.position,
        )


class ConditionTypeInterval(NamedTuple):
    start: int
    finish: int
    preserves_type_context: bool

    @staticmethod
    def from_kind(kind: Kind) -> "ConditionTypeInterval":
        if kind.callee_interval is None:
            raise sapp.ParseError(f"Callee interval expected in {kind}")
        return ConditionTypeInterval(
            start=kind.callee_interval[0],
            finish=kind.callee_interval[1],
            preserves_type_context=kind.preserves_type_context,
        )

    def to_sapp(self) -> sapp.ParseTypeInterval:
        return sapp.ParseTypeInterval(
            start=self.start,
            finish=self.finish,
            preserves_type_context=self.preserves_type_context,
        )


class Condition(NamedTuple):
    caller: ConditionCall
    callee: ConditionCall
    leaves: List[ConditionLeaf]
    local_positions: LocalPositions
    features: Features
    extra_traces: Set[ExtraTrace]
    type_interval: Optional[ConditionTypeInterval]

    def convert_to_sapp(
        self, kind: Literal[sapp.ParseType.PRECONDITION, sapp.ParseType.POSTCONDITION]
    ) -> sapp.ParseConditionTuple:
        return sapp.ParseConditionTuple(
            type=kind,
            caller=self.caller.method.name,
            caller_port=self.caller.port.value,
            filename=self.caller.position.path,
            callee=self.callee.method.name,
            callee_port=self.callee.port.value,
            callee_location=self.callee.position.to_sapp(),
            type_interval=(
                self.type_interval.to_sapp() if self.type_interval else None
            ),
            features=self.features.to_sapp_as_parsetracefeature(),
            titos=self.local_positions.to_sapp(),
            leaves=[leaf.to_sapp() for leaf in self.leaves],
            annotations=[extra_trace.to_sapp() for extra_trace in self.extra_traces],
        )


ConditionType = TypeVar("ConditionType", bound="Condition", covariant=True)


class Precondition(Condition):
    def to_sapp(self) -> sapp.ParseConditionTuple:
        return super().convert_to_sapp(sapp.ParseType.PRECONDITION)


class Postcondition(Condition):
    def to_sapp(self) -> sapp.ParseConditionTuple:
        return super().convert_to_sapp(sapp.ParseType.POSTCONDITION)


class Propagation(Condition):
    def to_sapp(self) -> sapp.ParseConditionTuple:
        return super().convert_to_sapp(sapp.ParseType.PRECONDITION)


class IssueCondition(NamedTuple):
    callee: ConditionCall
    leaves: List[ConditionLeaf]
    local_positions: LocalPositions
    features: Features
    extra_traces: Set[ExtraTrace]
    type_interval: Optional[ConditionTypeInterval]

    def to_sapp(self) -> sapp.ParseIssueConditionTuple:
        return sapp.ParseIssueConditionTuple(
            callee=self.callee.method.name,
            port=self.callee.port.value,
            location=self.callee.position.to_sapp(),
            leaves=[leaf.to_sapp() for leaf in self.leaves],
            titos=self.local_positions.to_sapp(),
            features=self.features.to_sapp_as_parsetracefeature(),
            type_interval=(
                self.type_interval.to_sapp() if self.type_interval else None
            ),
            annotations=[extra_trace.to_sapp() for extra_trace in self.extra_traces],
        )


class Leaf(NamedTuple):
    method: Method
    kind: str
    distance: int

    def to_sapp(self) -> sapp.ParseIssueLeaf:
        return (self.method.name, self.kind, self.distance)


class Issue(NamedTuple):
    code: int
    message: str
    callable: Method
    callee_signature: str
    sink_index: int
    callable_position: Position
    issue_position: Position
    preconditions: List[IssueCondition]
    postconditions: List[IssueCondition]
    initial_sources: Set[Leaf]
    final_sinks: Set[Leaf]
    features: Features

    def to_sapp(self, parser: "Parser") -> sapp.ParseIssueTuple:
        return sapp.ParseIssueTuple(
            code=self.code,
            message=self.message,
            callable=self.callable.name,
            handle=Parser.get_master_handle(
                self.callable.name,
                self.callee_signature,
                self.sink_index,
                self.code,
                self.callable_position.line,
                self.issue_position.line,
            ),
            filename=self.callable_position.path,
            callable_line=self.callable_position.line,
            line=self.issue_position.line,
            start=self.issue_position.start,
            end=self.issue_position.end,
            preconditions=[
                precondition.to_sapp() for precondition in self.preconditions
            ],
            postconditions=[
                postcondition.to_sapp() for postcondition in self.postconditions
            ],
            initial_sources={leaf.to_sapp() for leaf in self.initial_sources},
            final_sinks={leaf.to_sapp() for leaf in self.final_sinks},
            features=self.features.to_sapp(),
            fix_info=None,
        )


class Parser(BaseParser):
    def __init__(self, repo_dirs: Optional[Set[str]] = None) -> None:
        super().__init__(repo_dirs)
        # pyre-fixme[4]: Attribute annotation cannot contain `Any`.
        self._rules: Dict[int, Any] = {}
        self._initialized: bool = False

    @staticmethod
    def is_supported(metadata: Metadata) -> bool:
        return (
            metadata.tool == "mariana_trench"
            and metadata.analysis_tool_version == "0.2"
        )

    # This is meant to remove the compiler-generated anonymous class numbers within
    # the sink callee signature to be included in an issue master handle. The number
    # is replaced with the relative line of the issue within the root callable. This
    # is done because the anonymous class number is more susceptible to changing with
    # unrelated changes in a diff rather than the relative line number of the issue
    # in the root callable.
    @staticmethod
    def strip_anonymous_class_numbers(
        callee_signature: str, callable_line: int, issue_line: int
    ) -> str:
        first_semicolon = callee_signature.find(";")
        if first_semicolon < 0:
            return callee_signature
        class_name = callee_signature[:first_semicolon]
        class_name_length = len(class_name)
        stripped_classname = ""
        index = 0
        while index < class_name_length:
            character = class_name[index]
            stripped_classname += character
            index += 1
            if (
                character != "$"
                or index == class_name_length
                or not class_name[index].isdigit()
            ):
                continue
            while index < class_name_length and class_name[index].isdigit():
                index += 1
        if stripped_classname == class_name:
            return callee_signature

        relative_line = -1
        if issue_line > -1 and issue_line >= callable_line:
            relative_line = issue_line - callable_line
        return (
            f"{stripped_classname}#{relative_line}{callee_signature[first_semicolon:]}"
        )

    @staticmethod
    def get_master_handle(
        callable: str,
        callee_signature: str,
        sink_index: int,
        code: int,
        callable_line: int,
        issue_line: int,
    ) -> str:
        return BaseParser.compute_handle_from_key(
            f"{callable}:{Parser.strip_anonymous_class_numbers(callee_signature, callable_line, issue_line)}:{sink_index}:{code}"
        )

    def initialize(self, metadata: Optional[Metadata]) -> None:
        if self._initialized:
            return

        if metadata:
            # We get the rules from the metadata when parsing json lines.
            rules = metadata.rules
            if rules:
                self._rules = rules

        self._initialized = True

    # pyre-fixme[14]: `parse` overrides method defined in `BaseParser` inconsistently.
    def parse(
        self, output: AnalysisOutput
    ) -> Iterable[Union[sapp.ParseConditionTuple, sapp.ParseIssueTuple]]:
        self.initialize(output.metadata)

        for handle in output.file_handles():
            yield from self.parse_handle(handle)

    def parse_handle(
        self, handle: IO[str]
    ) -> Iterable[Union[sapp.ParseConditionTuple, sapp.ParseIssueTuple]]:
        for line in handle.readlines():
            if line.startswith("//"):
                continue
            model = json.loads(line)

            # Note: Non method models include field models. We don't process those
            # since traces show methods only.
            if "method" in model.keys():
                yield from self._parse_issues(model)
                for precondition in self._parse_preconditions(model):
                    yield precondition.to_sapp()
                for effect_precondition in self._parse_effect_preconditions(model):
                    yield effect_precondition.to_sapp()
                for postcondition in self._parse_postconditions(model):
                    yield postcondition.to_sapp()
                for propagation in self._parse_propagations(model):
                    yield propagation.to_sapp()

    def _parse_issues(self, model: Dict[str, Any]) -> Iterable[sapp.ParseIssueTuple]:
        for issue in model.get("issues", []):
            code = issue["rule"]
            rule = self._rules[code]
            callable = Method.from_json(model["method"])
            callable_position = Position.from_json(model["position"], callable)
            issue_position = Position.from_json(issue["position"], callable)
            features = Features.from_json(issue)

            (preconditions, final_sinks) = self._parse_issue_conditions(
                issue, callable, callable_position, "sink"
            )
            (postconditions, initial_sources) = self._parse_issue_conditions(
                issue, callable, callable_position, "source"
            )

            yield Issue(
                code=code,
                message=f"{rule['name']}: {rule['description']}",
                callable=callable,
                callee_signature=issue["callee"],
                sink_index=issue["sink_index"],
                callable_position=callable_position,
                issue_position=issue_position,
                preconditions=preconditions,
                postconditions=postconditions,
                initial_sources=initial_sources,
                final_sinks=final_sinks,
                features=features,
            ).to_sapp(self)

    def _parse_issue_conditions(
        self,
        issue: Dict[str, Any],
        callable: Method,
        callable_position: Position,
        leaf_kind: str,
    ) -> Tuple[List[IssueCondition], Set[Leaf]]:
        condition_taints = issue[f"{leaf_kind}s"]

        conditions = []
        issue_leaves = set()

        for condition_taint in condition_taints:
            local_positions = LocalPositions.from_taint_json(condition_taint, callable)
            features = Features.from_taint_json(condition_taint)
            call_info = CallInfo.from_json(
                condition_taint["call_info"], leaf_kind, callable_position
            )

            kinds_by_interval = Kind.partition_by_interval(
                [
                    Kind.from_json(kind_json, leaf_kind, callable_position)
                    for kind_json in condition_taint["kinds"]
                ]
            )

            issue_leaves.update(
                {
                    Leaf(
                        method=origin.callee_name,
                        kind=kind.name,
                        distance=kind.distance,
                    )
                    for _, kinds in kinds_by_interval.items()
                    for kind in kinds
                    for origin in kind.origins
                }
            )

            if call_info.is_declaration():
                raise sapp.ParseError(
                    f"Unexpected declaration frame at issue {leaf_kind}: {issue}"
                )

            if call_info.is_origin():
                for interval, kinds in kinds_by_interval.items():
                    for kind in kinds:
                        condition_leaves = [ConditionLeaf.from_kind(kind)]
                        for origin in kind.origins:
                            conditions.append(
                                IssueCondition(
                                    callee=ConditionCall.from_origin(origin, call_info),
                                    leaves=condition_leaves,
                                    local_positions=local_positions,
                                    features=features,
                                    extra_traces=set(kind.extra_traces),
                                    type_interval=interval,
                                )
                            )
            else:
                for interval, kinds in kinds_by_interval.items():
                    condition_leaves = []
                    extra_traces = set()
                    for kind in kinds:
                        condition_leaves.append(ConditionLeaf.from_kind(kind))
                        extra_traces.update(kind.extra_traces)
                    conditions.append(
                        IssueCondition(
                            callee=ConditionCall.from_call_info(call_info),
                            leaves=condition_leaves,
                            local_positions=local_positions,
                            features=features,
                            extra_traces=extra_traces,
                            type_interval=interval,
                        )
                    )

        return conditions, issue_leaves

    def _parse_preconditions(self, model: Dict[str, Any]) -> Iterable[Precondition]:
        return self._parse_condition(
            model,
            condition_model_key="sinks",
            port_key="port",
            leaf_model_key="taint",
            leaf_kind="sink",
            condition_class=Precondition,
        )

    def _parse_effect_preconditions(
        self, model: Dict[str, Any]
    ) -> Iterable[Precondition]:
        return self._parse_condition(
            model,
            condition_model_key="effect_sinks",
            port_key="port",
            leaf_model_key="taint",
            leaf_kind="sink",
            condition_class=Precondition,
        )

    def _parse_postconditions(self, model: Dict[str, Any]) -> Iterable[Postcondition]:
        return self._parse_condition(
            model,
            condition_model_key="generations",
            port_key="port",
            leaf_model_key="taint",
            leaf_kind="source",
            condition_class=Postcondition,
        )

    def _parse_propagations(self, model: Dict[str, Any]) -> Iterable[Propagation]:
        return self._parse_condition(
            model,
            condition_model_key="propagation",
            port_key="input",
            leaf_model_key="output",
            leaf_kind="sink",
            condition_class=Propagation,
        )

    def _parse_condition(
        self,
        model: Dict[str, Any],
        condition_model_key: str,
        port_key: str,
        leaf_model_key: str,
        leaf_kind: str,
        condition_class: Type[ConditionType],
    ) -> Iterable[ConditionType]:
        caller_method = Method.from_json(model["method"])
        caller_position = Position.from_json(model["position"], caller_method)

        for leaf_model in model.get(condition_model_key, []):
            caller = ConditionCall(
                method=caller_method,
                port=Port.from_json(leaf_model[port_key], leaf_kind),
                position=caller_position,
            )
            for leaf_taint in leaf_model[leaf_model_key]:
                call_info_json = leaf_taint["call_info"]
                call_info = CallInfo.from_json(
                    call_info_json, leaf_kind, caller_position
                )
                if (
                    call_info.is_declaration()
                    or call_info.is_propagation_without_trace()
                ):
                    # (User)-Declarations do not translate into trace frames.
                    # Propagations (without traces) can also be ignored.
                    continue

                local_positions = LocalPositions.from_taint_json(
                    leaf_taint, caller_method
                )
                local_features = Features.from_taint_json(leaf_taint)

                kinds_json = leaf_taint["kinds"]
                kinds_by_interval = Kind.partition_by_interval(
                    [
                        Kind.from_json(kind_json, leaf_kind, caller_position)
                        for kind_json in kinds_json
                    ]
                )

                if call_info.is_origin():
                    for interval, kinds in kinds_by_interval.items():
                        condition_by_callee = {}
                        for kind in kinds:
                            for origin in kind.origins:
                                callee = ConditionCall.from_origin(origin, call_info)
                                condition = condition_by_callee.get(
                                    callee,
                                    condition_class(
                                        caller=caller,
                                        callee=callee,
                                        leaves=[],
                                        local_positions=local_positions,
                                        features=local_features,
                                        extra_traces=set(),
                                        type_interval=interval,
                                    ),
                                )
                                condition.leaves.append(ConditionLeaf.from_kind(kind))
                                condition.extra_traces.update(kind.extra_traces)
                                condition_by_callee[callee] = condition
                        for condition in condition_by_callee.values():
                            yield condition
                else:
                    for interval, kinds in kinds_by_interval.items():
                        extra_traces = set()
                        for kind in kinds:
                            extra_traces.update(kind.extra_traces)
                        yield condition_class(
                            caller=caller,
                            callee=ConditionCall.from_call_info(call_info),
                            leaves=[ConditionLeaf.from_kind(kind) for kind in kinds],
                            local_positions=local_positions,
                            features=local_features,
                            extra_traces=extra_traces,
                            type_interval=interval,
                        )
