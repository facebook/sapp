# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import json
import logging
import sys

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
from . import mariana_trench_parser_objects as mariana_trench
from .base_parser import BaseParser

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


log: logging.Logger = logging.getLogger()


class ConditionLeaf(NamedTuple):
    kind: str
    distance: int

    @staticmethod
    def from_kind(kind: mariana_trench.Kind) -> "ConditionLeaf":
        return ConditionLeaf(kind=kind.name, distance=kind.distance)

    def to_sapp(self) -> Tuple[str, int]:
        return (self.kind, self.distance)


class ConditionCall(NamedTuple):
    """Represents a caller/callee in a [pre|post]Condition"""

    method: mariana_trench.Method
    port: mariana_trench.Port
    position: mariana_trench.Position

    @staticmethod
    def from_call_info(call_info: mariana_trench.CallInfo) -> "ConditionCall":
        if call_info.method is None:
            raise sapp.ParseError(
                f"Cannot construct a ConditionCall without a valid method {call_info}"
            )
        return ConditionCall(call_info.method, call_info.port, call_info.position)

    @staticmethod
    def from_origin(
        origin: mariana_trench.Origin, call_info: mariana_trench.CallInfo
    ) -> "ConditionCall":
        return ConditionCall(
            method=origin.callee_name,
            port=origin.callee_port,
            position=call_info.position,
        )


class Condition(NamedTuple):
    caller: ConditionCall
    callee: ConditionCall
    leaves: List[ConditionLeaf]
    local_positions: mariana_trench.LocalPositions
    features: mariana_trench.Features
    extra_traces: Set[mariana_trench.ExtraTrace]
    type_interval: Optional[mariana_trench.TypeInterval]

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
    local_positions: mariana_trench.LocalPositions
    features: mariana_trench.Features
    extra_traces: Set[mariana_trench.ExtraTrace]
    type_interval: Optional[mariana_trench.TypeInterval]

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
    method: mariana_trench.Method
    kind: str
    distance: int

    def to_sapp(self) -> sapp.ParseIssueLeaf:
        return (self.method.name, self.kind, self.distance)


class Issue(NamedTuple):
    code: int
    message: str
    callable: mariana_trench.Method
    callee: mariana_trench.IssueCallee
    sink_index: int
    callable_position: mariana_trench.Position
    issue_position: mariana_trench.Position
    preconditions: List[IssueCondition]
    postconditions: List[IssueCondition]
    initial_sources: Set[Leaf]
    final_sinks: Set[Leaf]
    features: mariana_trench.Features

    def to_sapp(self, parser: "Parser") -> sapp.ParseIssueTuple:
        return sapp.ParseIssueTuple(
            code=self.code,
            message=self.message,
            callable=self.callable.name,
            handle=Parser.get_master_handle(
                self.callable.name,
                self.callee,
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

    @staticmethod
    def get_master_handle(
        callable: str,
        issue_callee: mariana_trench.IssueCallee,
        sink_index: int,
        code: int,
        callable_line: int,
        issue_line: int,
    ) -> str:
        return BaseParser.compute_handle_from_key(
            f"{callable}"
            f":{issue_callee.to_sapp_handle(callable_line, issue_line)}"
            f":{sink_index}"
            f":{code}"
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
            callable = mariana_trench.Method.from_json(model["method"])
            callable_position = mariana_trench.Position.from_json(
                model["position"], callable
            )
            issue_position = mariana_trench.Position.from_json(
                issue["position"], callable
            )
            features = mariana_trench.Features.from_json(issue)

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
                callee=mariana_trench.IssueCallee.from_json(issue),
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
        callable: mariana_trench.Method,
        callable_position: mariana_trench.Position,
        leaf_kind: str,
    ) -> Tuple[List[IssueCondition], Set[Leaf]]:
        condition_taints = issue[f"{leaf_kind}s"]

        conditions = []
        issue_leaves = set()

        for condition_taint in condition_taints:
            local_positions = mariana_trench.LocalPositions.from_taint_json(
                condition_taint, callable
            )
            features = mariana_trench.Features.from_taint_json(condition_taint)
            call_info = mariana_trench.CallInfo.from_json(
                condition_taint["call_info"], leaf_kind, callable_position
            )

            kinds_by_interval = mariana_trench.Kind.partition_by_interval(
                [
                    mariana_trench.Kind.from_json(
                        kind_json, leaf_kind, callable_position
                    )
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
        caller_method = mariana_trench.Method.from_json(model["method"])
        caller_position = mariana_trench.Position.from_json(
            model["position"], caller_method
        )

        for leaf_model in model.get(condition_model_key, []):
            caller = ConditionCall(
                method=caller_method,
                port=mariana_trench.Port.from_json(leaf_model[port_key]),
                position=caller_position,
            )
            for leaf_taint in leaf_model[leaf_model_key]:
                call_info_json = leaf_taint["call_info"]
                call_info = mariana_trench.CallInfo.from_json(
                    call_info_json, leaf_kind, caller_position
                )
                if (
                    call_info.is_declaration()
                    or call_info.is_propagation_without_trace()
                ):
                    # (User)-Declarations do not translate into trace frames.
                    # Propagations (without traces) can also be ignored.
                    continue

                local_positions = mariana_trench.LocalPositions.from_taint_json(
                    leaf_taint, caller_method
                )
                local_features = mariana_trench.Features.from_taint_json(leaf_taint)

                kinds_json = leaf_taint["kinds"]
                kinds_by_interval = mariana_trench.Kind.partition_by_interval(
                    [
                        mariana_trench.Kind.from_json(
                            kind_json, leaf_kind, caller_position
                        )
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
