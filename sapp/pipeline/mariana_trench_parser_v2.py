# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import json
import logging
import re
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
from .base_parser import BaseParser

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


LOG: logging.Logger = logging.getLogger()
UNKNOWN_PATH: str = "unknown"
UNKNOWN_LINE: int = -1


class Method(NamedTuple):
    name: str

    def is_leaf(self) -> bool:
        return self.name == "leaf"

    @staticmethod
    def from_json(method: Union[None, str, Dict[str, Any]]) -> "Method":
        if method is None:
            return Method("leaf")
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
    def from_json(position: Dict[str, Any], method: Method) -> "Position":
        path = position.get("path", UNKNOWN_PATH)
        line = position.get("line", UNKNOWN_LINE)
        start = position.get("start", 0) + 1
        end = max(position.get("end", 0) + 1, start)
        if path == UNKNOWN_PATH and not method.is_leaf():
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


class Call(NamedTuple):
    method: Method
    port: Port
    position: Position

    @staticmethod
    def from_json(
        method: Union[None, str, Dict[str, Any]],
        port: str,
        position: Optional[Dict[str, Any]],
        default_position: Position,
        leaf_kind: str,
    ) -> "Call":
        call_method = Method.from_json(method)
        call_port = Port.from_json(port, leaf_kind)
        if position is None:
            if not call_port.is_leaf():
                raise sapp.ParseError(
                    f"Missing call position for call to `{call_method.name}`."
                )
            else:
                call_position = default_position
        else:
            call_position = Position.from_json(position, call_method)
        return Call(call_method, call_port, call_position)

    @staticmethod
    def from_taint_callee_json(
        callee_json: Union[None, Dict[str, Any]],
        caller_position: Position,
        leaf_kind: str,
    ) -> "Call":
        """Creates Call object from JSON representing a pre/postcondition's taint.
        This represents the condition's callee."""
        if callee_json:
            return Call.from_json(
                method=callee_json.get("resolves_to"),
                port=callee_json.get("port", "Leaf"),
                position=callee_json.get("position"),
                default_position=caller_position,
                leaf_kind=leaf_kind,
            )
        else:
            return Call.from_json(
                method=None,
                port="Leaf",
                position=None,
                default_position=caller_position,
                leaf_kind=leaf_kind,
            )


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
        """The `taint` json should be of the form:
        {
            "call": {...},  --> Optional field in `taint`
            "kinds": [
                { "kind": "Source", "local_positions": [ { <position> } ] },
                ...
            ]
        }
        """
        # TODO(T91357916): LocalPositions (and LocalFeatures) are not unique
        # to a kind even though it is currently stored within one. Therefore,
        # these are read from the first kind in the list. The analysis should
        # update its (TaintV2) storage and JSON format.
        return LocalPositions.from_json(
            taint["kinds"][0].get("local_positions", [])
            if len(taint["kinds"]) > 0
            else [],
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
        # TODO(T91357916): See comments in LocalPositions
        return Features.from_json(
            taint["kinds"][0].get("local_features", {})
            if len(taint["kinds"]) > 0
            else {}
        )

    def to_sapp(self) -> List[str]:
        return sorted(self.features)

    def to_sapp_as_parsetracefeature(self) -> List[sapp.ParseTraceFeature]:
        return [
            sapp.ParseTraceFeature(feature, []) for feature in sorted(self.features)
        ]


class ConditionLeaf(NamedTuple):
    kind: str
    distance: int

    @staticmethod
    def from_json(kind: Dict[str, Any]) -> "ConditionLeaf":
        return ConditionLeaf(kind=kind["kind"], distance=kind.get("distance", 0))

    def to_sapp(self) -> Tuple[str, int]:
        return (self.kind, self.distance)


class Condition(NamedTuple):
    caller: Call
    callee: Call
    leaves: List[ConditionLeaf]
    local_positions: LocalPositions
    features: Features

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
            type_interval=None,
            features=self.features.to_sapp_as_parsetracefeature(),
            titos=self.local_positions.to_sapp(),
            leaves=[leaf.to_sapp() for leaf in self.leaves],
            annotations=[],
        )


ConditionType = TypeVar("ConditionType", bound="Condition", covariant=True)


class Precondition(Condition):
    def to_sapp(self) -> sapp.ParseConditionTuple:
        return super().convert_to_sapp(sapp.ParseType.PRECONDITION)


class Postcondition(Condition):
    def to_sapp(self) -> sapp.ParseConditionTuple:
        return super().convert_to_sapp(sapp.ParseType.POSTCONDITION)


class IssueCondition(NamedTuple):
    callee: Call
    leaves: List[ConditionLeaf]
    local_positions: LocalPositions
    features: Features

    def to_sapp(self) -> sapp.ParseIssueConditionTuple:
        return sapp.ParseIssueConditionTuple(
            callee=self.callee.method.name,
            port=self.callee.port.value,
            location=self.callee.position.to_sapp(),
            leaves=[leaf.to_sapp() for leaf in self.leaves],
            titos=self.local_positions.to_sapp(),
            features=self.features.to_sapp_as_parsetracefeature(),
            type_interval=None,
            annotations=[],
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
    def __init__(self, repo_dirs: Optional[List[str]] = None) -> None:
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
                for postcondition in self._parse_postconditions(model):
                    yield postcondition.to_sapp()

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
        leaves = set()

        for condition_taint in condition_taints:
            normalized_conditions = Parser._normalize_conditions(
                taint=condition_taint, caller_method=callable
            )
            for normalized_condition in normalized_conditions:
                conditions.append(
                    IssueCondition(
                        callee=Call.from_taint_callee_json(
                            normalized_condition.get("call"),
                            callable_position,
                            leaf_kind,
                        ),
                        leaves=[
                            ConditionLeaf.from_json(kind)
                            for kind in normalized_condition["kinds"]
                        ],
                        local_positions=LocalPositions.from_taint_json(
                            normalized_condition, callable
                        ),
                        features=Features.from_taint_json(normalized_condition),
                    )
                )

                for kind in normalized_condition["kinds"]:
                    for origin in kind.get("origins", []):
                        leaves.add(
                            Leaf(
                                method=Method.from_json(origin),
                                kind=kind["kind"],
                                distance=kind.get("distance", 0),
                            )
                        )
                    for field_origin in kind.get("field_origins", []):
                        leaves.add(
                            Leaf(
                                method=Method(field_origin),
                                kind=kind["kind"],
                                distance=kind.get("distance", 0),
                            ),
                        )

        return conditions, leaves

    @staticmethod
    def _normalize_conditions(
        taint: Dict[str, Any], caller_method: Method
    ) -> List[Dict[str, Any]]:
        # The analysis should emit traces where the JSON already conforms to
        # the way traces are structured in SAPP, i.e.:
        # caller -> caller_port -> (callee, position, port) -> (kind, distance)
        # However, it does not do that today for CRTEX and field callees. This
        # chain of "normalize" operations transforms the JSON into that form
        # above so all of them can be parsed in the same way.
        normalized_field_callees = Parser._normalize_field_callees(taint)

        normalized_taints = []
        for leaf_taint in normalized_field_callees:
            normalized_taints.extend(
                Parser._normalize_crtex_conditions(leaf_taint, caller_method)
            )

        return normalized_taints

    @staticmethod
    def _normalize_crtex_condition(
        callee: Dict[str, Any],
        kind: Dict[str, Any],
        caller_method: Method,
    ) -> List[Dict[str, Any]]:
        if "canonical_names" not in kind:
            return [{"call": callee, "kinds": [kind]}]

        conditions = []
        # Expected format: "canonical_names": [ { "instantiated": "<name>" }, ... ]
        # Canonical names are used for CRTEX only, and are expected to be the callee
        # name where traces are concerned. Each instantiated name maps to one frame.
        for canonical_name in kind["canonical_names"]:
            if "instantiated" not in canonical_name:
                # Uninstantiated canonical names are user-defined CRTEX leaves
                # They do not show up as a frame in the UI.
                continue

            # Shallow copy is ok, only "resolves_to" field is different.
            callee_copy = callee.copy()
            callee_copy["resolves_to"] = canonical_name["instantiated"]
            # Same for kind. We are just removing a key/field.
            kind_copy = kind.copy()
            kind_copy.pop("canonical_names")
            conditions.append({"call": callee_copy, "kinds": [kind_copy]})

        return conditions

    @staticmethod
    def _normalize_crtex_conditions(
        taint: Dict[str, Any], caller_method: Method
    ) -> List[Dict[str, Any]]:
        """CRTEX frames contain the callee information (instantiated canonical name)
        within the kinds field. Each of these maps to a unique callee and should be
        represented as such. This performs the following transformation on the JSON.

        From:
        {
          "call": {
            "port": "Anchor.Argument(0)"
          },
          "kinds": [
            {
              "kind": "CRTEXSink1",
              "canonical_names": [
                { "instantiated" : "Instantiated1" },
                { "instantiated" : "Instantiated2" }
              ],
              ...
            },
            {
              "kind": "CRTEXSink2",
              "canonical_names": [
                { "instantiated" : "Instantiated3" },
              ],
              ...
            }
          ]
        }

        To:
        [
          {
            "call": {
              "resolves_to": "Instantiated1",
              "port": "Anchor.Argument(0)",
            },
            "kinds": [
              { "kind": "CRTEXSink1", ... }
            ]
          },
          {
            "call": {
              "resolves_to": "Instantiated2",
              "port": "Anchor.Argument(0)",
            },
            "kinds": [
              { "kind": "CRTEXSink1", ... }
            ]
          },
          {
            "call": {
              "resolves_to": "Instantiated3",
              "port": "Anchor.Argument(0)",
            },
            "kinds": [
              { "kind": "CRTEXSink2", ... }
            ]
          }
        ]

        The idea is that each canonical name should translate into a unique callee.
        """
        # TODO(T91357916): Similar to local positions and features, canonical names do
        # not need to be stored in "kinds". The analysis should update its internal
        # representation and output JSON. Doing the transformation here is messy.
        callee = taint.get("call")
        if callee is None:
            # CRTEX frames always have a "call" indicating the callee.
            return [taint]

        port = callee.get("port", "")
        if not (port.startswith("Anchor") or port.startswith("Producer")):
            # CRTEX frames have port anchor/producer.
            return [taint]

        conditions = []
        for kind in taint["kinds"]:
            conditions.extend(
                Parser._normalize_crtex_condition(callee, kind, caller_method)
            )
        return conditions

    @staticmethod
    def _normalize_field_callees(taint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Similar to `_normalize_crtex_conditions`, but does it for "field_callee"
        instead of "canonical_names"."""
        # TODO(T91357916): The analysis should be able to emit this correctly without
        # the parser having to post-process it.
        if taint.get("call") is not None:
            # Field callees only appear at the leaf. If a "call" exists, this is not
            # a leaf.
            return [taint]

        non_field_callee_taint_kinds = []
        normalized_taints = []

        for kind in taint["kinds"]:
            field_callee = kind.get("field_callee")
            if field_callee:
                normalized_taints.append(
                    {"call": {"resolves_to": field_callee}, "kinds": [kind]}
                )
            else:
                non_field_callee_taint_kinds.append(kind)

        if len(non_field_callee_taint_kinds) > 0:
            normalized_taints.append({"kinds": non_field_callee_taint_kinds})

        return normalized_taints

    def _parse_preconditions(self, model: Dict[str, Any]) -> Iterable[Precondition]:
        return self._parse_condition(
            model,
            condition_model_key="sinks",
            leaf_kind="sink",
            condition_class=Precondition,
        )

    def _parse_postconditions(self, model: Dict[str, Any]) -> Iterable[Postcondition]:
        return self._parse_condition(
            model,
            condition_model_key="generations",
            leaf_kind="source",
            condition_class=Postcondition,
        )

    def _parse_condition(
        self,
        model: Dict[str, Any],
        condition_model_key: str,
        leaf_kind: str,
        condition_class: Type[ConditionType],
    ) -> Iterable[ConditionType]:
        caller_method = Method.from_json(model["method"])
        caller_position = Position.from_json(model["position"], caller_method)

        for leaf_model in model.get(condition_model_key, []):
            caller = Call(
                method=caller_method,
                port=Port.from_json(leaf_model["port"], leaf_kind),
                position=caller_position,
            )
            for unnormalized_leaf_taint in leaf_model["taint"]:
                normalized_taints = Parser._normalize_conditions(
                    unnormalized_leaf_taint, caller_method
                )

                for leaf_taint in normalized_taints:
                    callee = Call.from_taint_callee_json(
                        leaf_taint.get("call"), caller_position, leaf_kind
                    )
                    leaves = [
                        ConditionLeaf.from_json(kind) for kind in leaf_taint["kinds"]
                    ]
                    yield condition_class(
                        caller=caller,
                        callee=callee,
                        leaves=leaves,
                        local_positions=LocalPositions.from_taint_json(
                            leaf_taint, caller_method
                        ),
                        features=Features.from_taint_json(leaf_taint),
                    )
