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


class Precondition(Condition):
    def to_sapp(self) -> sapp.ParseConditionTuple:
        return super().convert_to_sapp(sapp.ParseType.PRECONDITION)


class Postcondition(Condition):
    def to_sapp(self) -> sapp.ParseConditionTuple:
        return super().convert_to_sapp(sapp.ParseType.POSTCONDITION)


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
                # TODO(T91357916): Implement parse issues and postconditions
                # yield from self._parse_issues(model)
                for precondition in self._parse_precondition(model):
                    yield precondition.to_sapp()
                # for postcondition in self._parse_postconditions(model):
                #     yield postcondition.to_sapp()

    def _parse_precondition(self, model: Dict[str, Any]) -> Iterable[Precondition]:
        caller_method = Method.from_json(model["method"])
        caller_position = Position.from_json(model["position"], caller_method)

        for sink in model.get("sinks", []):
            caller = Call(
                method=caller_method,
                port=Port.from_json(sink["caller_port"], "sink"),
                position=caller_position,
            )
            for sink_taint in sink["taint"]:
                # TODO(T91357916): Handle CRTEX (see _normalize_frame in v1 parser)
                callee = Call.from_taint_callee_json(
                    sink_taint.get("call"), caller_position, leaf_kind="sink"
                )
                leaves = [ConditionLeaf.from_json(kind) for kind in sink_taint["kinds"]]

                # TODO(T91357916): LocalPositions and LocalFeatures are not unique
                # to a kind even though it is currently stored within one. Therefore,
                # these are read from the first kind in the list. The analysis should
                # update its inner (TaintV2) storage and JSON format.
                local_positions = LocalPositions.from_json(
                    sink_taint["kinds"][0].get("local_positions", [])
                    if len(sink_taint["kinds"]) > 0
                    else [],
                    caller_method,
                )
                local_features = Features.from_json(
                    sink_taint["kinds"][0].get("local_features", {})
                    if len(sink_taint["kinds"]) > 0
                    else {}
                )

                yield Precondition(
                    caller=caller,
                    callee=callee,
                    leaves=leaves,
                    local_positions=local_positions,
                    features=local_features,
                )