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
PROGRAMMATIC_LEAF_NAME_PLACEHOLDER = "%programmatic_leaf_name%"
SOURCE_VIA_TYPE_PLACEHOLDER = "%source_via_type_of%"


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

    @staticmethod
    def _normalize_crtex_condition(
        callee: Dict[str, Any],
        kind: Dict[str, Any],
        caller_method: Method,
        caller_port: Optional[str],
    ) -> List[Dict[str, Any]]:
        if "canonical_names" not in kind:
            return [{"call": callee, "kinds": [kind]}]

        conditions = []
        # Expected format: "canonical_names": [ { "instantiated": "<name>" }, ... ]
        # Canonical names are used for CRTEX only, and are expected to be the callee
        # name where traces are concerned. Each instantiated name maps to one frame.
        for canonical_name in kind["canonical_names"]:
            if (
                "instantiated" not in canonical_name
                and SOURCE_VIA_TYPE_PLACEHOLDER not in canonical_name["template"]
            ):
                # Uninstantiated canonical names are user-defined CRTEX leaves
                # They do not show up as a frame in the UI.
                continue

            # Shallow copy is ok, only "callee"/"resolves_to" field is different.
            callee_copy = callee.copy()

            if "instantiated" in canonical_name:
                resolves_to = canonical_name["instantiated"]
            else:
                resolves_to = canonical_name["template"].replace(
                    PROGRAMMATIC_LEAF_NAME_PLACEHOLDER, caller_method.name
                )
                # If the canonical name is uninstantiated, the canonical port will be
                # uninstantiated too, so we fill it in here.
                # Frames within the issue won't have a caller port,
                # and we know that only Return sinks will reach this logic
                # right now, so the default is return
                callee_copy["port"] = "Anchor." + (caller_port or "Return")

            callee_copy["resolves_to"] = resolves_to
            kind_copy = kind.copy()
            kind_copy.pop("canonical_names")
            conditions.append({"call": callee_copy, "kinds": [kind_copy]})

        return conditions

    @staticmethod
    def _normalize_crtex_conditions(
        taint: Dict[str, Any], caller_method: Method, caller_port: Optional[str]
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
                Parser._normalize_crtex_condition(
                    callee, kind, caller_method, caller_port
                )
            )
        return conditions

    def _normalize_field_callees(self, taint: Dict[str, Any]) -> List[Dict[str, Any]]:
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

    def _parse_precondition(self, model: Dict[str, Any]) -> Iterable[Precondition]:
        caller_method = Method.from_json(model["method"])
        caller_position = Position.from_json(model["position"], caller_method)

        for sink in model.get("sinks", []):
            caller = Call(
                method=caller_method,
                port=Port.from_json(sink["caller_port"], "sink"),
                position=caller_position,
            )
            for unnormalized_sink_taint in sink["taint"]:
                # The analysis should emit traces where the JSON already conforms to
                # the way traces are structured in SAPP, i.e.:
                # caller -> caller_port -> (callee, position, port) -> (kind, distance)
                # However, it does not do that today for CRTEX and field callees. This
                # chain of "normalize" operations transforms the JSON into that form
                # above so all of them can be parsed in the same way.
                normalized_field_callees = self._normalize_field_callees(
                    unnormalized_sink_taint
                )

                normalized_taints = []
                for sink_taint in normalized_field_callees:
                    normalized_taints.extend(
                        Parser._normalize_crtex_conditions(
                            sink_taint, caller_method, sink["caller_port"]
                        )
                    )

                for sink_taint in normalized_taints:
                    callee = Call.from_taint_callee_json(
                        sink_taint.get("call"), caller_position, leaf_kind="sink"
                    )
                    leaves = [
                        ConditionLeaf.from_json(kind) for kind in sink_taint["kinds"]
                    ]

                    # TODO(T91357916): LocalPositions and LocalFeatures are not unique
                    # to a kind even though it is currently stored within one.
                    # Therefore, these are read from the first kind in the list. The
                    # analysis should update its (TaintV2) storage and JSON format.
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
