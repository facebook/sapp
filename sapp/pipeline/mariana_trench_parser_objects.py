# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict


import re
from collections import defaultdict
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple, Union

from .. import pipeline as sapp

UNKNOWN_PATH: str = "unknown"
UNKNOWN_LINE: int = -1


def _parse_partial_kind_name(kind: Dict[str, Any]) -> str:
    partial_label = kind.get("partial_label")
    name = kind.get("name")
    if name is None:
        raise AssertionError(f"PartialKind must have a name. Kind: {kind}")
    return f"Partial:{name}:{partial_label}"


def _parse_transform_kind_name(kind: Dict[str, Any]) -> str:
    name = ""
    if local_transform := kind.get("local"):
        name += f"{local_transform}@"
    if global_transform := kind.get("global"):
        name += f"{global_transform}:"

    # At least one of local or global transform should be present in a
    # transform kind
    if len(name) == 0:
        raise AssertionError(
            f"TransformKind must have a local or global transform. Kind: {kind}"
        )

    name += kind["base"]
    return name


def _parse_kind_name(kind: Union[str, Dict[str, Any]]) -> str:
    if type(kind) is str:
        return kind

    if "base" in kind:
        return _parse_transform_kind_name(kind)
    elif "partial_label" in kind:
        # This applies to both PartialKind and TriggeredPartialKind. The latter
        # has an additional "triggered_rule" key but can be ignored here. For
        # traces to connect correctly, the string representation of both kinds
        # must be the same.
        return _parse_partial_kind_name(kind)

    raise AssertionError(
        "Unable to parse kind object. Must have either 'base' or "
        f"'partial_label' key. Kind: {kind}"
    )


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
            self.value.startswith("source")
            or self.value.startswith("sink")
            or self.value.startswith("anchor:")
            or self.value.startswith("producer:")
        )

    @staticmethod
    def to_crtex(port: str) -> str:
        """Converts 'argument(n)' to 'formal(n)'. Other CRTEX tools use 'formal'
        to denote argument positions."""
        return re.sub(r"argument\((-?\d+)\)", r"formal(\1)", port)

    @staticmethod
    def from_json(port: str) -> "Port":
        elements = port.split(".")

        if len(elements) == 0:
            raise sapp.ParseError(f"Invalid port: `{port}`.")

        elements[0] = elements[0].lower()
        if elements[0] == "return":
            elements[0] = "result"
        elif elements[0] == "anchor":
            # Anchor port is of the form Anchor.<MT port, e.g. Argument(0)>
            # SAPP/CRTEX expects: "anchor:formal(0)"
            canonical_port = Port.from_json(".".join(elements[1:]))
            return Port(f"{elements[0]}:{Port.to_crtex(canonical_port.value)}")
        elif elements[0] == "producer" and len(elements) >= 3:
            # Producer port is of the form Producer.<producer_id>.<MT port>.
            # SAPP/CRTEX expects: "producer:<producer_id>:<canonical_port>".
            root = elements[0]
            producer_id = elements[1]
            canonical_port = Port.from_json(".".join(elements[2:]))
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


class ExploitabilityOrigin(NamedTuple):
    exploitability_root: str
    callee: str
    position: Position

    @staticmethod
    def from_json(leaf_json: Dict[str, Any]) -> "ExploitabilityOrigin":
        """
        Represents the exploitability origin json object which is:
        {"exploitability_root": ..., "callee": ..., "position": ...}
        """
        return ExploitabilityOrigin(
            exploitability_root=leaf_json["exploitability_root"],
            callee=leaf_json["callee"],
            position=Position.from_json(leaf_json["position"], None),
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
        # ports should always be <leaf_kind>[:<actual port>].
        if "canonical_name" in leaf_json:
            # All CRTEX ports are considered leaf ports.
            callee_port = Port.from_json(leaf_json["port"])
        else:
            actual_callee_port = leaf_json.get("port")
            if actual_callee_port is not None:
                # Normalize the actual callee port as well.
                actual_callee_port = Port.from_json(actual_callee_port).value
                callee_port = Port.from_json(f"{leaf_kind}:{actual_callee_port}")
            else:
                callee_port = Port.from_json(leaf_kind)

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
        port = Port.from_json(taint_json.get("port", leaf_kind))

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

    def is_callsite(self) -> bool:
        return "CallSite" in self.call_kind

    def is_propagation_without_trace(self) -> bool:
        return "Propagation" == self.call_kind

    def is_propagation_with_trace(self) -> bool:
        return "PropagationWithTrace" in self.call_kind


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
    frame_type: str

    @staticmethod
    def from_json(
        extra_trace: Dict[str, Any], caller_position: Position
    ) -> "ExtraTrace":
        frame_type = extra_trace["frame_type"]
        return ExtraTrace(
            kind=_parse_kind_name(extra_trace["kind"]),
            callee=CallInfo.from_json(
                extra_trace["call_info"], frame_type, caller_position
            ),
            frame_type=frame_type,
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

        # Since we currently do not track callee.method when CallInfo is Origin,
        # we do not attach subtraces for them. Indicate if the subtrace is expected
        # only when the callinfo is a callsite.
        message = "Subtrace: " if self.callee.is_callsite() else ""
        if self.callee.is_propagation_with_trace():
            message += f"Propagation through {self.kind}"
        else:
            message += f"To {self.frame_type} kind: {self.kind}"

        return sapp.ParseTraceAnnotation(
            location=self.callee.position.to_sapp(),
            kind=self.frame_type,
            msg=message,
            leaf_kind=self.kind,
            leaf_depth=0,
            type_interval=None,
            link=None,
            trace_key=None,
            titos=[],
            subtraces=subtraces,
        )


class TypeInterval(NamedTuple):
    callee_interval: Tuple[int, int]
    preserves_type_context: bool

    @staticmethod
    def from_json(kind: Dict[str, Any], leaf_kind: str) -> Optional["TypeInterval"]:
        """Parses class interval information from the kind JSON"""
        interval = kind.get("callee_interval")
        if interval is None:
            return None

        # If "callee_interval" exists, "preserves_type_context" must exist too.
        return TypeInterval(
            callee_interval=(interval[0], interval[1]),
            preserves_type_context=kind["preserves_type_context"],
        )

    def to_sapp(self) -> sapp.ParseTypeInterval:
        return sapp.ParseTypeInterval(
            start=self.callee_interval[0],
            finish=self.callee_interval[1],
            preserves_type_context=self.preserves_type_context,
        )


class Kind(NamedTuple):
    name: str
    distance: int
    origins: List[Origin]
    extra_traces: List[ExtraTrace]
    type_interval: Optional[TypeInterval]

    @staticmethod
    def from_json(
        kind: Dict[str, Any], leaf_kind: str, caller_position: Position
    ) -> "Kind":
        origins = []
        for origin in kind.get("origins", []):
            # exploitability_root is only used internally and not required for SAPP.
            if "exploitability_root" in origin:
                continue
            origins.append(Origin.from_json(origin, leaf_kind))
        extra_traces = []
        for extra_trace in kind.get("extra_traces", []):
            extra_traces.append(ExtraTrace.from_json(extra_trace, caller_position))
        return Kind(
            name=_parse_kind_name(kind["kind"]),
            distance=kind.get("distance", 0),
            origins=origins,
            extra_traces=extra_traces,
            type_interval=TypeInterval.from_json(kind, leaf_kind),
        )

    @staticmethod
    def partition_by_interval(
        kinds: List["Kind"],
    ) -> Dict[Optional[TypeInterval], List["Kind"]]:
        kinds_by_interval = defaultdict(list)
        for kind in kinds:
            kinds_by_interval[kind.type_interval].append(kind)
        return kinds_by_interval


EXTERNAL_SYNTHETIC_LAMBDA_PATTERNS: List[str] = [
    # https://r8.googlesource.com/r8/+/refs/tags/3.1.34/src/main/java/com/android/tools/r8/synthesis/SyntheticNaming.java#140
    "$$ExternalSyntheticLambda",
    #  Desugared lambda classes from older versions of D8.
    "$$Lambda$",
    # $n for java anonymous classes. This should be checked last.
    "$",
]


class IssueCallee(NamedTuple):
    callee: Union[str, ExploitabilityOrigin]

    @staticmethod
    def from_json(issue_json: Dict[str, Any]) -> "IssueCallee":
        """
        A helper method to parse Issue::Callee variant:
        - if "callee" key is present, it is a regular source/sink flow and
          callee is the string itself.
        - else it is an issue for an exploitability rule and must have
          the key "exploitability_origin".
        """
        if "callee" in issue_json:
            return IssueCallee(issue_json["callee"])
        else:
            return IssueCallee(
                ExploitabilityOrigin.from_json(issue_json["exploitability_origin"])
            )

    @staticmethod
    def _split_class_name_at_lambda_pattern(class_name: str) -> Tuple[str, str]:
        """
        This method splits the input class_name at lambda pattern boundaries and
        returns the prefix and the remainder of the class_name after the removal
        of the lambda pattern.
        """
        substring_index = class_name.find("$")
        if substring_index < 0:
            return (class_name, "")

        # Keep the $ in prefix to separate nested anonymous classes.
        prefix = class_name[: (substring_index + 1)]
        remaining = class_name[substring_index:]

        for pattern in EXTERNAL_SYNTHETIC_LAMBDA_PATTERNS:
            if remaining.startswith(pattern):
                # Found lambda pattern. Strip it from remaining
                remaining = remaining.lstrip(pattern)
                break

        # Remove digits after lambda patterns
        remaining_length = len(remaining)
        index = 0

        while index < remaining_length and remaining[index].isdigit():
            index += 1
        remaining = remaining[index:]

        return (prefix, remaining)

    @staticmethod
    def _strip_anonymous_class_numbers(
        callee_signature: str, callable_line: int, issue_line: int
    ) -> str:
        """
        This is meant to remove the compiler-generated anonymous class numbers within
        the sink callee signature to be included in an issue master handle. The number
        is replaced with the relative line of the issue within the root callable. This
        is done because the anonymous class number is more susceptible to changing with
        unrelated changes in a diff rather than the relative line number of the issue
        in the root callable.
        """
        first_semicolon = callee_signature.find(";")
        if first_semicolon < 0:
            return callee_signature

        class_name = callee_signature[:first_semicolon]

        stripped_classname, remaining = IssueCallee._split_class_name_at_lambda_pattern(
            class_name
        )

        while len(remaining) > 0:
            prefix, remaining = IssueCallee._split_class_name_at_lambda_pattern(
                remaining
            )
            stripped_classname += prefix

        if stripped_classname == class_name:
            return callee_signature

        relative_line = -1
        if issue_line > -1 and issue_line >= callable_line:
            relative_line = issue_line - callable_line
        return (
            f"{stripped_classname}#{relative_line}{callee_signature[first_semicolon:]}"
        )

    def to_sapp_handle(self, callable: str, callable_line: int, issue_line: int) -> str:
        if isinstance(self.callee, ExploitabilityOrigin):
            # We do not include `callable` in the handle for exploitability issues.
            # This way, SAPP UI groups all issues with the same exploitability origin
            # together in the unique issues view.
            # This does mean that we will write multiple issue instances with the
            # same issue handle.
            callee = IssueCallee._strip_anonymous_class_numbers(
                self.callee.callee, callable_line, issue_line
            )
            return f"{self.callee.exploitability_root}:{callee}"
        elif isinstance(self.callee, str):
            callee = IssueCallee._strip_anonymous_class_numbers(
                self.callee, callable_line, issue_line
            )
            return f"{callable}:{callee}"
        else:
            raise AssertionError(
                "Unreachable state for IssueCallee.get_handle() method"
            )
