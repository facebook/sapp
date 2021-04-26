# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import json
import logging
import re
import sys
from typing import (
    IO,
    Any,
    Dict,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    Union,
    Pattern,
)

from .. import pipeline as sapp
from ..analysis_output import AnalysisOutput, Metadata
from .base_parser import BaseParser

try:
    # type: ignore
    from ...facebook.lib import configuration
except Exception:
    from .. import configuration

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


LOG: logging.Logger = logging.getLogger()
UNKNOWN_PATH: str = "unknown"
UNKNOWN_LINE: int = -1


# NOTE: This may or may not produce desired results if there is a number
# in the field name; need to find an example
def _upper_camel_case_to_snake_case(string: str) -> str:
    return re.sub("([a-z])([A-Z])", "\\1_\\2", string).lower()


class CanonicalNames:
    class JavaMethod:
        class_package: str
        class_name: str
        method_name: str
        type_string: str

        def __init__(
            self,
            class_package: str,
            class_name: str,
            method_name: str,
            type_string: str,
        ) -> None:
            self.class_package = class_package
            self.class_name = class_name
            self.method_name = method_name
            self.type_string = type_string

        _prototype_regex: Pattern[str] = re.compile("L(.+)/([^/;]+);\\.([^:]+):(.+)")

        @classmethod
        def parse_from_prototype(
            cls, prototype_string: str
        ) -> Optional["CanonicalNames.JavaMethod"]:
            match_data = cls._prototype_regex.match(prototype_string)

            if match_data is None:
                return None
            else:
                return CanonicalNames.JavaMethod(
                    match_data[1], match_data[2], match_data[3], match_data[4]
                )

    @staticmethod
    def mariana_trench_canonicalize_name(method_prototype: str) -> str:
        method_parsed: Optional[
            CanonicalNames.JavaMethod
        ] = CanonicalNames.JavaMethod.parse_from_prototype(method_prototype)

        if method_parsed is None:
            LOG.warning(
                f"Attempting to canonicalize Java method prototype {method_prototype} "
                "as connection point. This likely occurred because a leaf marked as "
                "a connection point had parameter overrides."
            )
            return method_prototype

        if method_parsed.class_package == configuration.GRAPHQL_PACKAGE:
            ### GraphQL mutation

            if not method_parsed.method_name.startswith("set"):
                LOG.error(
                    f"Non-setter method {method_parsed.method_name} "
                    "of GraphQL mutation {method_parsed.class_name} "
                    "marked as connection point; don't know how to "
                    "canonicalize name."
                )
                return method_prototype

            mutation_name = method_parsed.class_name
            field_name = _upper_camel_case_to_snake_case(
                method_parsed.method_name[len("set") :]
            )

            return f"{mutation_name}:{field_name}"
        elif (
            method_parsed.class_package == configuration.STRUCTURED_LOGGER_PACKAGE
            and not method_parsed.class_name.endswith("Impl")
        ):
            #### Structured logggers

            if not method_parsed.method_name.startswith("set"):
                LOG.error(
                    f"Non-setter method {method_parsed.method_name} "
                    "of structured logger {method_parsed.class_name} "
                    "marked as connection point; don't know how to "
                    "canonicalize name."
                )
                return method_prototype

            event_name = method_parsed.class_name
            field_name = _upper_camel_case_to_snake_case(
                method_parsed.method_name[len("set") :]
            )

            return f"{event_name}:{field_name}"
        else:
            return method_prototype


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
    def from_json(port: str, leaf_kind: str) -> "Port":
        elements = port.split(".")

        if len(elements) == 0:
            raise AssertionError(f"invalid port: `{port}`")

        elements[0] = elements[0].lower()
        if elements[0] == "leaf":
            elements[0] = leaf_kind
        elif elements[0] == "return":
            elements[0] = "result"
        elif elements[0] == "anchor":
            return Port("%s:%s" % (elements[0], ".".join(elements[1:])))
        elif elements[0] == "producer" and len(elements) >= 4:
            # Producer port is of the form Producer:<producer_id>:<canonical_port>:<canonical_name>
            port_match = re.search("Argument\\((-?\\d+)\\)", elements[2])
            if port_match:
                # Add 1 here since we subtracted 1 when canonicalizing the port in to_crtex.py
                index = int(port_match.group(1)) + 1
                return Port(
                    "%s:%s:%s"
                    % (
                        elements[0],
                        elements[1],
                        f"argument({index})",
                    )
                )
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
                raise AssertionError(
                    f"missing call position for call to `{call_method.name}`"
                )
            else:
                call_position = default_position
        else:
            call_position = Position.from_json(position, call_method)
        return Call(call_method, call_port, call_position)


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
        may_features = set(
            features.get("may_features", []) + features.get("always_features", [])
        )
        always_features = {
            f"always-{feature}" for feature in features.get("always_features", [])
        }
        return Features(may_features | always_features)

    def to_sapp(self) -> List[str]:
        return sorted(self.features)


class Condition(NamedTuple):
    caller: Call
    callee: Call
    kind: str
    distance: int
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
            features=self.features.to_sapp(),
            titos=self.local_positions.to_sapp(),
            leaves=[(self.kind, self.distance)],
            annotations=[],
        )


class Precondition(Condition):
    def to_sapp(self) -> sapp.ParseConditionTuple:
        return super().convert_to_sapp(sapp.ParseType.PRECONDITION)


class Postcondition(Condition):
    def to_sapp(self) -> sapp.ParseConditionTuple:
        return super().convert_to_sapp(sapp.ParseType.POSTCONDITION)


class IssueCondition(NamedTuple):
    callee: Call
    kind: str
    distance: int
    local_positions: LocalPositions
    features: Features

    def to_sapp(self) -> sapp.ParseIssueConditionTuple:
        return sapp.ParseIssueConditionTuple(
            callee=self.callee.method.name,
            port=self.callee.port.value,
            location=self.callee.position.to_sapp(),
            leaves=[(self.kind, self.distance)],
            titos=self.local_positions.to_sapp(),
            features=self.features.to_sapp(),
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
            handle=parser.compute_master_handle(
                callable=self.callable.name,
                line=self.issue_position.line - self.callable_position.line,
                start=self.issue_position.start,
                end=self.issue_position.end,
                code=self.code,
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
        return metadata.tool == "mariana_trench"

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
            yield from self._parse_issues(model)
            for precondition in self._parse_precondition(model):
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
        frames = issue[f"{leaf_kind}s"]

        conditions = []
        leaves = set()

        for frame in frames:
            frame = Parser._normalize_frame(frame, callable)
            conditions.append(
                IssueCondition(
                    callee=Call.from_json(
                        method=frame.get("callee"),
                        port=frame["callee_port"],
                        position=frame.get("call_position"),
                        default_position=callable_position,
                        leaf_kind=leaf_kind,
                    ),
                    kind=frame["kind"],
                    distance=frame.get("distance", 0),
                    local_positions=LocalPositions.from_json(
                        frame.get("local_positions", []), callable
                    ),
                    features=Features.from_json(frame.get("local_features", {})),
                )
            )

            for origin in frame.get("origins", []):
                leaves.add(
                    Leaf(
                        method=Method.from_json(origin),
                        kind=frame["kind"],
                        distance=frame.get("distance", 0),
                    )
                )

        return conditions, leaves

    @staticmethod
    def _normalize_frame(frame: Dict[str, Any], caller: Method) -> Dict[str, Any]:
        # Handle cross-repository taint exchange.
        if str.startswith(frame["callee_port"], "Anchor"):
            frame["callee"] = CanonicalNames.mariana_trench_canonicalize_name(
                caller.name
            )
            frame["callee_port"] += "."
            frame["callee_port"] += Port.from_json(
                frame["caller_port"], leaf_kind=""
            ).value
        elif str.startswith(frame["callee_port"], "Producer"):
            # Currently the Producer port is of the form
            # Producer.<producer_id>.<canonical_port>.<canonical_name>,
            # so we get the canonical name from it
            port_parts = frame["callee_port"].split(".", 3)
            if len(port_parts) == 4:
                frame["callee"] = port_parts[-1]

        return frame

    def _parse_precondition(self, model: Dict[str, Any]) -> Iterable[Precondition]:
        caller = Method.from_json(model["method"])
        caller_position = Position.from_json(model["position"], caller)

        for sink in model.get("sinks", []):
            sink = Parser._normalize_frame(sink, caller)
            yield Precondition(
                caller=Call(
                    method=caller,
                    port=Port.from_json(sink["caller_port"], "sink"),
                    position=caller_position,
                ),
                callee=Call.from_json(
                    method=sink.get("callee"),
                    port=sink["callee_port"],
                    position=sink.get("call_position"),
                    default_position=caller_position,
                    leaf_kind="sink",
                ),
                kind=sink["kind"],
                distance=sink.get("distance", 0),
                local_positions=LocalPositions.from_json(
                    sink.get("local_positions", []), caller
                ),
                features=Features.from_json(sink.get("local_features", {})),
            )

    def _parse_postconditions(self, model: Dict[str, Any]) -> Iterable[Postcondition]:
        caller = Method.from_json(model["method"])
        caller_position = Position.from_json(model["position"], caller)

        for generation in model.get("generations", []):
            generation = Parser._normalize_frame(generation, caller)
            yield Postcondition(
                caller=Call(
                    method=caller,
                    port=Port.from_json(generation["caller_port"], "source"),
                    position=caller_position,
                ),
                callee=Call.from_json(
                    method=generation.get("callee"),
                    port=generation["callee_port"],
                    position=generation.get("call_position"),
                    default_position=caller_position,
                    leaf_kind="source",
                ),
                kind=generation["kind"],
                distance=generation.get("distance", 0),
                local_positions=LocalPositions.from_json(
                    generation.get("local_positions", []), caller
                ),
                features=Features.from_json(generation.get("local_features", {})),
            )
