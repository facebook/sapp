# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import logging
import sys
from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    cast,
    Dict,
    Generic,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

from ..analysis_output import Metadata
from ..models import Run, SourceLocation, TraceKind

if sys.version_info >= (3, 8):
    from typing import Literal, TypedDict
else:
    from typing_extensions import Literal, TypedDict


# pyre-fixme[5]: Global expression must be annotated.
log = logging.getLogger("sapp")

T = TypeVar("T")
T_in = TypeVar("T_in")
T_out = TypeVar("T_out")


class ParseError(Exception):
    def __init__(self, message: str, received: object = None) -> None:
        self.message = message
        self.received = received

    def __str__(self) -> str:
        message = self.message
        if self.received is not None:
            message = f"{message}\nReceived: `{self.received}`"
        return message


class ParseType(Enum):
    ISSUE = "issue"
    PRECONDITION = "precondition"
    POSTCONDITION = "postcondition"


class ParseTypeInterval(NamedTuple):
    start: int
    finish: int
    preserves_type_context: bool


class ParseTraceAnnotationSubtrace(NamedTuple):
    callee: str
    port: str
    position: SourceLocation
    features: List["ParseTraceFeature"] = []
    annotations: List["ParseTraceAnnotation"] = []


class ParseTraceAnnotation(NamedTuple):
    location: SourceLocation
    kind: str
    msg: str
    leaf_kind: Optional[str]
    leaf_depth: int
    type_interval: Optional[ParseTypeInterval]
    link: Optional[str]
    trace_key: Optional[str]
    titos: List[SourceLocation]
    subtraces: List[ParseTraceAnnotationSubtrace]

    @staticmethod
    def from_json(j: Dict[str, Any]) -> "ParseTraceAnnotation":
        return ParseTraceAnnotation(
            location=SourceLocation.from_typed_dict(j["location"]),
            kind=j["kind"],
            msg=j["msg"],
            leaf_kind=j.get("leaf_kind"),
            leaf_depth=j["leaf_depth"],
            type_interval=j.get("type_interval"),
            link=j.get("link"),
            trace_key=j.get("trace_key"),
            titos=list(map(SourceLocation.from_typed_dict, j.get("titos", []))),
            subtraces=j["subtraces"],
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.location,
                self.kind,
                self.msg,
                self.leaf_kind,
                self.leaf_depth,
            )
        )


class ParseTraceFeature(NamedTuple):
    name: str
    locations: List[SourceLocation]

    @staticmethod
    def from_json(j: Dict[str, Any]) -> "ParseTraceFeature":
        return ParseTraceFeature(
            name=j["name"],
            locations=list(map(SourceLocation.from_typed_dict, j.get("locations", []))),
        )

    def interned(self) -> "ParseTraceFeature":
        "Return self, but with certain strings interned"
        return ParseTraceFeature(
            name=sys.intern(self.name),
            locations=self.locations,
        )


def parse_trace_feature(feature: Union[str, Dict[str, Any]]) -> ParseTraceFeature:
    if isinstance(feature, dict):
        return ParseTraceFeature.from_json(feature)
    return ParseTraceFeature(feature, [])


ParseFeature = Dict[str, str]
ParseLeaf = Tuple[str, int]  # (kind, distance)
ParseIssueLeaf = Tuple[Optional[str], str, int]  # (callable, kind, distance)


def flatten_feature_to_parse_trace_feature(
    feature: Dict[str, Any],
) -> Iterable[ParseTraceFeature]:
    for key, value in feature.items():
        if isinstance(value, str) and value:
            yield ParseTraceFeature(key + ":" + value, [])
        else:
            yield ParseTraceFeature(key, [])


def flatten_features_to_parse_trace_feature(
    features: Iterable[Dict[str, Any]],
) -> List[ParseTraceFeature]:
    ret = []
    for feature in features:
        ret.extend(flatten_feature_to_parse_trace_feature(feature))
    return ret


def flatten_feature(feature: ParseFeature) -> Iterable[str]:
    for key, value in feature.items():
        if isinstance(value, str) and value:
            yield key + ":" + value
        else:
            yield key


def flatten_features(features: Iterable[Dict[str, Any]]) -> List[str]:
    ret = []
    for feature in features:
        ret.extend(flatten_feature(feature))
    return ret


def intern_leaves(leaves: Iterable[ParseLeaf]) -> List[ParseLeaf]:
    return list(map(lambda p: (sys.intern(p[0]), p[1]), leaves))


class ParseConditionTuple(NamedTuple):
    type: Union[Literal[ParseType.PRECONDITION], Literal[ParseType.POSTCONDITION]]
    caller: str
    caller_port: str
    filename: str
    callee: str
    callee_port: str
    callee_location: SourceLocation
    leaves: List[ParseLeaf]
    type_interval: Optional[ParseTypeInterval]
    features: List[ParseTraceFeature]
    titos: Iterable[SourceLocation]
    annotations: Iterable[ParseTraceAnnotation]

    def interned(self) -> "ParseConditionTuple":
        "Return self, but with certain strings interned"
        return ParseConditionTuple(
            type=self.type,
            caller=sys.intern(self.caller),
            caller_port=sys.intern(self.caller_port),
            filename=sys.intern(self.filename),
            callee=sys.intern(self.callee),
            callee_port=sys.intern(self.callee_port),
            callee_location=self.callee_location,
            leaves=intern_leaves(self.leaves),
            type_interval=self.type_interval,
            features=list(map(ParseTraceFeature.interned, self.features)),
            titos=self.titos,
            annotations=self.annotations,
        )


class ParseIssueConditionTuple(NamedTuple):
    callee: str
    port: str
    location: SourceLocation
    leaves: List[ParseLeaf]
    titos: Iterable[SourceLocation]
    features: List[ParseTraceFeature]
    type_interval: Optional[ParseTypeInterval]
    annotations: Iterable[ParseTraceAnnotation]
    root_port: Optional[str] = None

    def interned(self) -> "ParseIssueConditionTuple":
        "Return self, but with certain strings interned"
        return ParseIssueConditionTuple(
            callee=sys.intern(self.callee),
            port=sys.intern(self.port),
            location=self.location,
            leaves=intern_leaves(self.leaves),
            titos=self.titos,
            features=list(map(ParseTraceFeature.interned, self.features)),
            type_interval=self.type_interval,
            annotations=self.annotations,
            root_port=self.root_port,
        )


class ParseIssueTuple(NamedTuple):
    code: int
    message: str
    callable: str
    handle: str
    filename: str
    line: int
    start: int
    end: int
    preconditions: Iterable[ParseIssueConditionTuple]
    postconditions: Iterable[ParseIssueConditionTuple]
    initial_sources: Iterable[ParseIssueLeaf]
    final_sinks: Iterable[ParseIssueLeaf]
    features: List[str]
    callable_line: Optional[int]
    fix_info: Optional[Dict[str, Any]]

    def interned(self) -> "ParseIssueTuple":
        return ParseIssueTuple(
            code=self.code,
            message=self.message,
            callable=sys.intern(self.callable),
            handle=self.handle,
            filename=sys.intern(self.filename),
            callable_line=self.callable_line,
            line=self.line,
            start=self.start,
            end=self.end,
            preconditions=list(
                map(ParseIssueConditionTuple.interned, self.preconditions)
            ),
            postconditions=list(
                map(ParseIssueConditionTuple.interned, self.postconditions)
            ),
            initial_sources=self.initial_sources,
            final_sinks=self.final_sinks,
            features=list(map(sys.intern, self.features)),
            fix_info=self.fix_info,
        )


DictKey = Union[str, Tuple[str, str]]  # handle or (caller, caller_port)


class DictEntries(TypedDict):
    preconditions: Dict[DictKey, List[ParseConditionTuple]]
    postconditions: Dict[DictKey, List[ParseConditionTuple]]
    issues: List[ParseIssueTuple]


class Summary(TypedDict, total=False):
    affected_file_sets: List[Optional[List[str]]]
    affected_issues_only: bool
    big_tito: Set[Tuple[str, str, int]]
    branch: Optional[str]
    codes: Optional[List[int]]
    commit_hash: Optional[str]
    input_metadata: Metadata
    job_id: Optional[str]
    logger_tier: Optional[str]
    meta_run_child_label: Optional[str]
    meta_run_identifier: Optional[str]
    missing_traces: Dict[TraceKind, Set[Tuple[str, str]]]
    old_linemap_file: Optional[str]
    previous_issue_handles: Optional[Path]
    project: Optional[str]
    repo_dir: str
    repository: Optional[str]
    runs: List[Run]
    runs_attributes: List[object]  # List[List[RunAttribute]]
    run_kind: Optional[str]
    store_unused_models: bool
    trace_entries: Dict[TraceKind, Dict[DictKey, List[ParseConditionTuple]]]


# pyre-fixme[3]: Return type must be annotated.
def time_str(delta: timedelta):
    minutes, seconds = divmod(delta.total_seconds(), 60)
    seconds_string = f"{int(seconds)}s"
    if minutes > 0:
        return f"{int(minutes)}m {seconds_string}"
    return seconds_string


class PipelineStep(Generic[T_in, T_out], metaclass=ABCMeta):
    """Pipeline steps have an input type and an output type.
    T_in and T_out should both be child classes of PipelineData.
    """

    # pyre-fixme[3]: Return type must be annotated.
    def __init__(self):
        pass

    @abstractmethod
    def run(self, input: T_in, summary: Summary) -> Tuple[T_out, Summary]:
        raise NotImplementedError("PipelineStep.run is abstract")


class Pipeline:
    # pyre-fixme[3]: Return type must be annotated.
    # pyre-fixme[2]: Parameter annotation cannot contain `Any`.
    def __init__(self, steps: List[PipelineStep[Any, Any]]):
        # pyre-fixme[4]: Attribute annotation cannot contain `Any`.
        self.steps: List[PipelineStep[Any, Any]] = steps

    # pyre-fixme[3]: Return annotation cannot contain `Any`.
    def run(
        self,
        # pyre-fixme[2]: Parameter must be annotated.
        first_input,
        summary: Optional[Summary] = None,
    ) -> Tuple[Any, Summary]:
        if summary is None:
            summary = cast(Summary, {})
        next_input = first_input
        timing = []
        for step in self.steps:
            start_time = datetime.now()
            next_input, summary = step.run(next_input, summary)
            timing.append((step.__class__.__name__, datetime.now() - start_time))
        log.info(
            "Step timing: %s",
            ", ".join([f"{name} took {time_str(delta)}" for name, delta in timing]),
        )
        return next_input, summary


class PipelineBuilder(Generic[T_in]):
    def __init__(self) -> None:
        # pyre-fixme[4]: Attribute annotation cannot contain `Any`.
        self.steps: List[PipelineStep[Any, Any]] = []

    def append(self, step: PipelineStep[T_in, T_out]) -> "PipelineBuilder[T_out]":
        self.steps.append(step)
        return cast(PipelineBuilder[T_out], self)

    def build(self) -> Pipeline:
        return Pipeline(self.steps)
