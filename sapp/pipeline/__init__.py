# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import logging
import sys
import time
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
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
from ..metrics_logger import MetricsLogger, NoOpMetricsLogger, ScopedMetricsLogger
from ..models import Run, SourceLocation, TraceKind

from ..operating_system import get_rss_in_gb

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


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
    type: Literal[ParseType.ISSUE] = ParseType.ISSUE

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

    def with_added_features(self, features_to_add: Set[str]) -> "ParseIssueTuple":
        return self._replace(features=list(set(self.features) | features_to_add))


FrameKey = Tuple[str, str]  # (caller, caller_port)


@dataclass
class Frames:
    _frames: Dict[FrameKey, List[ParseConditionTuple]]
    _disposed: bool = False

    def __init__(self, frames: Dict[FrameKey, List[ParseConditionTuple]]) -> None:
        self._frames = frames

    def frames_from_caller(
        self, caller: str, caller_port: str
    ) -> List[ParseConditionTuple]:
        self._assert_not_disposed()
        return self._frames.get((caller, caller_port), [])

    def all_frames(self) -> Iterable[ParseConditionTuple]:
        self._assert_not_disposed()
        for frame in self._frames.values():
            yield from frame

    def key_count(self) -> int:
        self._assert_not_disposed()
        return len(self._frames)

    def frame_count(self) -> int:
        self._assert_not_disposed()
        return sum(len(frames) for frames in self._frames.values())

    def dispose(self) -> None:
        self._assert_not_disposed()
        self._disposed = True
        self._frames = {}

    def _assert_not_disposed(self) -> None:
        if self._disposed:
            raise Exception("dispose has already been called")


@dataclass
class IssuesAndFrames:
    issues: List[ParseIssueTuple]
    preconditions: Frames
    postconditions: Frames


@dataclass
class Summary:
    affected_file_sets: Optional[List[Optional[List[str]]]] = None
    affected_issues_only: Optional[bool] = None
    big_tito: Optional[Set[Tuple[str, str, int]]] = None
    branch: Optional[str] = None
    codes: Optional[List[int]] = None
    commit_hash: Optional[str] = None
    input_metadata: Optional[Metadata] = None
    job_id: Optional[str] = None
    logger_tier: Optional[str] = None
    meta_run_child_label: Optional[str] = None
    meta_run_identifier: Optional[str] = None
    missing_traces: Optional[Dict[TraceKind, Set[Tuple[str, str]]]] = None
    old_linemap_file: Optional[str] = None
    previous_issue_handles: Optional[Path] = None
    project: Optional[str] = None
    repo_dir: Optional[str] = None
    repository: Optional[str] = None
    runs: Optional[List[Run]] = None
    runs_attributes: Optional[List[List[object]]] = None  # List[List[RunAttribute]]
    run_kind: Optional[str] = None
    store_unused_models: Optional[bool] = None


def time_str(delta_in_seconds: float) -> str:
    minutes, seconds = divmod(delta_in_seconds, 60)
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
    def run(
        self, input: T_in, summary: Summary, scoped_metrics_logger: ScopedMetricsLogger
    ) -> Tuple[T_out, Summary]:
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
        metrics_logger: Optional[MetricsLogger] = None,
    ) -> Tuple[Any, Summary]:
        if summary is None:
            summary = Summary()
        if metrics_logger is None:
            metrics_logger = NoOpMetricsLogger()
        next_input = first_input
        timing = []
        for step in self.steps:
            step_name = step.__class__.__name__
            with metrics_logger.log_timing(
                key=f"Processing:{step_name}"
            ) as scoped_metrics_logger:
                start_perf_counter = time.perf_counter()
                next_input, summary = step.run(
                    next_input, summary, scoped_metrics_logger
                )
                scoped_metrics_logger.add_data("rss_in_gb", f"{get_rss_in_gb():.3}")
                timing.append((step_name, time.perf_counter() - start_perf_counter))
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
