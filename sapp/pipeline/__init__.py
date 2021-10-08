# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import logging
import sys
from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any,
    Dict,
    Generic,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Tuple,
    TypeVar,
    Union,
)

from ..sarif_types import SARIFRegionObject


if sys.version_info >= (3, 8):
    from typing import TypedDict, Literal
else:
    from typing_extensions import TypedDict, Literal


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


# NB: The TypedDict types are an approximation of the legacy untyped maps emitted
# by the various parsers. They are transformed into the NamedTuple versions immediately
# after parsing, before the rest of the pipeline is executed.
# This is for performance reasons (we intern very common strings, and NamedTuples themselves are more memory-efficient).

# Parsers can also choose to directly return the new NamedTuple types.
# Eventually, we should convert all the parsers to return the NamedTuple versions,
# and delete the TypedDict versions. But it's a ton of work to do so
# (especially converting all the unit tests), so we have two versions for now.


class ParsePosition(TypedDict, total=False):
    filename: str
    line: int
    start: int
    end: int


class SourceLocation(NamedTuple):
    """The location in a source file that an error occurred in

    If end_column is defined then we have a range, otherwise it defaults to
    begin_column and we have a single point.
    """

    line_no: int
    begin_column: int
    end_column: int

    @staticmethod
    def of(
        line_no: int, begin_column: int, end_column: Optional[int] = None
    ) -> "SourceLocation":
        return SourceLocation(line_no, begin_column, end_column or begin_column)

    def __str__(self) -> str:
        return SourceLocation.to_string(self)

    def to_sarif(self) -> SARIFRegionObject:
        region = {
            "startLine": self.line_no,
            "startColumn": self.begin_column,
        }
        if self.end_column:
            region["endColumn"] = self.end_column + 1
        return region

    @staticmethod
    def from_typed_dict(d: ParsePosition) -> "SourceLocation":
        return SourceLocation(
            d["line"],
            d["start"],
            d["end"],
        )

    @staticmethod
    def from_string(location_string: str) -> "SourceLocation":
        location_points = location_string.split("|")
        assert len(location_points) == 3, "Invalid location string %s" % location_string
        return SourceLocation(*map(int, location_points))

    @staticmethod
    def to_string(location: "SourceLocation") -> str:
        return "|".join(
            map(str, [location.line_no, location.begin_column, location.end_column])
        )


class ParseTypeInterval(NamedTuple):
    start: int
    finish: int
    preserves_type_context: bool


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
    subtraces: List[Dict[str, Any]]  # TODO figure what exactly this shape is

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


ParseFeature = Dict[str, str]
ParseLeaf = Tuple[str, int]  # (kind, distance)
ParseIssueLeaf = Tuple[str, str, int]  # (callable, kind, distance)


def flatten_feature(feature: ParseFeature) -> Iterable[str]:
    for key, value in feature.items():
        if isinstance(value, str) and value:
            yield key + ":" + value
        else:
            yield key


def flatten_features(features: Iterable[ParseFeature]) -> List[str]:
    ret = []
    for feature in features:
        ret.extend(flatten_feature(feature))
    return ret


def intern_leaves(leaves: Iterable[ParseLeaf]) -> List[ParseLeaf]:
    return list(map(lambda p: (sys.intern(p[0]), p[1]), leaves))


class ParseCondition(TypedDict, total=False):
    type: Union[Literal[ParseType.PRECONDITION], Literal[ParseType.POSTCONDITION]]
    callable: str
    caller: str
    caller_port: str
    filename: str
    callee: str
    callee_port: str
    callee_location: ParsePosition
    leaves: Iterable[ParseLeaf]
    type_interval: Optional[ParseTypeInterval]
    features: Iterable[ParseFeature]
    titos: Iterable[ParsePosition]
    annotations: Iterable[Dict[str, Any]]


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
    features: List[str]
    titos: Iterable[SourceLocation]
    annotations: Iterable[ParseTraceAnnotation]

    @staticmethod
    def from_typed_dict(d: ParseCondition) -> "ParseConditionTuple":
        return ParseConditionTuple(
            type=d["type"],
            caller=d["caller"],
            caller_port=d["caller_port"],
            filename=d["filename"],
            callee=d["callee"],
            callee_port=d["callee_port"],
            callee_location=SourceLocation.from_typed_dict(d["callee_location"]),
            leaves=list(d["leaves"]),
            type_interval=d["type_interval"],
            features=flatten_features(d.get("features", [])),
            titos=list(map(SourceLocation.from_typed_dict, d.get("titos", []))),
            annotations=list(
                map(ParseTraceAnnotation.from_json, d.get("annotations", []))
            ),
        )

    def interned(self) -> "ParseConditionTuple":
        "Return self, but with certain strings interned"
        return ParseConditionTuple(
            type=self.type,
            caller=self.caller,
            caller_port=sys.intern(self.caller_port),
            filename=self.filename,
            callee=self.callee,
            callee_port=sys.intern(self.callee_port),
            callee_location=self.callee_location,
            leaves=intern_leaves(self.leaves),
            type_interval=self.type_interval,
            features=list(map(sys.intern, self.features)),
            titos=self.titos,
            annotations=self.annotations,
        )


class ParseIssueCondition(TypedDict):
    callee: str
    port: str
    location: ParsePosition
    leaves: Iterable[ParseLeaf]
    titos: Iterable[ParsePosition]
    features: Iterable[ParseFeature]
    type_interval: Optional[ParseTypeInterval]
    annotations: Iterable[Dict[str, Any]]


class ParseIssueConditionTuple(NamedTuple):
    callee: str
    port: str
    location: SourceLocation
    leaves: List[ParseLeaf]
    titos: Iterable[SourceLocation]
    features: List[str]
    type_interval: Optional[ParseTypeInterval]
    annotations: Iterable[ParseTraceAnnotation]

    @staticmethod
    def from_typed_dict(d: ParseIssueCondition) -> "ParseIssueConditionTuple":
        return ParseIssueConditionTuple(
            callee=d["callee"],
            port=d["port"],
            location=SourceLocation.from_typed_dict(d["location"]),
            leaves=list(d["leaves"]),
            titos=list(map(SourceLocation.from_typed_dict, d.get("titos", []))),
            features=flatten_features(d.get("features", [])),
            type_interval=d["type_interval"],
            annotations=list(
                map(ParseTraceAnnotation.from_json, d.get("annotations", []))
            ),
        )

    def interned(self) -> "ParseIssueConditionTuple":
        "Return self, but with certain strings interned"
        return ParseIssueConditionTuple(
            callee=self.callee,
            port=sys.intern(self.port),
            location=self.location,
            leaves=intern_leaves(self.leaves),
            titos=self.titos,
            features=list(map(sys.intern, self.features)),
            type_interval=self.type_interval,
            annotations=self.annotations,
        )


class ParseIssue(TypedDict, total=False):
    type: Literal[ParseType.ISSUE]
    code: int
    message: str
    callable: str
    handle: str
    filename: str
    callable_line: int
    line: int
    start: int
    end: int
    preconditions: Iterable[ParseIssueCondition]
    postconditions: Iterable[ParseIssueCondition]
    initial_sources: Iterable[ParseIssueLeaf]
    final_sinks: Iterable[ParseIssueLeaf]
    features: Iterable[ParseFeature]
    fix_info: Optional[Dict[str, Any]]


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

    @staticmethod
    def from_typed_dict(d: ParseIssue) -> "ParseIssueTuple":
        return ParseIssueTuple(
            code=d["code"],
            message=d["message"],
            callable=d["callable"],
            handle=d["handle"],
            filename=d["filename"],
            callable_line=d.get("callable_line", None),
            line=d["line"],
            start=d["start"],
            end=d["end"],
            preconditions=list(
                map(ParseIssueConditionTuple.from_typed_dict, d["preconditions"])
            ),
            postconditions=list(
                map(ParseIssueConditionTuple.from_typed_dict, d["postconditions"])
            ),
            initial_sources=d["initial_sources"],
            final_sinks=d["final_sinks"],
            features=flatten_features(d["features"]),
            fix_info=d.get("fix_info"),
        )

    def interned(self) -> "ParseIssueTuple":
        return ParseIssueTuple(
            code=self.code,
            message=self.message,
            callable=self.callable,
            handle=self.handle,
            filename=self.filename,
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
    issues: Iterable[ParseIssueTuple]


Summary = Dict[str, Any]  # blob of objects that gets passed through the pipeline


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


class Pipeline(object):
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
            summary = {}
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
