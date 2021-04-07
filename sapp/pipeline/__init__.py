# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import logging
from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    TypeVar,
    TypedDict,
    Iterable,
    Union,
    Literal,
)

from ..analysis_output import AnalysisOutput


# pyre-fixme[5]: Global expression must be annotated.
log = logging.getLogger("sapp")

T = TypeVar("T")
T_in = TypeVar("T_in")
T_out = TypeVar("T_out")


class ParseType(Enum):
    ISSUE = "issue"
    PRECONDITION = "precondition"
    POSTCONDITION = "postcondition"


class ParsePosition(TypedDict, total=False):
    filename: str
    line: int
    start: int
    end: int


class ParseTypeInterval(TypedDict, total=False):
    start: int
    finish: int
    preserves_type_context: bool


ParseFeature = Dict[str, str]
ParseLeaf = Tuple[str, int]  # (kind, distance)
ParseIssueLeaf = Tuple[str, str, int]  # (callable, kind, distance)


class ParseCondition(TypedDict, total=False):
    type: Union[Literal[ParseType.PRECONDITION], Literal[ParseType.POSTCONDITION]]
    callable: str
    caller: str
    caller_port: str
    filename: str
    callee: str
    callee_port: str
    callee_location: ParsePosition
    sources: Iterable[ParseLeaf]
    sinks: Iterable[ParseLeaf]
    leaves: Iterable[ParseLeaf]  # specify either `leaves`, `sources` or `sinks`.
    type_interval: ParseTypeInterval
    features: Iterable[ParseFeature]
    titos: Iterable[ParsePosition]
    annotations: Iterable[Dict[str, Any]]


class ParseIssueCondition(TypedDict):
    callee: str
    port: str
    location: ParsePosition
    leaves: Iterable[ParseLeaf]
    titos: Iterable[ParsePosition]
    features: Iterable[ParseFeature]
    type_interval: ParseTypeInterval
    annotations: Iterable[Dict[str, Any]]


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
    fix_info: Dict[str, Any]


DictKey = Union[str, Tuple[str, str]]  # handle or (caller, caller_port)


class DictEntries(TypedDict):
    preconditions: Dict[DictKey, List[ParseCondition]]
    postconditions: Dict[DictKey, List[ParseCondition]]
    issues: Iterable[ParseIssue]


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
        assert False, "Abstract method called!"
        pass


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
