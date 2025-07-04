# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from typing import (
    Any,
    Dict,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

import graphene  # @manual=fbsource//third-party/pypi/graphene-legacy:graphene-legacy

# @manual=fbsource//third-party/pypi/graphql-core-legacy:graphql-core-legacy
from graphql.execution.base import ResolveInfo
from sqlalchemy.orm import aliased, Session
from sqlalchemy.orm.util import AliasedClass

from ..models import (
    DBID,
    IssueInstanceTraceFrameAssoc,
    SharedText,
    SharedTextKind,
    SourceLocation,
    TraceFrame,
    TraceFrameLeafAssoc,
    TraceKind,
)
from . import run

FilenameText: AliasedClass = aliased(SharedText)
CallableText: AliasedClass = aliased(SharedText)
CallerText: AliasedClass = aliased(SharedText)
CalleeText: AliasedClass = aliased(SharedText)
MessageText: AliasedClass = aliased(SharedText)


def is_leaf_port(port: str) -> bool:
    return (
        port == "leaf"
        or port == "source"
        or port == "sink"
        or port.startswith("anchor:")
        or port.startswith("producer:")
        or port.startswith("leaf:")
        or port.startswith("source:")
        or port.startswith("sink:")
    )


class TraceFrameQueryResultType(graphene.ObjectType):
    class Meta:
        interfaces = (graphene.relay.Node,)

    frame_id = graphene.ID()
    caller = graphene.String()
    caller_port = graphene.String()
    callee = graphene.String()
    callee_port = graphene.String()
    caller_id = graphene.ID()
    callee_id = graphene.ID()
    callee_location = graphene.ID()
    kind = graphene.String()
    filename = graphene.String()
    trace_length = graphene.Int()
    is_leaf = graphene.Boolean()
    titos = graphene.String()

    def resolve_frame_id(self, info: ResolveInfo) -> DBID:
        # pyre-fixme[16]: `TraceFrameQueryResultType` has no attribute `id`.
        return self.id

    def resolve_is_leaf(self, info: ResolveInfo) -> bool:
        return is_leaf_port(str(self.callee_port))


class TraceFrameQueryResult(NamedTuple):
    id: DBID
    caller: str
    caller_port: str
    callee: str
    callee_port: str
    caller_id: Optional[DBID] = None
    callee_id: Optional[DBID] = None
    callee_location: Optional[SourceLocation] = None
    kind: Optional[TraceKind] = None
    filename: Optional[str] = None
    trace_length: Optional[int] = None
    titos: Optional[str] = None
    type_interval_lower: Optional[int] = None
    type_interval_upper: Optional[int] = None
    preserves_type_context: Optional[bool] = None
    shared_texts: List[SharedText] = []

    @staticmethod
    def from_record(
        record: Any,  # pyre-fixme[2]: Parameter annotation cannot be `Any`.
        shared_texts: Optional[List[SharedText]] = None,
    ) -> "TraceFrameQueryResult":
        return TraceFrameQueryResult(
            id=record.id,
            caller=record.caller,
            caller_port=record.caller_port,
            callee=record.callee,
            callee_port=record.callee_port,
            caller_id=record.caller_id,
            callee_id=record.callee_id,
            callee_location=record.callee_location,
            kind=record.kind,
            filename=record.filename,
            trace_length=getattr(record, "trace_length", None),
            titos=";".join([str(titos) for titos in getattr(record, "titos", [])]),
            type_interval_lower=record.type_interval_lower,
            type_interval_upper=record.type_interval_upper,
            preserves_type_context=record.preserves_type_context,
            shared_texts=shared_texts if shared_texts else [],
        )

    def is_leaf(self) -> bool:
        return is_leaf_port(self.callee_port)

    def get_human_readable_caller(self, tool: str) -> str:
        return self._human_readable_callable(self.caller, tool)

    def get_human_readable_callee(self, tool: str) -> str:
        return self._human_readable_callable(self.callee, tool)

    def _human_readable_callable(self, name: str, tool: str, depth: int = 1) -> str:
        if is_leaf_port(name):
            return name
        if tool == "mariana-trench":
            # convert name from dalvik byte code e.g.,
            # `Lpackage1/package2/class;.Func1` to human readable name class.Func1
            package_class_and_method_name = name.split(".")
            if len(package_class_and_method_name) != 2:
                return name
            package_and_class, method_name = package_class_and_method_name
            method_name = method_name.split(":")[0]
            package_and_class = package_and_class.strip(";").split("/")[depth * -1]
            return f"{package_and_class}.{method_name}"
        else:
            return name


class TraceTuple(NamedTuple):
    trace_frame: TraceFrameQueryResult
    branches: int = 1
    missing: bool = False
    # Suppose we select a trace frame (A->B) and the generated trace is
    #   (A->B), (B->C), (C->D) with D as leaf.
    # When we display traces, we only use the callee, so this trace would look
    #   like B->C->D. If we also want to see A->, then we need to add a
    #   placeholder trace tuple. We do this by setting our trace tuples to
    #   [(A->B, placeholder=True), (A->B), (B->C), (C->D)]. When placeholder is
    #   True, that means we need to output the caller rather than the callee.
    placeholder: bool = False


class LeafLookup:
    def __init__(
        self, sources: Dict[int, str], sinks: Dict[int, str], features: Dict[int, str]
    ) -> None:
        self._lookup: Dict[SharedTextKind, Dict[int, str]] = {
            SharedTextKind.source: sources,
            SharedTextKind.sink: sinks,
            SharedTextKind.feature: features,
        }

    @staticmethod
    def create(session: Session) -> "LeafLookup":
        return LeafLookup(
            {
                int(id): contents
                for id, contents in session.query(
                    SharedText.id, SharedText.contents
                ).filter(SharedText.kind == SharedTextKind.source)
            },
            {
                int(id): contents
                for id, contents in session.query(
                    SharedText.id, SharedText.contents
                ).filter(SharedText.kind == SharedTextKind.sink)
            },
            {
                int(id): contents
                for id, contents in session.query(
                    SharedText.id, SharedText.contents
                ).filter(SharedText.kind == SharedTextKind.feature)
            },
        )

    def resolve(self, ids: Sequence[int], kind: SharedTextKind) -> Set[str]:
        if kind not in [
            SharedTextKind.source,
            SharedTextKind.sink,
            SharedTextKind.feature,
        ]:
            raise ValueError(f"Cannot resolve ids of kind `{kind}`")

        lookup = self._lookup[kind]
        return {lookup[id] for id in ids if id in lookup}


def initial_frames(
    session: Session,
    issue_id: DBID,
    kind: TraceKind,
) -> List[TraceFrameQueryResult]:
    records = list(
        session.query(
            TraceFrame.id,
            TraceFrame.caller_id,
            CallerText.contents.label("caller"),
            TraceFrame.caller_port,
            TraceFrame.callee_id,
            CalleeText.contents.label("callee"),
            TraceFrame.callee_port,
            TraceFrame.callee_location,
            TraceFrame.kind,
            TraceFrame.type_interval_lower,
            TraceFrame.type_interval_upper,
            TraceFrame.preserves_type_context,
            FilenameText.contents.label("filename"),
            TraceFrameLeafAssoc.trace_length,
            TraceFrame.titos,
        )
        .filter(TraceFrame.kind == kind)
        .join(
            IssueInstanceTraceFrameAssoc,
            IssueInstanceTraceFrameAssoc.trace_frame_id == TraceFrame.id,
        )
        .filter(IssueInstanceTraceFrameAssoc.issue_instance_id == issue_id)
        .join(CallerText, CallerText.id == TraceFrame.caller_id)
        .join(CalleeText, CalleeText.id == TraceFrame.callee_id)
        .join(FilenameText, FilenameText.id == TraceFrame.filename_id)
        .join(TraceFrameLeafAssoc, TraceFrameLeafAssoc.trace_frame_id == TraceFrame.id)
        .group_by(TraceFrame.id)
        .order_by(TraceFrameLeafAssoc.trace_length, TraceFrame.callee_location)
        .all()
    )

    frames = []
    for record in records:
        shared_texts = list(
            session.query(SharedText)
            .join(TraceFrameLeafAssoc, SharedText.id == TraceFrameLeafAssoc.leaf_id)
            .filter(TraceFrameLeafAssoc.trace_frame_id == record.id)
            .all()
        )
        frames.append(TraceFrameQueryResult.from_record(record, shared_texts))
    return frames


def navigate_trace_frames(
    session: Session,
    initial_trace_frames: List[TraceFrameQueryResult],
    initial_leaf_kinds: Set[str],
    index: int = 0,
) -> List[Tuple[TraceFrameQueryResult, int]]:
    leaf_lookup = LeafLookup.create(session)

    if not initial_trace_frames:
        return []
    trace_frames: List[Tuple[TraceFrameQueryResult, Set[str], int]] = [
        (initial_trace_frames[index], initial_leaf_kinds, len(initial_trace_frames))
    ]
    visited_ids: Set[int] = {int(initial_trace_frames[index].id)}
    while not trace_frames[-1][0].is_leaf():
        trace_frame, leaf_kinds, branches = trace_frames[-1]
        next_nodes = next_frames(
            session,
            trace_frame,
            leaf_kinds,
            visited_ids,
            leaf_lookup=leaf_lookup,
        )

        if len(next_nodes) == 0:
            # Denote a missing frame by setting caller to None
            trace_frames.append(
                (
                    TraceFrameQueryResult(
                        id=DBID(0),
                        callee=trace_frame.callee,
                        callee_port=trace_frame.callee_port,
                        caller="",
                        caller_port="",
                    ),
                    set(),
                    0,
                )
            )
            break

        first_next_frame, first_leaf_kinds = next_nodes[0]
        visited_ids.add(int(first_next_frame.id))
        trace_frames.append((first_next_frame, first_leaf_kinds, len(next_nodes)))

    return [
        (trace_frame, branches) for trace_frame, leaf_kinds, branches in trace_frames
    ]


def leaf_kind_matches_caller(callee_kind: str, caller_kinds: Set[str]) -> bool:
    callee_kind = callee_kind.replace("@", ":")
    for caller_kind in caller_kinds:
        if "@" in caller_kind:
            # Compare with global transform kind only
            caller_kind = caller_kind.split("@", 1)[1]
        if caller_kind == callee_kind:
            return True

    return False


def next_frames(
    session: Session,
    pre_frame: TraceFrameQueryResult,
    pre_leaf_kinds: Set[str],
    visited_ids: Set[int],
    run_id: Optional[DBID] = None,
    leaf_lookup: Optional[LeafLookup] = None,
    backwards: bool = False,
) -> List[Tuple[TraceFrameQueryResult, Set[str]]]:
    """Finds all trace frames that the given trace_frame flows to.

    When backwards=True, the result will include the parameter trace_frame,
    since we are filtering on the parameter's callee.
    """
    query = (
        session.query(
            TraceFrame.id,
            TraceFrame.caller_id,
            CallerText.contents.label("caller"),
            TraceFrame.caller_port,
            TraceFrame.callee_id,
            CalleeText.contents.label("callee"),
            TraceFrame.callee_port,
            TraceFrame.callee_location,
            TraceFrame.kind,
            TraceFrame.type_interval_lower,
            TraceFrame.type_interval_upper,
            TraceFrame.preserves_type_context,
            FilenameText.contents.label("filename"),
            TraceFrameLeafAssoc.trace_length,
            TraceFrame.titos,
        )
        .filter(TraceFrame.run_id == (run_id or run.latest(session)))
        .filter(TraceFrame.kind == pre_frame.kind)
        .join(CallerText, CallerText.id == TraceFrame.caller_id)
        .join(CalleeText, CalleeText.id == TraceFrame.callee_id)
        .join(FilenameText, FilenameText.id == TraceFrame.filename_id)
        .filter(TraceFrame.id != pre_frame.id)  # skip trivial loops
    )
    if backwards:
        query = query.filter(TraceFrame.callee_id == pre_frame.caller_id).filter(
            TraceFrame.callee_port == pre_frame.caller_port
        )
    else:
        query = query.filter(TraceFrame.caller_id == pre_frame.callee_id).filter(
            TraceFrame.caller_port == pre_frame.callee_port
        )

    results = (
        query.join(
            TraceFrameLeafAssoc, TraceFrameLeafAssoc.trace_frame_id == TraceFrame.id
        )
        .group_by(TraceFrame.id)
        .order_by(TraceFrameLeafAssoc.trace_length, TraceFrame.callee_location)
    )

    filtered_results = []

    for frame in results:
        if int(frame.id) in visited_ids:
            continue
        frame_leaf_kinds = [
            leaf_kind
            for leaf_kind in get_leaves_trace_frame(
                session,
                int(frame.id),
                trace_kind_to_shared_text_kind(frame.kind),
                _leaf_lookup(session, leaf_lookup),
            )
            if leaf_kind_matches_caller(
                callee_kind=leaf_kind, caller_kinds=pre_leaf_kinds
            )
        ]
        if len(frame_leaf_kinds) == 0:
            continue

        if not TraceFrame.type_intervals_match_or_ignored(
            pre_frame.type_interval_lower,
            pre_frame.type_interval_upper,
            pre_frame.preserves_type_context,
            frame.type_interval_lower,
            frame.type_interval_upper,
            frame.preserves_type_context,
        ):
            # We are not ignoring and we have no match
            # so therefore filter the result from the results
            continue

        shared_texts = list(
            session.query(SharedText)
            .join(TraceFrameLeafAssoc, SharedText.id == TraceFrameLeafAssoc.leaf_id)
            .filter(TraceFrameLeafAssoc.trace_frame_id == frame.id)
            .all()
        )

        filtered_results.append((frame, frame_leaf_kinds, shared_texts))

    return [
        (TraceFrameQueryResult.from_record(frame, shared_texts), leaf_kinds)
        for frame, leaf_kinds, shared_texts in filtered_results
    ]


def _leaf_lookup(
    session: Session, leaf_lookup: Optional[LeafLookup] = None
) -> LeafLookup:
    if leaf_lookup:
        return leaf_lookup

    return LeafLookup.create(session)


def get_leaves_trace_frame(
    session: Session,
    trace_frame_id: Union[int, DBID],
    kind: SharedTextKind,
    leaf_lookup: Optional[LeafLookup] = None,
) -> Set[str]:
    ids = [
        int(id)
        for (id,) in session.query(SharedText.id)
        .distinct(SharedText.id)
        .join(TraceFrameLeafAssoc, SharedText.id == TraceFrameLeafAssoc.leaf_id)
        .filter(TraceFrameLeafAssoc.trace_frame_id == trace_frame_id)
        .filter(SharedText.kind == kind)
    ]
    return _leaf_lookup(session, leaf_lookup).resolve(ids, kind)


def trace_kind_to_shared_text_kind(trace_kind: Optional[TraceKind]) -> SharedTextKind:
    if trace_kind == TraceKind.postcondition:
        return SharedTextKind.source
    if trace_kind == TraceKind.precondition:
        return SharedTextKind.sink

    raise AssertionError(f"{trace_kind} is invalid")


def create_trace_tuples(
    navigation: Iterable[Tuple[TraceFrameQueryResult, int]],
) -> List[TraceTuple]:
    return [
        TraceTuple(
            trace_frame=trace_frame,
            branches=branches,
            missing=trace_frame.caller == "",
        )
        for trace_frame, branches in navigation
    ]
