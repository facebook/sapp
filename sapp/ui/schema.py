# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
from pathlib import Path
from typing import Any, List, Optional

import graphene
from graphene import relay
from graphene_sqlalchemy import get_session
from graphql.execution.base import ResolveInfo

from ..filter import Filter
from ..models import DBID, TraceFrame, TraceKind
from . import filters as filters_module
from . import issues, run, trace, typeahead
from .issues import (
    Instance,
    IssueQueryResult,
    IssueQueryResultType,
    update_status,
)
from .trace import TraceFrameQueryResult, TraceFrameQueryResultType


class RunConnection(relay.Connection):
    class Meta:
        node = run.Run


class IssueConnection(relay.Connection):
    class Meta:
        node = IssueQueryResultType


class TraceFrameConnection(relay.Connection):
    class Meta:
        node = TraceFrameQueryResultType


class File(graphene.ObjectType):
    class Meta:
        interfaces = (relay.Node,)

    path = graphene.String()
    contents = graphene.String()
    editor_link = graphene.String()


class FileConnection(relay.Connection):
    class Meta:
        node = File


class CodeConnection(relay.Connection):
    class Meta:
        node = typeahead.Code


class PathConnection(relay.Connection):
    class Meta:
        node = typeahead.Path


class CallableConnection(relay.Connection):
    class Meta:
        node = typeahead.Callable


class SourceNameConnection(relay.Connection):
    class Meta:
        node = typeahead.SourceName


class SourceKindConnection(relay.Connection):
    class Meta:
        node = typeahead.SourceKind


class SinkNameConnection(relay.Connection):
    class Meta:
        node = typeahead.SinkName


class SinkKindConnection(relay.Connection):
    class Meta:
        node = typeahead.SinkKind


class StatusConnection(relay.Connection):
    class Meta:
        node = typeahead.Status


class FeatureConnection(relay.Connection):
    class Meta:
        node = typeahead.Feature


class FilterConnection(relay.Connection):
    class Meta:
        node = filters_module.Filter


class FeatureCondition(graphene.InputObjectType):
    mode = graphene.String()
    features = graphene.List(graphene.String)


class MatchesIsField(graphene.InputObjectType):
    operation = graphene.String()
    value = graphene.List(graphene.String)


class Query(graphene.ObjectType):
    # pyre-fixme[4]: Attribute must be annotated.
    node = relay.Node.Field()

    runs = relay.ConnectionField(
        RunConnection,
    )

    issues = relay.ConnectionField(
        IssueConnection,
        run_id=graphene.Int(required=True),
        codes=graphene.List(graphene.Int, default_value=["%"]),
        paths=graphene.List(graphene.String, default_value=["%"]),
        callables=MatchesIsField(),
        source_names=MatchesIsField(),
        source_kinds=MatchesIsField(),
        sink_names=MatchesIsField(),
        sink_kinds=MatchesIsField(),
        statuses=graphene.List(graphene.String, default_value=["%"]),
        features=graphene.List(FeatureCondition),
        min_trace_length_to_sinks=graphene.Int(),
        max_trace_length_to_sinks=graphene.Int(),
        min_trace_length_to_sources=graphene.Int(),
        max_trace_length_to_sources=graphene.Int(),
        issue_instance_id=graphene.Int(),
        is_new_issue=graphene.Boolean(),
    )

    trace = relay.ConnectionField(TraceFrameConnection, issue_instance_id=graphene.ID())
    initial_trace_frames = relay.ConnectionField(
        TraceFrameConnection, issue_instance_id=graphene.Int(), kind=graphene.String()
    )
    next_trace_frames = relay.ConnectionField(
        TraceFrameConnection,
        issue_instance_id=graphene.Int(),
        frame_id=graphene.Int(),
        kind=graphene.String(),
    )

    # Typeahead data.
    codes = relay.ConnectionField(CodeConnection)
    paths = relay.ConnectionField(PathConnection)
    callables = relay.ConnectionField(CallableConnection)
    features = relay.ConnectionField(FeatureConnection)
    source_names = relay.ConnectionField(SourceNameConnection)
    source_kinds = relay.ConnectionField(SourceKindConnection)
    sink_names = relay.ConnectionField(SinkNameConnection)
    sink_kinds = relay.ConnectionField(SinkKindConnection)
    statuses = relay.ConnectionField(StatusConnection)

    file = relay.ConnectionField(FileConnection, path=graphene.String())

    filters = relay.ConnectionField(FilterConnection)

    def resolve_runs(self, info: ResolveInfo) -> List[run.Run]:
        session = get_session(info.context)
        return run.runs(session)

    def resolve_issues(
        self,
        info: ResolveInfo,
        run_id: int,
        codes: List[int],
        paths: List[str],
        statuses: List[str],
        callables: Optional[MatchesIsField] = None,
        features: Optional[List[FeatureCondition]] = None,
        min_trace_length_to_sinks: Optional[int] = None,
        max_trace_length_to_sinks: Optional[int] = None,
        min_trace_length_to_sources: Optional[int] = None,
        max_trace_length_to_sources: Optional[int] = None,
        issue_instance_id: Optional[int] = None,
        is_new_issue: Optional[bool] = None,
        source_names: Optional[MatchesIsField] = None,
        source_kinds: Optional[MatchesIsField] = None,
        sink_names: Optional[MatchesIsField] = None,
        sink_kinds: Optional[MatchesIsField] = None,
        **kwargs: Any,
    ) -> List[IssueQueryResult]:
        session = get_session(info.context)

        filter_instance = Filter.from_query(
            codes,
            paths,
            callables,
            statuses,
            source_names,
            source_kinds,
            sink_names,
            sink_kinds,
            features,
            min_trace_length_to_sinks,
            max_trace_length_to_sinks,
            min_trace_length_to_sources,
            max_trace_length_to_sources,
            is_new_issue,
        )

        issues = (
            Instance(session, DBID(run_id))
            .where_filter(filter_instance)
            .where_issue_instance_id_is(issue_instance_id)
            .get()
        )
        return issues

    def resolve_initial_trace_frames(
        self, info: ResolveInfo, issue_instance_id: int, kind: str
    ) -> List[TraceFrameQueryResult]:
        session = info.context.get("session")
        return trace.initial_frames(
            session, DBID(issue_instance_id), TraceKind.create_from_string(kind)
        )

    def resolve_next_trace_frames(
        self, info: ResolveInfo, issue_instance_id: int, frame_id: int, kind: str
    ) -> List[TraceFrameQueryResult]:
        session = info.context.get("session")

        trace_kind = TraceKind.create_from_string(kind)
        if trace_kind == TraceKind.POSTCONDITION:
            leaf_kind = issues.sources(session, DBID(issue_instance_id))
        elif trace_kind == TraceKind.PRECONDITION:
            leaf_kind = issues.sinks(session, DBID(issue_instance_id))

        trace_frame = session.query(TraceFrame).get(frame_id)
        if trace_frame is None:
            raise ValueError(f"`{frame_id}` is not a valid trace frame id")

        return trace.next_frames(
            session,
            trace_frame,
            # pyre-fixme[61]: `leaf_kind` may not be initialized here.
            leaf_kind,
            visited_ids=set(),
        )

    def resolve_codes(self, info: ResolveInfo) -> List[typeahead.Code]:
        session = info.context["session"]
        return typeahead.all_codes(session)

    def resolve_paths(self, info: ResolveInfo) -> List[typeahead.Path]:
        session = info.context["session"]
        return typeahead.all_paths(session)

    def resolve_callables(self, info: ResolveInfo) -> List[typeahead.Callable]:
        session = info.context["session"]
        return typeahead.all_callables(session)

    def resolve_source_names(self, info: ResolveInfo) -> List[typeahead.SourceName]:
        session = info.context["session"]
        return typeahead.all_source_names(session)

    def resolve_source_kinds(self, info: ResolveInfo) -> List[typeahead.SourceName]:
        session = info.context["session"]
        return typeahead.all_source_kinds(session)

    def resolve_sink_names(self, info: ResolveInfo) -> List[typeahead.SourceName]:
        session = info.context["session"]
        return typeahead.all_sink_names(session)

    def resolve_sink_kinds(self, info: ResolveInfo) -> List[typeahead.SourceName]:
        session = info.context["session"]
        return typeahead.all_sink_kinds(session)

    def resolve_statuses(self, info: ResolveInfo) -> List[typeahead.Status]:
        session = info.context["session"]
        return typeahead.all_statuses(session)

    def resolve_features(self, info: ResolveInfo) -> List[typeahead.Feature]:
        session = info.context["session"]
        return typeahead.all_features(session)

    def resolve_file(self, info: ResolveInfo, path: str, **kwargs: Any) -> List[File]:
        if ".." in path:
            raise FileNotFoundError("Attempted directory traversal")

        source_directory = Path(info.context.get("source_directory") or os.getcwd())
        full_path = source_directory / path
        contents = full_path.read_text()

        editor_link = None
        editor_schema = info.context.get("editor_schema")
        if editor_schema is not None:
            editor_link = f"{editor_schema}//file/{str(full_path)}"

        return [File(path=path, contents=contents, editor_link=editor_link)]

    def resolve_filters(self, info: ResolveInfo) -> List[filters_module.Filter]:
        session = info.context["session"]
        return filters_module.all_filters(session)


class SaveFilterMutation(relay.ClientIDMutation):
    node = graphene.Field(filters_module.Filter)

    class Input:
        name = graphene.String(required=True)
        description = graphene.String()
        json = graphene.String()

    def mutate_and_get_payload(
        self, info: ResolveInfo, **kwargs: Any
    ) -> "SaveFilterMutation":
        session = info.context.get("session")
        filter = filters_module.Filter(**kwargs)
        filters_module.save_filter(session, filter)
        return SaveFilterMutation(node=filter)


class DeleteFilterMutation(relay.ClientIDMutation):
    class Input:
        name = graphene.String(required=True)

    def mutate_and_get_payload(
        self, info: ResolveInfo, **kwargs: Any
    ) -> "DeleteFilterMutation":
        session = info.context.get("session")
        filters_module.delete_filter(session, kwargs["name"])
        return DeleteFilterMutation()


class DeleteRunMutation(relay.ClientIDMutation):
    class Input:
        id = graphene.ID(required=True)

    def mutate_and_get_payload(
        self, info: ResolveInfo, **kwargs: Any
    ) -> "DeleteRunMutation":
        session = info.context.get("session")
        run.delete_run(session, kwargs["id"])
        return DeleteRunMutation()


class UpdateStatusMutation(relay.ClientIDMutation):
    class Input:
        id = graphene.ID(required=True)
        status = graphene.String(required=True)

    def mutate_and_get_payload(
        self, info: ResolveInfo, **kwargs: Any
    ) -> "UpdateStatusMutation":
        session = info.context.get("session")
        update_status(session, kwargs["id"], kwargs["status"])
        return UpdateStatusMutation()


class Mutation(graphene.ObjectType):
    # pyre-fixme[4]: Attribute must be annotated.
    save_filter = SaveFilterMutation.Field()
    # pyre-fixme[4]: Attribute must be annotated.
    delete_filter = DeleteFilterMutation.Field()
    delete_run: DeleteRunMutation = DeleteRunMutation.Field()
    update_status: UpdateStatusMutation = UpdateStatusMutation.Field()


schema = graphene.Schema(query=Query, mutation=Mutation, auto_camelcase=False)
