# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from __future__ import annotations

from typing import List, Optional, Set

import graphene  # @manual=fbsource//third-party/pypi/graphene-legacy:graphene-legacy

# @manual=fbsource//third-party/pypi/graphql-core-legacy:graphql-core-legacy
from graphql.execution.base import ResolveInfo
from sqlalchemy import func
from sqlalchemy.orm import aliased, Session

from ..filter import Filter
from ..models import (
    DBID,
    Issue,
    IssueInstance,
    IssueInstanceSharedTextAssoc,
    IssueStatus,
    SharedText,
    SharedTextKind,
)
from ..queries import get_warning_message
from . import filter_predicates, run
from .query_result import IssueQueryResult, SimilarIssue

# pyre-fixme[5]: Global expression must be annotated.
FilenameText = aliased(SharedText)
# pyre-fixme[5]: Global expression must be annotated.
CallableText = aliased(SharedText)
# pyre-fixme[5]: Global expression must be annotated.
CallerText = aliased(SharedText)
# pyre-fixme[5]: Global expression must be annotated.
CalleeText = aliased(SharedText)
# pyre-fixme[5]: Global expression must be annotated.
MessageText = aliased(SharedText)
# pyre-fixme[5]: Global expression must be annotated.
FeatureText = aliased(SharedText)
# pyre-fixme[5]: Global expression must be annotated.
SourceNameText = aliased(SharedText)
# pyre-fixme[5]: Global expression must be annotated.
SourceKindText = aliased(SharedText)
# pyre-fixme[5]: Global expression must be annotated.
SinkNameText = aliased(SharedText)
# pyre-fixme[5]: Global expression must be annotated.
SinkKindText = aliased(SharedText)


class SimilarIssueResultType(graphene.ObjectType):
    issue_id = graphene.ID()
    score = graphene.Float()


class IssueQueryResultType(graphene.ObjectType):
    # pyre-fixme[13]: Attribute `concatenated_features` is never initialized.
    concatenated_features: str

    class Meta:
        interfaces = (graphene.relay.Node,)

    issue_id = graphene.ID()
    issue_instance_id = graphene.ID()
    run_id = graphene.ID()

    code = graphene.Int()
    message = graphene.String()

    callable = graphene.String()
    status = graphene.String()

    filename = graphene.String()
    location = graphene.String()

    sources = graphene.List(graphene.String)
    source_names = graphene.List(graphene.String)
    sinks = graphene.List(graphene.String)
    sink_names = graphene.List(graphene.String)
    features = graphene.List(graphene.String)

    is_new_issue = graphene.Boolean()
    detected_time = graphene.DateTime()

    min_trace_length_to_sources = graphene.Int()
    min_trace_length_to_sinks = graphene.Int()

    warning_message = graphene.String()
    similar_issues = graphene.List(SimilarIssueResultType)

    def resolve_sources(self, info: ResolveInfo) -> List[str]:
        # pyre-ignore[6]: graphene too dynamic.
        return list(sources(info.context["session"], self.issue_instance_id))

    def resolve_source_names(self, info: ResolveInfo) -> List[str]:
        # pyre-ignore[6]: graphene too dynamic.
        return list(source_names(info.context["session"], self.issue_instance_id))

    def resolve_sinks(self, info: ResolveInfo) -> List[str]:
        # pyre-ignore[6]: graphene too dynamic.
        return list(sinks(info.context["session"], self.issue_instance_id))

    def resolve_sink_names(self, info: ResolveInfo) -> List[str]:
        # pyre-ignore[6]: graphene too dynamic.
        return list(sink_names(info.context["session"], self.issue_instance_id))

    def resolve_features(self, info: ResolveInfo) -> List[str]:
        # pyre-ignore[6]: graphene too dynamic.
        return sorted(self.features)

    def resolve_warning_message(self, info: ResolveInfo) -> str:
        # pyre-ignore[6]: graphene too dynamic.
        warning_message = get_warning_message(info.context["session"], self.code)
        if warning_message:
            return warning_message.message
        return ""

    def resolve_similar_issues(self, info: ResolveInfo) -> Set[SimilarIssue]:
        # pyre-ignore[6]: graphene too dynamic.
        other_issues = Instance(info.context["session"], DBID(self.run_id)).get()

        for other_issue in other_issues:
            if (
                other_issue.issue_instance_id.resolved()
                # pyre-ignore[16]: grapehene too dynamic
                == self.issue_instance_id.resolved()
            ):
                continue
            # pyre-ignore[16]: grapehene too dynamic
            similarity = self.similarity_with(other_issue)
            if similarity.score > 0.5:
                # pyre-ignore[16]: grapehene too dynamic
                self.similar_issues.add(similarity)
        # pyre-ignore[7]: grapehene too dynamic
        return self.similar_issues


class Instance:
    def __init__(self, session: Session, run_id: Optional[DBID] = None) -> None:
        self._session: Session = session
        self._predicates: List[filter_predicates.Predicate] = []
        self._run_id: DBID = run_id or run.latest(session)

    def get(self) -> List[IssueQueryResult]:
        features = (
            self._session.query(
                IssueInstance.id.label("id"),
                func.group_concat(FeatureText.contents.distinct()).label(
                    "concatenated_features"
                ),
            )
            .join(
                IssueInstanceSharedTextAssoc,
                IssueInstanceSharedTextAssoc.issue_instance_id == IssueInstance.id,
                isouter=True,
            )
            .join(
                FeatureText,
                FeatureText.id == IssueInstanceSharedTextAssoc.shared_text_id,
                isouter=True,
            )
            .filter(FeatureText.kind == SharedTextKind.feature)
            .group_by(IssueInstance)
            .subquery()
        )
        source_names = (
            self._session.query(
                IssueInstance.id.label("id"),
                func.group_concat(SourceNameText.contents.distinct()).label(
                    "concatenated_source_names"
                ),
            )
            .join(
                IssueInstanceSharedTextAssoc,
                IssueInstanceSharedTextAssoc.issue_instance_id == IssueInstance.id,
            )
            .join(
                SourceNameText,
                SourceNameText.id == IssueInstanceSharedTextAssoc.shared_text_id,
            )
            .filter(SourceNameText.kind == SharedTextKind.source_detail)
            .group_by(IssueInstance)
            .subquery()
        )
        source_kinds = (
            self._session.query(
                IssueInstance.id.label("id"),
                func.group_concat(SourceKindText.contents.distinct()).label(
                    "concatenated_source_kinds"
                ),
            )
            .join(
                IssueInstanceSharedTextAssoc,
                IssueInstanceSharedTextAssoc.issue_instance_id == IssueInstance.id,
            )
            .join(
                SourceKindText,
                SourceKindText.id == IssueInstanceSharedTextAssoc.shared_text_id,
            )
            .filter(SourceKindText.kind == SharedTextKind.source)
            .group_by(IssueInstance)
            .subquery()
        )
        sink_names = (
            self._session.query(
                IssueInstance.id.label("id"),
                func.group_concat(SinkNameText.contents.distinct()).label(
                    "concatenated_sink_names"
                ),
            )
            .join(
                IssueInstanceSharedTextAssoc,
                IssueInstanceSharedTextAssoc.issue_instance_id == IssueInstance.id,
            )
            .join(
                SinkNameText,
                SinkNameText.id == IssueInstanceSharedTextAssoc.shared_text_id,
            )
            .filter(SinkNameText.kind == SharedTextKind.sink_detail)
            .group_by(IssueInstance)
            .subquery()
        )
        sink_kinds = (
            self._session.query(
                IssueInstance.id.label("id"),
                func.group_concat(SinkKindText.contents.distinct()).label(
                    "concatenated_sink_kinds"
                ),
            )
            .join(
                IssueInstanceSharedTextAssoc,
                IssueInstanceSharedTextAssoc.issue_instance_id == IssueInstance.id,
            )
            .join(
                SinkKindText,
                SinkKindText.id == IssueInstanceSharedTextAssoc.shared_text_id,
            )
            .filter(SinkKindText.kind == SharedTextKind.sink)
            .group_by(IssueInstance)
            .subquery()
        )

        query = (
            self._session.query(
                IssueInstance.id.label("issue_instance_id"),
                FilenameText.contents.label("filename"),
                IssueInstance.location,
                Issue.id.label("issue_id"),
                Issue.code,
                Issue.status,
                Issue.detected_time,
                CallableText.contents.label("callable"),
                MessageText.contents.label("message"),
                IssueInstance.is_new_issue,
                IssueInstance.min_trace_length_to_sources,
                IssueInstance.min_trace_length_to_sinks,
                features.c.concatenated_features,
                source_names.c.concatenated_source_names,
                source_kinds.c.concatenated_source_kinds,
                sink_names.c.concatenated_sink_names,
                sink_kinds.c.concatenated_sink_kinds,
                IssueInstance.run_id,
            )
            .filter(IssueInstance.run_id == self._run_id)
            .join(FilenameText, FilenameText.id == IssueInstance.filename_id)
            .join(CallableText, CallableText.id == IssueInstance.callable_id)
            .join(features, IssueInstance.id == features.c.id, isouter=True)
            .join(source_names, IssueInstance.id == source_names.c.id, isouter=True)
            .join(source_kinds, IssueInstance.id == source_kinds.c.id, isouter=True)
            .join(sink_names, IssueInstance.id == sink_names.c.id, isouter=True)
            .join(sink_kinds, IssueInstance.id == sink_kinds.c.id, isouter=True)
        )

        for predicate in self._predicates:
            if isinstance(predicate, filter_predicates.QueryPredicate):
                query = predicate.apply(query)

        issues = [
            IssueQueryResult.from_record(record)
            for record in query.join(Issue, IssueInstance.issue_id == Issue.id).join(
                MessageText, MessageText.id == IssueInstance.message_id
            )
        ]

        issue_predicates = [
            predicate
            for predicate in self._predicates
            if isinstance(predicate, filter_predicates.IssuePredicate)
        ]
        if len(issue_predicates) > 0:
            for issue_predicate in issue_predicates:
                issues = issue_predicate.apply(issues)
        return issues

    def where(self, *predicates: filter_predicates.Predicate) -> "Instance":
        self._predicates.extend(predicates)
        return self

    def where_issue_instance_id_is(self, issue_id: Optional[int]) -> "Instance":
        if issue_id is not None:
            self._predicates.append(
                filter_predicates.Equals(IssueInstance.id, DBID(issue_id))
            )
        return self

    def where_is_new_issue(self, is_new_issue: Optional[bool]) -> "Instance":
        if is_new_issue:
            self._predicates.append(
                filter_predicates.Equals(IssueInstance.is_new_issue, True)
            )
        return self

    def where_codes_is_any_of(self, codes: List[int]) -> "Instance":
        return self.where(filter_predicates.Like(Issue.code, codes))

    def where_callables_is_any_of(self, callables: List[str]) -> "Instance":
        return self.where(filter_predicates.Like(CallableText.contents, callables))

    def where_callables_matches(self, regex: str) -> "Instance":
        return self.where(filter_predicates.Matches(regex, "callable"))

    def where_status_is_any_of(self, statuses: List[str]) -> "Instance":
        return self.where(filter_predicates.Like(Issue.status, statuses))

    def where_path_is_any_of(self, paths: List[str]) -> "Instance":
        return self.where(filter_predicates.Like(FilenameText.contents, paths))

    def where_source_name_is_any_of(self, source_names: List[str]) -> "Instance":
        return self.where(filter_predicates.HasAny(set(source_names), "source_names"))

    def where_source_name_matches(self, regex: str) -> "Instance":
        return self.where(filter_predicates.Matches(regex, "source_names"))

    def where_source_kind_is_any_of(self, source_kinds: List[str]) -> "Instance":
        return self.where(filter_predicates.HasAny(set(source_kinds), "source_kinds"))

    def where_source_kind_matches(self, regex: str) -> "Instance":
        return self.where(filter_predicates.Matches(regex, "source_kinds"))

    def where_sink_name_is_any_of(self, sink_names: List[str]) -> "Instance":
        return self.where(filter_predicates.HasAny(set(sink_names), "sink_names"))

    def where_sink_name_matches(self, regex: str) -> "Instance":
        return self.where(filter_predicates.Matches(regex, "sink_names"))

    def where_sink_kind_is_any_of(self, sink_kinds: List[str]) -> "Instance":
        return self.where(filter_predicates.HasAny(set(sink_kinds), "sink_kinds"))

    def where_sink_kind_matches(self, regex: str) -> "Instance":
        return self.where(filter_predicates.Matches(regex, "sink_kinds"))

    def where_trace_length_to_sinks(
        self, minimum: Optional[int] = None, maximum: Optional[int] = None
    ) -> "Instance":
        return self.where(
            filter_predicates.InRange(
                IssueInstance.min_trace_length_to_sinks, lower=minimum, upper=maximum
            )
        )

    def where_filter(self, filter_instance: Filter) -> "Instance":
        traceLengthToSinks = filter_instance.traceLengthToSinks
        min_trace_length_to_sinks: Optional[int] = None
        if traceLengthToSinks is not None:
            min_trace_length_to_sinks = traceLengthToSinks[0]

        max_trace_length_to_sinks: Optional[int] = None
        if traceLengthToSinks is not None:
            max_trace_length_to_sinks = traceLengthToSinks[1]

        traceLengthFromSources = filter_instance.traceLengthFromSources
        min_trace_length_to_sources: Optional[int] = None
        if traceLengthFromSources is not None:
            min_trace_length_to_sources = traceLengthFromSources[0]

        max_trace_length_to_sources: Optional[int] = None
        if traceLengthFromSources is not None:
            max_trace_length_to_sources = traceLengthFromSources[1]

        builder = (
            self.where_codes_is_any_of(filter_instance.codes)
            .where_path_is_any_of(filter_instance.paths)
            .where_trace_length_to_sinks(
                min_trace_length_to_sinks, max_trace_length_to_sinks
            )
            .where_trace_length_to_sources(
                min_trace_length_to_sources, max_trace_length_to_sources
            )
            .where_is_new_issue(filter_instance.is_new_issue)
            .where_status_is_any_of(filter_instance.statuses)
        )

        if filter_instance.callables:
            if not isinstance(filter_instance.callables, List):
                if filter_instance.callables.get("operation") == "matches":
                    builder = builder.where_callables_matches(
                        filter_instance.callables.get("value", [""])[0]
                    )
                elif filter_instance.callables.get("operation") == "is":
                    if any(filter_instance.callables.get("value", [])):
                        builder = builder.where_callables_is_any_of(
                            filter_instance.callables.get("value", [""])
                        )
                else:
                    raise ValueError(
                        """Invalid value supplied for callables parameter
                        `operation`. The supported values are `is` and
                        `matches`."""
                    )
            else:
                # Backward compatibility
                builder = builder.where_callables_is_any_of(filter_instance.callables)

        if filter_instance.source_names:
            if not isinstance(filter_instance.source_names, list):
                if filter_instance.source_names.get("operation") == "matches":
                    builder = builder.where_source_name_matches(
                        filter_instance.source_names.get("value", [""])[0]
                    )
                elif filter_instance.source_names.get("operation") == "is":
                    if any(filter_instance.source_names.get("value", [])):
                        builder = builder.where_source_name_is_any_of(
                            filter_instance.source_names.get("value", [""])
                        )
                else:
                    raise ValueError(
                        """Invalid value supplied for source_names parameter
                        `operation`. The supported values are `is` and
                        `matches`."""
                    )
            else:
                # Backward compatibility
                builder = builder.where_source_name_is_any_of(
                    filter_instance.source_names
                )

        if filter_instance.source_kinds:
            if not isinstance(filter_instance.source_kinds, list):
                if filter_instance.source_kinds.get("operation") == "matches":
                    builder = builder.where_source_kind_matches(
                        filter_instance.source_kinds.get("value", [""])[0]
                    )
                elif filter_instance.source_kinds.get("operation") == "is":
                    if any(filter_instance.source_kinds.get("value", [])):
                        builder = builder.where_source_kind_is_any_of(
                            filter_instance.source_kinds.get("value", [""])
                        )
                else:
                    raise ValueError(
                        """Invalid value supplied for source_kinds parameter
                        `operation`. The supported values are `is` and
                        `matches`."""
                    )
            else:
                # Backward compatibility
                builder = builder.where_source_kind_is_any_of(
                    filter_instance.source_kinds
                )

        if filter_instance.sink_names:
            if not isinstance(filter_instance.sink_names, list):
                if filter_instance.sink_names.get("operation") == "matches":
                    builder = builder.where_sink_name_matches(
                        filter_instance.sink_names.get("value", [""])[0]
                    )
                elif filter_instance.sink_names.get("operation") == "is":
                    if any(filter_instance.sink_names.get("value", [])):
                        builder = builder.where_sink_name_is_any_of(
                            filter_instance.sink_names.get("value", [""])
                        )
                else:
                    raise ValueError(
                        """Invalid value supplied for sink_names parameter
                        `operation`. The supported values are `is` and
                        `matches`."""
                    )
            else:
                # Backward compatibility
                builder = builder.where_sink_name_is_any_of(filter_instance.sink_names)

        if filter_instance.sink_kinds:
            if not isinstance(filter_instance.sink_kinds, list):
                if filter_instance.sink_kinds.get("operation") == "matches":
                    builder = builder.where_sink_kind_matches(
                        filter_instance.sink_kinds.get("value", [""])[0]
                    )
                elif filter_instance.sink_kinds.get("operation") == "is":
                    if any(filter_instance.sink_kinds.get("value", [])):
                        builder = builder.where_sink_kind_is_any_of(
                            filter_instance.sink_kinds.get("value", [""])
                        )
                else:
                    raise ValueError(
                        """Invalid value supplied for sink_kinds parameter
                        `operation`. The supported values are `is` and
                        `matches`."""
                    )
            else:
                # Backward compatibility if the filter is of the form List[str]
                builder = builder.where_sink_kind_is_any_of(filter_instance.sink_kinds)

        for feature in filter_instance.format_features_for_query() or []:
            if feature[0] == "any of":
                builder = builder.where_any_features(feature[1])
            if feature[0] == "all of":
                builder = builder.where_all_features(feature[1])
            if feature[0] == "none of":
                builder = builder.where_exclude_features(feature[1])

        return builder

    def where_trace_length_to_sources(
        self, minimum: Optional[int] = None, maximum: Optional[int] = None
    ) -> "Instance":
        return self.where(
            filter_predicates.InRange(
                IssueInstance.min_trace_length_to_sources, lower=minimum, upper=maximum
            )
        )

    def where_any_features(self, features: List[str]) -> "Instance":
        return self.where(filter_predicates.HasAny(set(features), "features"))

    def where_all_features(self, features: List[str]) -> "Instance":
        return self.where(filter_predicates.HasAll(set(features)))

    def where_exclude_features(self, features: List[str]) -> "Instance":
        return self.where(filter_predicates.HasNone(set(features)))


def sources(session: Session, issue_id: DBID) -> Set[str]:
    return _get_leaves(session, issue_id, SharedTextKind.source)


def source_names(session: Session, issue_id: DBID) -> Set[str]:
    return _get_leaves(session, issue_id, SharedTextKind.source_detail)


def sinks(session: Session, issue_id: DBID) -> Set[str]:
    return _get_leaves(session, issue_id, SharedTextKind.sink)


def sink_names(session: Session, issue_id: DBID) -> Set[str]:
    return _get_leaves(session, issue_id, SharedTextKind.sink_detail)


def features(session: Session, issue_id: DBID) -> Set[str]:
    return _get_leaves(session, issue_id, SharedTextKind.feature)


def _get_leaves(
    session: Session, issue_instance_id: DBID, kind: SharedTextKind
) -> Set[str]:
    message_ids = [
        int(id)
        for (id,) in session.query(SharedText.id)
        .distinct(SharedText.id)
        .join(
            IssueInstanceSharedTextAssoc,
            SharedText.id == IssueInstanceSharedTextAssoc.shared_text_id,
        )
        .filter(IssueInstanceSharedTextAssoc.issue_instance_id == issue_instance_id)
        .filter(SharedText.kind == kind)
    ]

    leaf_lookup = {
        int(id): contents
        for id, contents in session.query(SharedText.id, SharedText.contents).filter(
            SharedText.kind == kind
        )
    }
    return {leaf_lookup[id] for id in message_ids if id in leaf_lookup}


def update_status(session: Session, id: str, status: str) -> None:
    status_enums = {
        "bad_practice": IssueStatus.bad_practice,
        "false_positive": IssueStatus.false_positive,
        "valid_bug": IssueStatus.valid_bug,
        "do_not_care": IssueStatus.do_not_care,
        "uncategorized": IssueStatus.uncategorized,
    }
    session.query(Issue).filter(Issue.id == id).update({"status": status_enums[status]})
    session.commit()
