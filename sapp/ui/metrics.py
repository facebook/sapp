# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from __future__ import annotations

from typing import List, NamedTuple, Set, Tuple

import graphene
from sqlalchemy.orm import Session

from ..models import DBID, TraceKind
from .issues import IssueQueryResult
from .trace import TraceFrameQueryResult, initial_frames


class MetricsQueryResultType(graphene.ObjectType):
    warning_codes_and_statuses = graphene.List(graphene.List(graphene.String))
    files_count = graphene.List(graphene.List(graphene.String))

    triaged_count = graphene.Int()
    issues_count = graphene.Int()

    common_features = graphene.List(graphene.String)
    common_callables = graphene.List(graphene.String)
    common_callables_in_traces = graphene.List(graphene.String)


class MetricsQueryResult(NamedTuple):
    warning_codes_and_statuses: Set[Tuple[str]]
    files_count: Set[Tuple[str]]

    common_features: Set[str]
    common_callables: Set[str]
    common_callables_in_traces: Set[str]

    triaged_count: int
    issues_count: int

    @staticmethod
    def from_issues(
        session: Session, issues: List[IssueQueryResult]
    ) -> MetricsQueryResult:
        warning_codes_and_statuses = dict()
        files_count = dict()

        triaged_count: int = 0
        issues_count: int = len(issues)

        common_features = set()
        common_callables = set()
        common_callables_in_traces = set()
        if any(issues):
            common_features.update(issues[0].features)
            common_callables.add(issues[0].callable)

        traces: List[TraceFrameQueryResult] = []

        for issue in issues:
            # Each issue has only one callable, so either, all callables are common
            # or none
            if any(common_callables) and issue.callable not in common_callables:
                common_callables = set()

            common_features = common_features.intersection(set(issue.features))

            if issue.status != "Uncategorized":
                triaged_count += 1

            if issue.code not in warning_codes_and_statuses.keys():
                warning_codes_and_statuses[issue.code] = {}

            if issue.status not in warning_codes_and_statuses[issue.code].keys():
                warning_codes_and_statuses[issue.code][issue.status] = 1
            else:
                warning_codes_and_statuses[issue.code][issue.status] += 1

            traces = (
                traces
                + initial_frames(
                    session,
                    DBID(issue.issue_instance_id),
                    TraceKind.create_from_string("postcondition"),
                )
                + initial_frames(
                    session,
                    DBID(issue.issue_instance_id),
                    TraceKind.create_from_string("precondition"),
                )
            )

        if any(traces):
            common_callables_in_traces.add(traces[0].caller)

        for trace in traces:
            if (
                any(common_callables_in_traces)
                and trace.caller not in common_callables_in_traces
            ):
                common_callables_in_traces = set()

            if trace.filename in files_count.keys():
                files_count[trace.filename] += 1
            else:
                files_count[trace.filename] = 1

        warning_codes_and_statuses_set = set()
        for code in warning_codes_and_statuses.keys():
            for status in warning_codes_and_statuses[code]:
                warning_codes_and_statuses_set.add(
                    (code, status, warning_codes_and_statuses[code][status])
                )

        files_count_set = set()
        for key in files_count.keys():
            files_count_set.add((key, files_count[key]))

        return MetricsQueryResult(
            warning_codes_and_statuses=warning_codes_and_statuses_set,
            common_features=common_features,
            common_callables=common_callables,
            common_callables_in_traces=common_callables_in_traces,
            triaged_count=triaged_count,
            issues_count=issues_count,
            files_count=files_count_set,
        )
