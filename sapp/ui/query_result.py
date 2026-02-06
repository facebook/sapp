# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import datetime
from typing import Any, Dict, FrozenSet, List, NamedTuple, Set, Union

from ..models import DBID, SourceLocation


class SimilarIssue(NamedTuple):
    issue_id: DBID
    score: float


class IssueQueryResult(NamedTuple):
    issue_id: DBID
    issue_instance_id: DBID
    run_id: DBID

    code: int
    message: str

    callable: str
    status: str

    filename: str
    location: SourceLocation

    is_new_issue: bool
    detected_time: datetime.datetime

    min_trace_length_to_sources: int
    min_trace_length_to_sinks: int

    features: FrozenSet[str]

    source_names: FrozenSet[str]
    source_kinds: FrozenSet[str]
    sink_names: FrozenSet[str]
    sink_kinds: FrozenSet[str]

    similar_issues: Set[SimilarIssue]

    @staticmethod
    def from_record(record: Any) -> "IssueQueryResult":
        return IssueQueryResult(
            issue_id=record.issue_id,
            issue_instance_id=record.issue_instance_id,
            code=record.code,
            message=record.message,
            callable=record.callable,
            status=record.status.name.replace("_", " ").capitalize(),
            detected_time=datetime.datetime.fromtimestamp(record.detected_time),
            filename=record.filename,
            location=record.location,
            is_new_issue=record.is_new_issue,
            min_trace_length_to_sources=record.min_trace_length_to_sources,
            min_trace_length_to_sinks=record.min_trace_length_to_sinks,
            features=(
                frozenset(record.concatenated_features.split(","))
                if record.concatenated_features
                else frozenset()
            ),
            source_names=(
                frozenset(record.concatenated_source_names.split(","))
                if record.concatenated_source_names
                else frozenset()
            ),
            source_kinds=(
                frozenset(record.concatenated_source_kinds.split(","))
                if record.concatenated_source_kinds
                else frozenset()
            ),
            sink_names=(
                frozenset(record.concatenated_sink_names.split(","))
                if record.concatenated_sink_names
                else frozenset()
            ),
            sink_kinds=(
                frozenset(record.concatenated_sink_kinds.split(","))
                if record.concatenated_sink_kinds
                else frozenset()
            ),
            similar_issues=set(),
            run_id=record.run_id,
        )

    def to_json(
        self,
    ) -> Dict[str, Union[List[Dict[str, Any]], str, int, List[str], bool, None]]:
        return {
            "issue_id": self.issue_id.resolved(),
            "filename": self.filename,
            "line": self.location.line_no,
            "begin_column": self.location.begin_column,
            "end_column": self.location.end_column,
            "code": self.code,
            "message": self.message,
            "callable": self.callable,
            "status": self.status,
            "source_names": list(self.source_names),
            "source_kinds": list(self.source_kinds),
            "sink_names": list(self.sink_names),
            "sink_kinds": list(self.sink_kinds),
            "min_trace_length_to_sources": self.min_trace_length_to_sources,
            "min_trace_length_to_sinks": self.min_trace_length_to_sinks,
            "features": list(self.features),
            "is_new_issue": self.is_new_issue,
            "detected_time": self.detected_time.isoformat(),
            "run_id": self.run_id.resolved(),
            "similar_issues": [
                similar_issue.__dict__ for similar_issue in self.similar_issues
            ],
        }

    def __hash__(self) -> int:
        return hash(
            (
                self.issue_id.resolved(),
                self.issue_instance_id.resolved(),
                self.run_id.resolved(),
                self.code,
                self.message,
                self.callable,
                self.status,
                self.source_names,
                self.source_kinds,
                self.sink_names,
                self.sink_kinds,
                self.filename,
                self.location,
                self.is_new_issue,
                self.detected_time,
                self.min_trace_length_to_sinks,
                self.min_trace_length_to_sources,
                self.features,
                frozenset(self.similar_issues),
            )
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return (
            self.issue_id.resolved() == other.issue_id.resolved()
            and self.issue_instance_id.resolved() == other.issue_instance_id.resolved()
            and self.run_id.resolved() == other.run_id.resolved()
            and self.code == other.code
            and self.status == other.status
            and self.message == other.message
            and self.callable == other.callable
            and self.source_names == other.source_names
            and self.source_kinds == other.source_kinds
            and self.sink_names == other.sink_names
            and self.sink_kinds == other.sink_kinds
            and self.filename == other.filename
            and self.location == other.location
            and self.is_new_issue == other.is_new_issue
            and self.detected_time == other.detected_time
            and self.min_trace_length_to_sinks == other.min_trace_length_to_sinks
            and self.min_trace_length_to_sources == other.min_trace_length_to_sources
            and self.features == other.features
            and self.similar_issues == other.similar_issues
        )

    def similarity_with(self, other: object) -> SimilarIssue:
        if not isinstance(other, type(self)):
            raise NotImplementedError
        score: float = 0.0
        score += 1 if self.source_names == other.source_names else 0
        score += 1 if self.sink_names == other.sink_names else 0
        score += 1 if self.code == other.code else 0
        score += 1 if self.callable == other.callable else 0
        score += 2 * len(self.sink_kinds.intersection(other.sink_kinds))
        score += 2 * len(self.source_kinds.intersection(other.source_kinds))
        score = score / (
            4
            + len(self.sink_kinds)
            + len(other.sink_kinds)
            + len(self.source_kinds)
            + len(other.source_kinds)
        )
        return SimilarIssue(issue_id=other.issue_id, score=score)
