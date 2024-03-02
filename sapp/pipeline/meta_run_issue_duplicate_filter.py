# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import logging
from typing import Tuple

import xxhash
from sqlalchemy.orm import Session

from ..db import DB
from ..models import MetaRunIssueInstanceIndex
from . import Any, Dict, DictEntries, ParseIssueTuple, PipelineStep, Summary, Union

LOG: logging.Logger = logging.getLogger("sapp")


def feature_to_string(feature: Union[str, Dict[str, Any]]) -> str:
    if isinstance(feature, str):
        return feature
    else:
        raise AssertionError(
            "Unexpected feature in `ParseIssueTuple`: expected str, got `{feature}`"
        )


def compute_issue_instance_hash(json: ParseIssueTuple) -> str:
    """Return a hash that uniquely represents the given issue instance."""
    unique_string = "$".join(
        [
            json.handle,
            json.filename,
            str(json.line),
            str(json.start),
            str(json.end),
            "|".join(sorted({kind for _, kind, _ in json.initial_sources})),
            "|".join(sorted({kind for _, kind, _ in json.final_sinks})),
            "|".join(
                sorted({str(callable) for callable, _, _ in json.initial_sources})
            ),
            "|".join(sorted({str(callable) for callable, _, _ in json.final_sinks})),
            str(
                min(distance for _, _, distance in json.initial_sources)
            ),  # minimum source distance
            str(
                min(distance for _, _, distance in json.final_sinks)
            ),  # minimum sink distance
            "|".join(sorted({feature_to_string(feature) for feature in json.features})),
        ]
    )
    hash_generator = xxhash.xxh64()
    hash_generator.update(unique_string.encode())
    return hash_generator.hexdigest()


class MetaRunIssueDuplicateFilter(PipelineStep[DictEntries, DictEntries]):
    """
    This pipeline step automatically filters out issues that already exist in the
    database, within the given metarun. This is useful for metaruns with runs on
    overlapping code, since they will find similar issues.

    A given issue instance is skipped if and only if we find an issue instance in
    the database with the same handle, filename, location, source leaves, sink
    leaves, source kinds, sink kinds, features (i.e, breadcrumbs) and minimum
    distance to sources and sinks.

    Keep in mind that despite those conditions, issue instances with slightly
    different traces could exist and will be filtered out.
    """

    def __init__(self, meta_run_identifier: int, database: DB) -> None:
        self.meta_run_identifier: int = meta_run_identifier
        self.database: DB = database

    def _should_keep_issue(self, session: Session, issue: ParseIssueTuple) -> bool:
        issue_instance_hash = compute_issue_instance_hash(issue)
        found = (
            session.query(MetaRunIssueInstanceIndex.issue_instance_id)
            .filter(MetaRunIssueInstanceIndex.meta_run_id == self.meta_run_identifier)
            .filter(
                MetaRunIssueInstanceIndex.issue_instance_hash == issue_instance_hash
            )
            .first()
        )
        return found is None

    def run(self, input: DictEntries, summary: Summary) -> Tuple[DictEntries, Summary]:
        number_initial_issues = len(input["issues"])
        LOG.info(
            "Filtering out issues that already exist in meta run %d",
            self.meta_run_identifier,
        )

        with self.database.make_session() as session:
            input["issues"] = [
                issue
                for issue in input["issues"]
                if self._should_keep_issue(session, issue)
            ]

        LOG.info(
            "Removed %d issues existing in meta run %d (out of %d issues)",
            number_initial_issues - len(input["issues"]),
            self.meta_run_identifier,
            number_initial_issues,
        )
        return input, summary
