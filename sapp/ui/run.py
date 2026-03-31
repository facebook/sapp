# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from typing import List

import graphene  # @manual=fbsource//third-party/pypi/graphene-legacy:graphene-legacy
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from sqlalchemy.sql import distinct, func

from ..models import (
    DBID,
    Issue,
    IssueInstance,
    IssueStatus,
    MetaRunToRunAssoc,
    Run as RunColumn,
    RunOrigin,
    RunStatus,
    TraceFrame,
)


def latest(session: Session) -> DBID:
    return DBID(
        session.scalar(
            select(func.max(RunColumn.id)).where(RunColumn.status == RunStatus.finished)
        )
    )


class Run(graphene.ObjectType):
    run_id = graphene.ID()
    date = graphene.String()
    commit_hash = graphene.String()
    num_issues = graphene.Int()
    triaged_issues = graphene.Int()


def runs(session: Session) -> List[Run]:
    triaged_issues = (
        select(
            RunColumn.id.label("run_id"),
            func.count(distinct(IssueInstance.id)).label("count"),
        )
        .group_by(IssueInstance.run_id)
        .join(IssueInstance, IssueInstance.run_id == RunColumn.id)
        .join(Issue, Issue.id == IssueInstance.issue_id)
        .filter(Issue.status != IssueStatus.uncategorized)
        .subquery()
    )
    return session.execute(
        select(
            RunColumn.id.label("run_id"),
            RunColumn.date,
            RunColumn.commit_hash,
            func.count(distinct(IssueInstance.id)).label("num_issues"),
            triaged_issues.c.count.label("triaged_issues"),
        )
        .group_by(RunColumn)
        .join(IssueInstance, IssueInstance.run_id == RunColumn.id, isouter=True)
        .join(triaged_issues, triaged_issues.c.run_id == RunColumn.id, isouter=True)
        .filter(RunColumn.status == "finished")
        .order_by(RunColumn.id.desc())
    ).all()


class EmptyDeletionError(Exception):
    pass


def delete_run(session: Session, id: str) -> None:
    result = session.execute(delete(RunColumn).where(RunColumn.id == id))
    if result.rowcount == 0:
        raise EmptyDeletionError(f'No run with `id` "{id}" exists.')
    session.execute(delete(IssueInstance).where(IssueInstance.run_id == id))
    session.execute(delete(TraceFrame).where(TraceFrame.run_id == id))
    session.execute(delete(RunOrigin).where(RunOrigin.run_id == id))
    session.execute(delete(MetaRunToRunAssoc).where(MetaRunToRunAssoc.run_id == id))
    session.commit()
