# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from typing import List

import graphene
from sqlalchemy.orm import Session
from sqlalchemy.sql import func, distinct

from ..models import DBID, IssueInstance, Issue, IssueStatus, MetaRunToRunAssoc
from ..models import Run as RunColumn
from ..models import RunOrigin, RunStatus, TraceFrame


def latest(session: Session) -> DBID:
    return DBID(
        (
            session.query(func.max(RunColumn.id))
            .filter(RunColumn.status == RunStatus.FINISHED)
            .scalar()
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
        session.query(
            RunColumn.id.label("run_id"),
            func.count(distinct(IssueInstance.id)).label("count"),
        )
        .group_by(IssueInstance.run_id)
        .join(IssueInstance, IssueInstance.run_id == RunColumn.id)
        .join(Issue, Issue.id == IssueInstance.issue_id)
        .filter(Issue.status != IssueStatus.UNCATEGORIZED)
        .subquery()
    )
    return (
        session.query(
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
        .all()
    )


class EmptyDeletionError(Exception):
    pass


def delete_run(session: Session, id: str) -> None:
    deleted_run_rows = session.query(RunColumn).filter(RunColumn.id == id).delete()
    if deleted_run_rows == 0:
        raise EmptyDeletionError(f'No run with `id` "{id}" exists.')
    session.query(IssueInstance).filter(IssueInstance.run_id == id).delete()
    session.query(TraceFrame).filter(TraceFrame.run_id == id).delete()
    session.query(RunOrigin).filter(RunOrigin.run_id == id).delete()
    session.query(MetaRunToRunAssoc).filter(MetaRunToRunAssoc.run_id == id).delete()
    session.commit()
