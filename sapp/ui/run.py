# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from typing import List

import graphene
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from ..models import (
    DBID,
    IssueInstance,
    Run as RunColumn,
    RunStatus,
    TraceFrame,
    RunOrigin,
    MetaRunToRunAssoc,
)


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


def runs(session: Session) -> List[Run]:
    return (
        session.query(RunColumn.id.label("run_id"), RunColumn.date)
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
