#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict
from typing import Any, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from .decorators import UserError
from .models import (
    DBID,
    IssueInstance,
    IssueInstanceSharedTextAssoc,
    Run,
    RunStatus,
    SharedText,
    SharedTextKind,
    WarningMessage,
)


def get_warning_message_range(
    session: Session, startingCode: int, endingCode: int
) -> List[WarningMessage]:
    return (
        session.execute(
            select(WarningMessage)
            .where(WarningMessage.code >= startingCode)
            .where(WarningMessage.code < endingCode)
        )
        .scalars()
        .all()
    )


def get_warning_message(
    session: Session,
    code: int,
) -> Optional[WarningMessage]:
    return (
        session.execute(select(WarningMessage).where(WarningMessage.code == code))
        .scalars()
        .one_or_none()
    )


def latest_run_id(
    session: Session,
) -> DBID:
    return session.scalar(
        select(func.max(Run.id)).where(Run.status == RunStatus.finished)
    )


def _leaf_detail_kind(kind: str) -> SharedTextKind:
    """
    Convert a raw kind (source|sink|feature) into a SharedTextKind,
    converting source and sink into detail kinds.
    """
    text_kind = SharedTextKind.from_string(kind)
    if text_kind is None:
        raise UserError(f"Invalid kind {kind}")
    if text_kind == SharedTextKind.source:
        text_kind = SharedTextKind.source_detail
    elif text_kind == SharedTextKind.sink:
        text_kind = SharedTextKind.sink_detail
    return text_kind


def leaves(
    session: Session,
    kind: str,
    run_id: DBID,
) -> List[Any]:
    text_kind = _leaf_detail_kind(kind)
    return session.execute(
        select(IssueInstanceSharedTextAssoc.shared_text_id, SharedText.contents)
        .join(
            SharedText,
            IssueInstanceSharedTextAssoc.shared_text_id == SharedText.id,
        )
        .join(
            IssueInstance,
            IssueInstanceSharedTextAssoc.issue_instance_id == IssueInstance.id,
        )
        .filter(IssueInstance.run_id == run_id)
        .filter(SharedText.kind == text_kind)
    ).all()
