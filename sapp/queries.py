#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from sqlalchemy.orm import Session, Query

from .decorators import UserError
from .models import (
    DBID,
    IssueInstance,
    IssueInstanceSharedTextAssoc,
    SharedText,
    SharedTextKind,
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
) -> Query:
    text_kind = _leaf_detail_kind(kind)
    return (
        session.query(IssueInstanceSharedTextAssoc.shared_text_id, SharedText.contents)
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
    )
