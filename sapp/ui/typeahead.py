# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from __future__ import annotations

from typing import List

import graphene
from sqlalchemy.orm import Session

from ..models import Issue, IssueInstance, SharedText, SharedTextKind


class Code(graphene.ObjectType):
    code = graphene.Int()


def all_codes(session: Session) -> List[Code]:
    return session.query(Issue.code.distinct().label("code")).all()


class Path(graphene.ObjectType):
    path = graphene.String()


def all_paths(session: Session) -> List[Path]:
    return (
        # pyre-fixme[16]: `str` has no attribute `label`.
        session.query(IssueInstance, SharedText.contents.label("path"))
        .join(SharedText, SharedText.id == IssueInstance.filename_id)
        .group_by(SharedText)
        .all()
    )


class SourceName(graphene.ObjectType):
    source_name = graphene.String()


def all_source_names(session: Session) -> List[SourceName]:
    return (
        # pyre-fixme[16]: `str` has no attribute `label`
        session.query(IssueInstance, SharedText.contents.label("source_name"))
        .join(SharedText, SharedText.kind == SharedTextKind.SOURCE_DETAIL)
        .group_by(SharedText)
        .all()
    )


class SourceKind(graphene.ObjectType):
    source_kind = graphene.String()


def all_source_kinds(session: Session) -> List[SourceName]:
    return (
        # pyre-fixme[16]: `str` has no attribute `label`
        session.query(IssueInstance, SharedText.contents.label("source_kind"))
        .join(SharedText, SharedText.kind == SharedTextKind.SOURCE)
        .group_by(SharedText)
        .all()
    )


class SinkName(graphene.ObjectType):
    sink_name = graphene.String()


def all_sink_names(session: Session) -> List[SourceName]:
    return (
        # pyre-fixme[16]: `str` has no attribute `label`
        session.query(IssueInstance, SharedText.contents.label("sink_name"))
        .join(SharedText, SharedText.kind == SharedTextKind.SINK_DETAIL)
        .group_by(SharedText)
        .all()
    )


class SinkKind(graphene.ObjectType):
    sink_kind = graphene.String()


def all_sink_kinds(session: Session) -> List[SourceName]:
    return (
        # pyre-fixme[16]: `str` has no attribute `label`
        session.query(IssueInstance, SharedText.contents.label("sink_kind"))
        .join(SharedText, SharedText.kind == SharedTextKind.SINK)
        .group_by(SharedText)
        .all()
    )


class Status(graphene.ObjectType):
    status = graphene.String()


def all_statuses(session: Session) -> List[Status]:
    return session.query(Issue.status.distinct().label("status")).all()


class Callable(graphene.ObjectType):
    callable = graphene.String()


def all_callables(session: Session) -> List[Callable]:
    return (
        # pyre-fixme[16]: `str` has no attribute `label`.
        session.query(IssueInstance, SharedText.contents.label("callable"))
        .join(SharedText, SharedText.id == IssueInstance.callable_id)
        .group_by(SharedText)
        .all()
    )


class Feature(graphene.ObjectType):
    feature = graphene.String()


def all_features(session: Session) -> List[Feature]:
    return (
        # pyre-fixme[16]: `str` has no attribute `label`.
        session.query(SharedText, SharedText.contents.label("feature"))
        .filter(SharedText.kind == SharedTextKind.FEATURE)
        .all()
    )
