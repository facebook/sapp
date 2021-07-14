# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import (
    TYPE_CHECKING,
    Generic,
    List,
    Optional,
    Sequence,
    Set,
    TypeVar,
    Union,
)

from sqlalchemy import Column
from sqlalchemy.orm.query import Query
from sqlalchemy.sql.expression import or_
from typing_extensions import Final

from ..models import DBID

if TYPE_CHECKING:
    from .issues import IssueQueryResult  # noqa

_Q = TypeVar("_Q")
_T = TypeVar("_T")


class Predicate(ABC):
    pass


class QueryPredicate(Predicate):
    @abstractmethod
    def apply(self, query: Query[_Q]) -> Query[_Q]:
        ...


class InRange(Generic[_T], QueryPredicate):
    def __init__(
        self,
        column: Union[Column[_T], DBID],
        *,
        lower: Optional[_T] = None,
        upper: Optional[_T] = None,
    ) -> None:
        self._column = column
        self._lower: Final[Optional[_T]] = lower
        self._upper: Final[Optional[_T]] = upper

    def apply(self, query: Query[_Q]) -> Query[_Q]:
        if self._lower is not None:
            query = query.filter(self._column >= self._lower)
        if self._upper is not None:
            query = query.filter(self._column <= self._upper)
        return query


class Equals(Generic[_T], QueryPredicate):
    def __init__(self, column: Union[Column[_T], DBID], to: _T) -> None:
        self._column = column
        self._to: Final[Optional[_T]] = to

    def apply(self, query: Query[_Q]) -> Query[_Q]:
        return query.filter(self._column == self._to)


class IsNull(Generic[_T], QueryPredicate):
    def __init__(self, column: Union[Column[_T], DBID]) -> None:
        self._column = column

    def apply(self, query: Query[_Q]) -> Query[_Q]:
        return query.filter(self._column is None)


class Like(Generic[_T], QueryPredicate):
    def __init__(self, column: Union[Column[_T], DBID], items: Sequence[_T]) -> None:
        self._column = column
        self._items = items

    def apply(self, query: Query[_Q]) -> Query[_Q]:
        # pyre-ignore: SQLAlchemy too dynamic.
        return query.filter(or_(*[self._column.like(item) for item in self._items]))


class IssuePredicate(Predicate):
    @abstractmethod
    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        ...


class HasAll(IssuePredicate):
    def __init__(self, features: Set[str]) -> None:
        self._features = features

    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        return [
            issue
            for issue in issues
            if issue.features & self._features == self._features
        ]


class HasAny(IssuePredicate):
    def __init__(
        self, parameter_list: Set[str], parameter_type: str = "features"
    ) -> None:
        self._parameter_list = parameter_list
        self._parameter_type = parameter_type

    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        if self._parameter_type == "features":
            return [
                issue
                for issue in issues
                if len(issue.features & self._parameter_list) > 0
            ]
        elif self._parameter_type == "source_names":
            return [
                issue
                for issue in issues
                if len(issue.source_names & self._parameter_list) > 0
            ]
        elif self._parameter_type == "source_kinds":
            return [
                issue
                for issue in issues
                if len(issue.source_kinds & self._parameter_list) > 0
            ]
        elif self._parameter_type == "sink_names":
            return [
                issue
                for issue in issues
                if len(issue.sink_names & self._parameter_list) > 0
            ]
        elif self._parameter_type == "sink_kinds":
            return [
                issue
                for issue in issues
                if len(issue.sink_kinds & self._parameter_list) > 0
            ]
        else:
            return issues


class HasNone(IssuePredicate):
    def __init__(self, features: Set[str]) -> None:
        self._features = features

    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        return [issue for issue in issues if len(issue.features & self._features) == 0]
