# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import (
    TYPE_CHECKING,
    Generic,
    List,
    Optional,
    Pattern,
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


class Matches(IssuePredicate):
    def __init__(self, regex: str, parameter_name: str) -> None:
        self._regex: Pattern[str] = re.compile(regex)
        self._parameter_name = parameter_name

    def attribute_set(self, issue: IssueQueryResult) -> Set[str]:
        attribute = issue._asdict()[self._parameter_name]
        if isinstance(attribute, str):
            return {attribute}
        return set(attribute)

    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        return [
            issue
            for issue in issues
            if any(map(self._regex.match, self.attribute_set(issue)))
        ]


class HasAny(IssuePredicate):
    def __init__(self, parameter_list: Set[str], parameter_name: str) -> None:
        self._parameter_list = parameter_list
        self._parameter_name = parameter_name

    def attribute_set(self, issue: IssueQueryResult) -> Set[str]:
        attribute = issue._asdict()[self._parameter_name]
        if isinstance(attribute, str):
            return {attribute}
        return set(attribute)

    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        return [
            issue
            for issue in issues
            if not self.attribute_set(issue).isdisjoint(self._parameter_list)
        ]


class HasNone(IssuePredicate):
    def __init__(self, features: Set[str]) -> None:
        self._features = features

    def apply(self, issues: List[IssueQueryResult]) -> List[IssueQueryResult]:
        return [issue for issue in issues if len(issue.features & self._features) == 0]
