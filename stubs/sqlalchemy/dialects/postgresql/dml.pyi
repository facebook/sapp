from typing import Any, Optional

from ...sql.dml import Insert as _StandardInsert
from ...sql.elements import ClauseElement

class Insert(_StandardInsert):
    def excluded(self): ...
    def on_conflict_do_update(
        self,
        constraint: Optional[Any] = ...,
        index_elements: Optional[Any] = ...,
        index_where: Optional[Any] = ...,
        set_: Optional[Any] = ...,
        where: Optional[Any] = ...,
    ): ...
    def on_conflict_do_nothing(
        self,
        constraint: Optional[Any] = ...,
        index_elements: Optional[Any] = ...,
        index_where: Optional[Any] = ...,
    ): ...

insert: Any

class OnConflictClause(ClauseElement):
    constraint_target: Any = ...
    inferred_target_elements: Any = ...
    inferred_target_whereclause: Any = ...
    def __init__(
        self,
        constraint: Optional[Any] = ...,
        index_elements: Optional[Any] = ...,
        index_where: Optional[Any] = ...,
    ) -> None: ...

class OnConflictDoNothing(OnConflictClause):
    __visit_name__: str = ...

class OnConflictDoUpdate(OnConflictClause):
    __visit_name__: str = ...
    update_values_to_set: Any = ...
    update_whereclause: Any = ...
    def __init__(
        self,
        constraint: Optional[Any] = ...,
        index_elements: Optional[Any] = ...,
        index_where: Optional[Any] = ...,
        set_: Optional[Any] = ...,
        where: Optional[Any] = ...,
    ) -> None: ...
