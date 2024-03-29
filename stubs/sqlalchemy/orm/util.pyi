from typing import Any, Optional, Text

from ..sql import expression
from ..sql import util as sql_util
from ..sql.selectable import FromClause
from .base import InspectionAttr as InspectionAttr
from .base import object_mapper as object_mapper

all_cascades: Any = ...

class CascadeOptions(frozenset):
    save_update: Any = ...
    delete: Any = ...
    refresh_expire: Any = ...
    merge: Any = ...
    expunge: Any = ...
    delete_orphan: Any = ...
    def __new__(cls, value_list): ...
    @classmethod
    def from_string(cls, arg): ...

def polymorphic_union(
    table_map, typecolname, aliasname: str = ..., cast_nulls: bool = ...
): ...
def identity_key(*args, **kwargs): ...

class ORMAdapter(sql_util.ColumnAdapter):
    mapper: Any = ...
    aliased_class: Any = ...
    def __init__(
        self,
        entity,
        equivalents: Optional[Any] = ...,
        adapt_required: bool = ...,
        chain_to: Optional[Any] = ...,
        allow_label_resolve: bool = ...,
        anonymize_labels: bool = ...,
    ) -> None: ...

class AliasedClass(object):
    __name__: Any = ...
    def __init__(
        self,
        cls: Any,
        alias: Optional[FromClause] = ...,
        name: Optional[Text] = ...,
        flat: bool = ...,
        adapt_on_names: bool = ...,
        with_polymorphic_mappers: Any = ...,
        with_polymorphic_discriminator: Optional[Any] = ...,
        base_alias: Optional[Any] = ...,
        use_mapper_path: bool = ...,
    ) -> None: ...
    def __getattr__(self, key): ...

class AliasedInsp(InspectionAttr):
    entity: Any = ...
    mapper: Any = ...
    selectable: Any = ...
    name: str = ...
    with_polymorphic_mappers: Any = ...
    polymorphic_on: Any = ...
    def __init__(
        self,
        entity,
        mapper,
        selectable,
        name,
        with_polymorphic_mappers,
        polymorphic_on,
        _base_alias,
        _use_mapper_path,
        adapt_on_names,
    ) -> None: ...
    is_aliased_class: bool = ...
    @property
    def class_(self): ...

def aliased(
    element: Any,
    alias: Optional[FromClause] = ...,
    name: Optional[Text] = ...,
    flat: bool = ...,
    adapt_on_names: bool = ...,
) -> AliasedClass: ...
def with_polymorphic(
    base,
    classes,
    selectable: bool = ...,
    flat: bool = ...,
    polymorphic_on: Optional[Any] = ...,
    aliased: bool = ...,
    innerjoin: bool = ...,
    _use_mapper_path: bool = ...,
    _existing_alias: Optional[Any] = ...,
): ...

class _ORMJoin(expression.Join):
    __visit_name__: Any = ...
    onclause: Any = ...
    def __init__(
        self,
        left,
        right,
        onclause: Optional[Any] = ...,
        isouter: bool = ...,
        full: bool = ...,
        _left_memo: Optional[Any] = ...,
        _right_memo: Optional[Any] = ...,
    ) -> None: ...
    def join(
        self,
        right,
        onclause: Optional[Any] = ...,
        isouter: bool = ...,
        full: bool = ...,
        join_to_left: Optional[Any] = ...,
    ): ...
    def outerjoin(
        self,
        right,
        onclause: Optional[Any] = ...,
        full: bool = ...,
        join_to_left: Optional[Any] = ...,
    ): ...

def join(
    left,
    right,
    onclause: Optional[Any] = ...,
    isouter: bool = ...,
    full: bool = ...,
    join_to_left: Optional[Any] = ...,
): ...
def outerjoin(
    left,
    right,
    onclause: Optional[Any] = ...,
    full: bool = ...,
    join_to_left: Optional[Any] = ...,
): ...
def with_parent(instance, prop): ...
def has_identity(object) -> bool: ...
def was_deleted(object) -> bool: ...
def randomize_unitofwork(): ...
