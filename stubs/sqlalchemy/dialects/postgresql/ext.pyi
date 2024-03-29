from typing import Any, Dict, Optional, Tuple, Type, TypeVar, Union, overload

from ...engine.base import Connection, Engine
from ...sql import expression, functions, visitors
from ...sql.elements import ColumnElement
from ...sql.schema import ColumnCollectionConstraint
from ...sql.type_api import TypeEngine
from .array import ARRAY

_T = TypeVar("_T")
_AOB = TypeVar("_AOB", bound=aggregate_order_by)

class aggregate_order_by(expression.ColumnElement[Any]):
    __visit_name__: str = ...
    target: expression.ColumnElement[Any] = ...
    order_by: Any = ...
    def __init__(
        self, target: expression.ColumnElement[Any], *order_by: expression.ClauseElement
    ) -> None: ...
    def self_group(self: _AOB, against: Optional[Any] = ...) -> _AOB: ...
    def get_children(
        self, **kwargs: Any
    ) -> Tuple[expression.ColumnElement[Any], Any]: ...

_EC = TypeVar("_EC", bound=ExcludeConstraint)

class ExcludeConstraint(ColumnCollectionConstraint):
    __visit_name__: str = ...
    where: Optional[visitors.Visitable] = ...
    operators: Dict[str, Any] = ...
    using: str = ...
    def __init__(
        self,
        *elements: Any,
        name: str = ...,
        deferrable: bool = ...,
        initially: str = ...,
        using: str = ...,
        where: Optional[Union[str, bool, visitors.Visitable]] = ...
    ) -> None: ...
    def copy(self: _EC, **kw: Any) -> _EC: ...

@overload
def array_agg(
    self,
    *args: ColumnElement[Any],
    bind: Optional[Union[Engine, Connection]] = ...,
    type_: Type[TypeEngine[_T]]
) -> functions.array_agg[_T]: ...
@overload
def array_agg(
    self,
    *args: ColumnElement[Any],
    bind: Optional[Union[Engine, Connection]] = ...,
    type_: TypeEngine[_T]
) -> functions.array_agg[_T]: ...
@overload
def array_agg(
    self, *args: ColumnElement[_T], bind: Optional[Union[Engine, Connection]] = ...
) -> functions.array_agg[_T]: ...
