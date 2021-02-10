from typing import (
    Any,
    Optional,
    Union,
    Type,
    TypeVar,
    Generic,
    Callable,
    List,
    Dict,
    Set,
    Iterator,
    Iterable,
    Tuple as _TupleType,
    Mapping,
    overload,
    Text,
)
from typing_extensions import Protocol
from . import operators
from .. import util
from .visitors import Visitable as Visitable
from .annotation import Annotated as Annotated
from .base import Executable as Executable, Immutable as Immutable
from ..engine.base import Engine, Connection
from .type_api import TypeEngine
from .sqltypes import NullType, Boolean, Integer
from .selectable import TextAsFrom, TableClause
from .functions import FunctionElement
from .schema import ForeignKey

_T = TypeVar("_T")
_T_contra = TypeVar("_T_contra", contravariant=True)
_V = TypeVar("_V")
_U = TypeVar("_U")

def collate(expression, collation): ...
def between(expr, lower_bound, upper_bound, symmetric: bool = ...): ...
def literal(value, type_: Optional[Any] = ...): ...
def outparam(key, type_: Optional[Any] = ...): ...
def not_(clause): ...

class ClauseElement(Visitable):
    __visit_name__: str = ...
    supports_execution: bool = ...
    bind: Any = ...
    is_selectable: bool = ...
    is_clause_element: bool = ...
    description: Any = ...
    def unique_params(self, *optionaldict, **kwargs): ...
    def params(self, *optionaldict, **kwargs): ...
    def compare(self, other: Any, **kw: Any) -> bool: ...
    def get_children(self, **kwargs: Any) -> Any: ...
    def self_group(self, against: Optional[Any] = ...) -> Any: ...
    def compile(
        self, bind: Optional[Any] = ..., dialect: Optional[Any] = ..., **kw
    ) -> Any: ...
    def __and__(self, other): ...
    def __or__(self, other): ...
    def __invert__(self): ...
    def __bool__(self): ...
    __nonzero__: Any = ...

_CE = TypeVar("_CE", bound=ColumnElement)

class ColumnElement(operators.ColumnOperators, ClauseElement, Generic[_T]):
    __visit_name__: str = ...
    primary_key: bool = ...
    foreign_keys: List[ForeignKey] = ...
    key: Optional[str] = ...
    def self_group(
        self: _CE, against: Optional[Any] = ...
    ) -> Union[AsBoolean, Grouping[_T], _CE]: ...
    @property
    def type(self) -> TypeEngine[_T]: ...
    def comparator(self): ...
    def operate(self, op, *other, **kwargs): ...
    def reverse_operate(self, op, other, **kwargs): ...
    @property
    def expression(self: _CE) -> _CE: ...
    def base_columns(self) -> Set[ColumnElement[Any]]: ...
    def proxy_set(self) -> Set[ColumnElement[Any]]: ...
    def shares_lineage(self, othercolumn: ColumnElement[Any]) -> bool: ...
    def compare(
        self,
        other: ColumnElement[Any],
        use_proxies: bool = ...,
        equivalents: bool = ...,
        **kw: Any
    ) -> bool: ...
    @overload
    def cast(self, type_: Type[TypeEngine[_U]]) -> Cast[_U]: ...
    @overload
    def cast(self, type_: TypeEngine[_U]) -> Cast[_U]: ...
    def label(self, name: str) -> Label[_T]: ...
    def anon_label(self) -> _anonymous_label: ...

class BindParameter(ColumnElement[_T]):
    __visit_name__: str = ...
    key: str = ...
    unique: bool = ...
    value: Optional[_T] = ...
    callable: Any = ...
    isoutparam: Any = ...
    required: bool = ...
    type: TypeEngine[_T] = ...
    @overload
    def __init__(
        self,
        key: str,
        value: _T = ...,
        type_: Optional[Type[TypeEngine[_T]]] = ...,
        unique: bool = ...,
        required: bool = ...,
        quote: Optional[Any] = ...,
        callable_: Optional[Callable[[], _T]] = ...,
        expanding: bool = ...,
        isoutparam: bool = ...,
        _compared_to_operator: Optional[Any] = ...,
        _compared_to_type: Optional[Any] = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        key: str,
        value: _T = ...,
        type_: Optional[TypeEngine[_T]] = ...,
        unique: bool = ...,
        required: bool = ...,
        quote: Optional[Any] = ...,
        callable_: Optional[Callable[[], _T]] = ...,
        expanding: bool = ...,
        isoutparam: bool = ...,
        _compared_to_operator: Optional[Any] = ...,
        _compared_to_type: Optional[Any] = ...,
    ) -> None: ...
    @property
    def effective_value(self) -> _T: ...
    # Signature of "compare" incompatible with supertype "ColumnElement"
    def compare(self, other: ColumnElement[Any], **kw: Any) -> bool: ...  # type: ignore

class TypeClause(ClauseElement, Generic[_T]):
    __visit_name__: str = ...
    type: TypeEngine[_T] = ...
    def __init__(self, type: TypeEngine[_T]) -> None: ...

_TC = TypeVar("_TC", bound=TextClause)

class TextClause(Executable, ClauseElement):
    __visit_name__: str = ...
    @property
    def selectable(self: _TC) -> _TC: ...
    key: Any = ...
    text: str = ...
    def __init__(
        self, text: Text, bind: Optional[Union[Engine, Connection]] = ...
    ) -> None: ...
    def bindparams(
        self: _TC, *binds: BindParameter[Any], **names_to_values: Any
    ) -> _TC: ...
    def columns(
        self,
        *cols: ColumnClause[Any],
        **types: Union[TypeEngine[Any], Type[TypeEngine[Any]]]
    ) -> TextAsFrom: ...
    @property
    def type(self) -> NullType: ...
    @property
    def comparator(self) -> Any: ...
    def self_group(
        self: _TC, against: Optional[Any] = ...
    ) -> Union[_TC, Grouping[None]]: ...
    def get_children(self, **kwargs: Any) -> List[BindParameter[Any]]: ...
    def compare(self, other: Any) -> bool: ...  # type: ignore
    @classmethod
    def _create_text(
        cls: Type[_TC],
        text: Text,
        bind: Optional[Union[Engine, Connection]] = ...,
        bindparams: Optional[Iterable[BindParameter[Any]]] = ...,
        typemap: Optional[
            Dict[str, Union[TypeEngine[Any], Type[TypeEngine[Any]]]]
        ] = ...,
        autocommit: Optional[bool] = ...,
    ) -> _TC: ...

class Null(ColumnElement[None]):
    __visit_name__: str = ...
    @property
    def type(self) -> NullType: ...
    def compare(self, other: Any) -> bool: ...  # type: ignore
    @classmethod
    def _instance(cls) -> Null: ...

class False_(ColumnElement[bool]):
    __visit_name__: str = ...
    @property
    def type(self) -> Boolean: ...
    def compare(self, other: Any) -> bool: ...  # type: ignore
    @classmethod
    def _instance(cls) -> False_: ...

class True_(ColumnElement[bool]):
    __visit_name__: str = ...
    @property
    def type(self) -> Boolean: ...
    def compare(self, other: Any) -> bool: ...  # type: ignore
    @classmethod
    def _instance(cls) -> True_: ...

_CL = TypeVar("_CL", bound=ClauseList)

class _LiteralAsTextCallback(Protocol[_T_contra]):
    def __call__(self, clause: _T_contra) -> List[ClauseElement]: ...

class ClauseList(ClauseElement):
    __visit_name__: str = ...
    operator: Any = ...
    group: bool = ...
    group_contents: bool = ...
    clauses: List[ClauseElement] = ...
    @overload
    def __init__(
        self,
        *clauses: _T,
        operator: Callable[..., Any] = ...,
        group: bool = ...,
        group_contents: bool = ...,
        _literal_as_text: _LiteralAsTextCallback[_T] = ...,
        **kwargs: Any
    ) -> None: ...
    @overload
    def __init__(
        self,
        *clauses: Optional[Union[str, bool, Visitable]],
        operator: Callable[..., Any] = ...,
        group: bool = ...,
        group_contents: bool = ...,
        **kwargs: Any
    ) -> None: ...
    def __iter__(self) -> Iterator[ClauseElement]: ...
    def __len__(self) -> int: ...
    def append(self, clause: ClauseElement): ...
    def get_children(self, **kwargs) -> List[ClauseElement]: ...
    def self_group(
        self: _CL, against: Optional[Any] = ...
    ) -> Union[_CL, Grouping[Any]]: ...
    def compare(self, other: Any, **kw: Any) -> bool: ...

_BCL = TypeVar("_BCL", bound=BooleanClauseList)

# Definitions of "compare" and "self_group" in ClauseList are incompatible with ColumnElement
class BooleanClauseList(ClauseList, ColumnElement[bool]):  # type: ignore
    __visit_name__: str = ...
    # Note: passing strings to below generates a warning, but still works.
    @classmethod
    def and_(cls, *clauses: Union[ClauseElement, str, bool]) -> BooleanClauseList: ...
    @classmethod
    def or_(cls, *clauses: Union[ClauseElement, str, bool]) -> BooleanClauseList: ...
    def self_group(
        self: _BCL, against: Optional[Any] = ...
    ) -> Union[_BCL, Grouping[bool]]: ...

and_ = BooleanClauseList.and_
or_ = BooleanClauseList.or_

# Definitions of "compare" and "self_group" in ClauseList are incompatible with ColumnElement
class Tuple(ClauseList, ColumnElement[_T]):  # type: ignore
    type: TypeEngine[_T] = ...
    @overload
    def __init__(
        self, *clauses: ColumnElement[Any], type_: Type[TypeEngine[_T]], **kw: Any
    ) -> None: ...
    @overload
    def __init__(
        self, *clauses: ColumnElement[Any], type_: TypeEngine[_T], **kw: Any
    ) -> None: ...
    @overload
    def __init__(
        self, clause: ColumnElement[_T], *clauses: ColumnElement[Any], **kw: Any
    ) -> None: ...

class Case(ColumnElement[_T]):
    __visit_name__: str = ...
    value: Any = ...
    type: TypeEngine[_T] = ...
    whens: Any = ...
    else_: Any = ...
    @overload
    def __init__(
        self,
        whens: Iterable[_TupleType[ClauseElement, _T]],
        value: None = ...,
        else_: Optional[_T] = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        whens: Mapping[Any, _T],
        value: ColumnElement[Any] = ...,
        else_: Optional[_T] = ...,
    ) -> None: ...
    def get_children(self, **kwargs: Any) -> Any: ...

@overload
def literal_column(
    text: str, type_: Optional[Type[TypeEngine[_T]]] = ...
) -> ColumnClause[TypeEngine[_T]]: ...
@overload
def literal_column(
    text: str, type_: Optional[TypeEngine[_T]] = ...
) -> ColumnClause[TypeEngine[_T]]: ...

class Cast(ColumnElement[_T]):
    __visit_name__: str = ...
    type: TypeEngine[_T] = ...
    clause: ClauseElement = ...
    typeclause: TypeClause[_T] = ...
    @overload
    def __init__(self, expression: Any, type_: Type[TypeEngine[_T]]) -> None: ...
    @overload
    def __init__(self, expression: Any, type_: TypeEngine[_T]) -> None: ...
    def get_children(
        self, **kwargs: Any
    ) -> _TupleType[ClauseElement, TypeClause[TypeEngine[_T]]]: ...

class TypeCoerce(ColumnElement[_T]):
    __visit_name__: str = ...
    type: TypeEngine[_T] = ...
    clause: ClauseElement = ...
    @overload
    def __init__(self, expression: str, type_: Type[TypeEngine[_T]]) -> None: ...
    @overload
    def __init__(
        self, expression: ColumnElement[Any], type_: Type[TypeEngine[_T]]
    ) -> None: ...
    @overload
    def __init__(self, expression: str, type_: TypeEngine[_T]) -> None: ...
    @overload
    def __init__(
        self, expression: ColumnElement[Any], type_: TypeEngine[_T]
    ) -> None: ...
    def get_children(self, **kwargs: Any) -> _TupleType[ClauseElement]: ...
    @property
    def typed_expression(self) -> Any: ...

class Extract(ColumnElement[int]):
    __visit_name__: str = ...
    type: Integer = ...
    field: Any = ...
    expr: ClauseElement = ...
    def __init__(self, field: Any, expr: ClauseElement, **kwargs: Any) -> None: ...
    def get_children(self, **kwargs) -> _TupleType[ClauseElement]: ...

_UE = TypeVar("_UE", bound=UnaryExpression)

class UnaryExpression(ColumnElement[_T]):
    __visit_name__: str = ...
    operator: Callable[..., Any] = ...
    modifier: Any = ...
    element: Any = ...
    type: TypeEngine[_T] = ...
    negate: Any = ...
    wraps_column_expression: bool = ...
    @overload
    def __init__(
        self,
        element: Any,
        operator: Optional[Callable[..., Any]] = ...,
        modifier: Optional[Any] = ...,
        type_: Optional[Type[TypeEngine[_T]]] = ...,
        negate: Optional[Any] = ...,
        wraps_column_expression: bool = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        element: Any,
        operator: Optional[Callable[..., Any]] = ...,
        modifier: Optional[Any] = ...,
        type_: Optional[TypeEngine[_T]] = ...,
        negate: Optional[Any] = ...,
        wraps_column_expression: bool = ...,
    ) -> None: ...
    def get_children(self, **kwargs) -> _TupleType[Any]: ...
    # Signature of "compare" incompatible with supertype "ColumnElement"
    def compare(self, other: ColumnElement[Any], **kw: Any) -> bool: ...  # type: ignore
    def self_group(
        self: _UE, against: Optional[Any] = ...
    ) -> Union[_UE, Grouping[_T]]: ...
    @classmethod
    def _create_nullsfirst(
        cls, column: ColumnElement[Any]
    ) -> UnaryExpression[NullType]: ...
    @classmethod
    def _create_nullslast(
        cls, column: ColumnElement[Any]
    ) -> UnaryExpression[NullType]: ...
    @classmethod
    def _create_desc(
        cls, column: Union[ColumnElement[Any], str]
    ) -> UnaryExpression[NullType]: ...
    @classmethod
    def _create_asc(
        cls, column: Union[ColumnElement[Any], str]
    ) -> UnaryExpression[NullType]: ...
    @classmethod
    def _create_distinct(cls, expr: ColumnElement[_U]) -> UnaryExpression[_U]: ...

class CollectionAggregate(UnaryExpression[_T]):
    def operate(self, op: Any, *other: Any, **kwargs: Any) -> Any: ...
    def reverse_operate(self, op: Any, other: Any, **kwargs: Any) -> Any: ...
    @overload
    @classmethod
    def _create_all(cls, expr: ColumnElement[_U]) -> CollectionAggregate[_U]: ...
    @overload
    @classmethod
    def _create_all(cls, expr: ClauseElement) -> CollectionAggregate[Any]: ...
    @overload
    @classmethod
    def _create_any(cls, expr: ColumnElement[_U]) -> CollectionAggregate[_U]: ...
    @overload
    @classmethod
    def _create_any(cls, expr: ClauseElement) -> CollectionAggregate[Any]: ...

_AB = TypeVar("_AB", bound=AsBoolean)

class AsBoolean(UnaryExpression[bool]):
    element: ColumnElement[Any] = ...
    type: Boolean = ...
    operator: Callable[..., Any] = ...
    negate: Callable[..., Any] = ...
    modifier: Any = ...
    wraps_column_expression: bool = ...
    def __init__(
        self,
        element: ColumnElement[Any],
        operator: Callable[..., Any],
        negate: Callable[..., Any],
    ) -> None: ...
    def self_group(self: _AB, against: Optional[Any] = ...) -> _AB: ...

_BE = TypeVar("_BE", bound=BinaryExpression)

class BinaryExpression(ColumnElement[_T], Generic[_T, _U, _V]):
    __visit_name__: str = ...
    left: Union[Grouping[_U], ColumnClause[_U]] = ...
    right: Union[Grouping[_V], ColumnElement[_V]] = ...
    operator: Callable[..., Any] = ...
    type: TypeEngine[_T] = ...
    negate: Any = ...
    modifiers: Any = ...
    @overload
    def __init__(
        self,
        left: ColumnClause[_U],
        right: ColumnClause[_V],
        operator: Callable[..., Any],
        type_: Optional[Type[TypeEngine[_T]]] = ...,
        negate: Optional[Any] = ...,
        modifiers: Optional[Any] = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        left: ColumnClause[_U],
        right: ColumnClause[_V],
        operator: Callable[..., Any],
        type_: Optional[TypeEngine[_T]] = ...,
        negate: Optional[Any] = ...,
        modifiers: Optional[Any] = ...,
    ) -> None: ...
    def __bool__(self) -> bool: ...
    __nonzero__: Any = ...
    @property
    def is_comparison(self): ...
    def get_children(self, **kwargs): ...
    # Signature of "compare" incompatible with supertype "ColumnElement"
    def compare(self, other: ColumnElement[Any], **kw: Any) -> bool: ...  # type: ignore
    def self_group(
        self: _BE, against: Optional[Any] = ...
    ) -> Union[_BE, Grouping[_T]]: ...

_SL = TypeVar("_SL", bound=Slice)

class Slice(ColumnElement[None]):
    __visit_name__: str = ...
    start: Any = ...
    stop: Any = ...
    step: Any = ...
    type: NullType = ...
    def __init__(self, start, stop, step) -> None: ...
    def self_group(self: _SL, against: Optional[Any] = ...) -> _SL: ...

class IndexExpression(BinaryExpression): ...

_G = TypeVar("_G", bound=Grouping)

class Grouping(ColumnElement[_T]):
    __visit_name__: str = ...
    element: ClauseElement = ...
    type: TypeEngine[_T] = ...
    @overload
    def __init__(self, element: ColumnElement[_T]) -> None: ...
    # the following __init__ signature produces Grouping[None] at runtime but mypy will require an annotation
    @overload
    def __init__(self, element: ClauseElement) -> None: ...
    def self_group(self: _G, against: Optional[Any] = ...) -> _G: ...
    def get_children(self, **kwargs) -> _TupleType[ClauseElement]: ...
    def __getattr__(self, attr): ...
    # Signature of "compare" incompatible with supertype "ColumnElement"
    def compare(self, other: ColumnElement[Any], **kw: Any) -> bool: ...  # type: ignore

RANGE_UNBOUNDED: util.symbol = ...
RANGE_CURRENT: util.symbol = ...

class Over(ColumnElement[_T]):
    __visit_name__: str = ...
    order_by: Optional[ClauseList] = ...
    partition_by: Optional[ClauseList] = ...
    element: Union[WithinGroup[_T], FunctionElement[_T]] = ...
    range_: Optional[_TupleType[Union[int, util.symbol], Union[int, util.symbol]]] = ...
    rows: Optional[_TupleType[Union[int, util.symbol], Union[int, util.symbol]]] = ...
    @overload
    def __init__(
        self,
        element: WithinGroup[_T],
        partition_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
        order_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
        range_: Optional[_TupleType[Optional[int], Optional[int]]] = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        element: WithinGroup[_T],
        partition_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
        order_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
        rows: Optional[_TupleType[Optional[int], Optional[int]]] = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        element: FunctionElement[_T],
        partition_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
        order_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
        range_: Optional[_TupleType[Optional[int], Optional[int]]] = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        element: FunctionElement[_T],
        partition_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
        order_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
        rows: Optional[_TupleType[Optional[int], Optional[int]]] = ...,
    ) -> None: ...
    @property
    def func(self) -> Union[WithinGroup[_T], FunctionElement[_T]]: ...
    @property
    def type(self) -> TypeEngine[_T]: ...
    def get_children(
        self, **kwargs: Any
    ) -> List[Union[WithinGroup[_T], FunctionElement[_T], ClauseList]]: ...

class WithinGroup(ColumnElement[_T]):
    __visit_name__: str = ...
    order_by: Optional[ClauseList] = ...
    element: FunctionElement[_T] = ...
    def __init__(
        self, element: FunctionElement[_T], *order_by: Union[str, ColumnElement[Any]]
    ) -> None: ...
    def over(
        self,
        partition_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
        order_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
    ) -> Over[_T]: ...
    @property
    def type(self) -> TypeEngine[_T]: ...
    def get_children(
        self, **kwargs: Any
    ) -> List[Union[FunctionElement[_T], ClauseList]]: ...

class FunctionFilter(ColumnElement[_T]):
    __visit_name__: str = ...
    criterion: Any = ...
    func: FunctionElement[_T] = ...
    def __init__(self, func: FunctionElement[_T], *criterion: Any) -> None: ...
    def filter(self, *criterion: Any) -> FunctionFilter[_T]: ...
    def over(
        self,
        partition_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
        order_by: Optional[
            Union[str, ColumnElement[Any], Iterable[Union[str, ColumnElement[Any]]]]
        ] = ...,
    ) -> Over[_T]: ...
    @property
    def type(self) -> TypeEngine[_T]: ...
    def get_children(self, **kwargs: Any) -> List[Any]: ...

_L = TypeVar("_L", bound=Label)

class Label(ColumnElement[_T]):
    __visit_name__: str = ...
    name: str = ...
    key: str = ...
    @overload
    def __init__(self, name: str, element: ColumnElement[_T]) -> None: ...
    @overload
    def __init__(
        self, name: str, element: ColumnElement[Any], type_: Type[TypeEngine[_T]] = ...
    ) -> None: ...
    @overload
    def __init__(
        self, name: str, element: ColumnElement[Any], type_: TypeEngine[_T] = ...
    ) -> None: ...
    def __reduce__(self) -> Any: ...
    @property
    def type(self) -> TypeEngine[_T]: ...
    @property
    def element(self) -> ColumnElement[_T]: ...
    def self_group(self: _L, against: Optional[Any] = ...) -> Union[_L, Label[_T]]: ...
    # Signature of "primary_key" incompatible with supertype "ColumnElement"
    @property
    def primary_key(self) -> bool: ...  # type: ignore
    # Signature of "foreign_keys" incompatible with supertype "ColumnElement"
    @property
    def foreign_keys(self) -> List[ForeignKey]: ...  # type: ignore
    def get_children(self, **kwargs: Any) -> Any: ...

class ColumnClause(Immutable, ColumnElement[_T]):
    __visit_name__: str = ...
    onupdate: Any = ...
    default: Any = ...
    server_default: Any = ...
    server_onupdate: Any = ...
    key: str = ...
    name: str = ...
    table: Optional[TableClause] = ...
    type: TypeEngine[_T] = ...
    is_literal: bool = ...
    @overload
    def __init__(
        self,
        text: str,
        type_: Optional[Type[TypeEngine[_T]]] = ...,
        is_literal: bool = ...,
        _selectable: Optional[TableClause] = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        text: str,
        type_: Optional[TypeEngine[_T]] = ...,
        is_literal: bool = ...,
        _selectable: Optional[TableClause] = ...,
    ) -> None: ...
    @property
    def description(self) -> str: ...

class _IdentifiedClause(Executable, ClauseElement):
    __visit_name__: str = ...
    ident: Any = ...
    def __init__(self, ident: Any) -> None: ...

class SavepointClause(_IdentifiedClause):
    __visit_name__: str = ...

class RollbackToSavepointClause(_IdentifiedClause):
    __visit_name__: str = ...

class ReleaseSavepointClause(_IdentifiedClause):
    __visit_name__: str = ...

class quoted_name(util.MemoizedSlots, util.text_type):
    quote: Any = ...
    def __new__(cls, value, quote): ...
    def __reduce__(self): ...

class _truncated_label(quoted_name):
    def __new__(cls, value, quote: Optional[Any] = ...): ...
    def __reduce__(self): ...
    def apply_map(self, map_): ...

class conv(_truncated_label): ...
class _anonymous_label(_truncated_label): ...

class AnnotatedColumnElement(Annotated[ColumnElement[_T]], Generic[_T]):
    def __init__(self, element: ColumnElement[_T], values: Any) -> None: ...
    @property
    def name(self) -> str: ...
    @property
    def table(self) -> TableClause: ...
    @property
    def key(self) -> str: ...
    @property
    def info(self) -> Any: ...
    @property
    def anon_label(self) -> str: ...
