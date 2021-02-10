import threading
from typing import (
    Any,
    Callable,
    Generic,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence as SequenceType,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

from typing_extensions import Literal, final

from .. import util
from ..engine import Connectable, Connection, Engine
from ..engine.url import URL
from . import functions, visitors
from .base import (
    ColumnCollection,
    DialectKWArgs as DialectKWArgs,
    SchemaEventTarget as SchemaEventTarget,
)
from .compiler import DDLCompiler
from .elements import ColumnClause as ColumnClause, ColumnElement, TextClause
from .expression import FunctionElement
from .selectable import TableClause as TableClause
from .type_api import TypeEngine

_T = TypeVar("_T")

RETAIN_SCHEMA: util.symbol = ...
BLANK_SCHEMA: util.symbol = ...

class SchemaItem(SchemaEventTarget, visitors.Visitable):
    __visit_name__: str = ...
    def get_children(self, **kwargs: Any) -> Iterable[Any]: ...
    @property
    def quote(self) -> str: ...
    @property
    def info(self) -> Optional[Mapping[str, Any]]: ...

# Definition of "get_children" in base class "SchemaItem" is incompatible with definition in base class "TableClause"
class Table(DialectKWArgs, SchemaItem, TableClause):  # type: ignore
    __visit_name__: str
    metadata: MetaData
    schema: Optional[str]
    indexes: Set[Index]
    constraints: Set[Constraint]
    foreign_keys: Set[ForeignKey]
    primary_key: PrimaryKeyConstraint  # type: ignore  # TableClause.primary_key defines this as "ColumnSet"
    fullname: str
    implicit_returning: bool
    comment: Any
    def __new__(cls, *args, **kw): ...
    @property
    def quote_schema(self) -> Optional[bool]: ...
    def __init__(
        self,
        name: str,
        metadata: MetaData,
        *args: Any,
        autoload: bool = ...,
        autoload_replace: bool = ...,
        autoload_with: Union[Engine, Connection] = ...,
        extend_existing: bool = ...,
        implicit_returning: bool = ...,
        include_columns: SequenceType[str] = ...,
        info: Mapping[str, Any] = ...,
        keep_existing: bool = ...,
        listeners: SequenceType[Tuple[str, Callable[..., Any]]] = ...,
        mustexist: bool = ...,
        prefixes: SequenceType[str] = ...,
        quote: Optional[bool] = ...,
        quote_schema: Optional[bool] = ...,
        schema: Optional[str] = ...,
        comment: str = ...,
        **kw: Any
    ) -> None: ...
    @property
    def foreign_key_constraints(self) -> Set[ForeignKeyConstraint]: ...
    @property
    def key(self) -> str: ...
    @property
    def bind(self) -> Optional[Union[Engine, Connection]]: ...
    def add_is_dependent_on(self, table: Table) -> None: ...
    def append_column(self, column: ColumnClause[Any]) -> None: ...
    def append_constraint(self, constraint: Constraint) -> None: ...
    def append_ddl_listener(
        self, event_name: str, listener: Callable[..., Any]
    ) -> None: ...
    def get_children(
        self, column_collections: bool = ..., schema_visitor: bool = ..., **kw: Any
    ) -> List[Any]: ...
    def exists(self, bind: Optional[Union[Engine, Connection]] = ...) -> bool: ...
    def create(
        self, bind: Optional[Connectable] = ..., checkfirst: bool = ...
    ) -> None: ...
    def drop(
        self, bind: Optional[Connectable] = ..., checkfirst: bool = ...
    ) -> None: ...
    def tometadata(
        self,
        metadata: MetaData,
        schema: str = ...,
        referred_schema_fn: Optional[
            Callable[[Table, str, ForeignKeyConstraint, str], str]
        ] = ...,
        name: Optional[str] = ...,
    ) -> Table: ...

_C = TypeVar("_C", bound=Column)
@final
class Column(SchemaItem, ColumnClause[_T]):
    __visit_name__: str = ...
    key: str = ...
    primary_key: bool = ...
    nullable: bool = ...
    default: Optional[Any] = ...
    server_default: Optional[Any] = ...
    server_onupdate: Optional[FetchedValue] = ...
    index: Optional[bool] = ...
    unique: Optional[bool] = ...
    system: bool = ...
    doc: Optional[str] = ...
    onupdate: Optional[Any] = ...
    autoincrement: Union[bool, str] = ...
    constraints: Set[Constraint] = ...
    foreign_keys: Set[  # type: ignore  # incompatible with ColumnElement.foreign_keys
        ForeignKey
    ] = ...
    info: Optional[Mapping[str, Any]] = ...
    comment: Optional[str] = ...
    table: Table = ...  # TODO: double-check this.

    # Passing a keyword argument of primary_key=True or nullable=False will
    # make the return type a Column[_T]. Otherwise, the return type will be
    # Column[Optional[_T]]. This gives us three overloads for each combination
    # of parameters.

    # Overloads with name and type_: Type[TypeEngine[_T]].
    @overload
    def __new__(  # type: ignore
        self,
        name: str,
        type_: Type[TypeEngine[_T]],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: Literal[True],
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        name: str,
        type_: Type[TypeEngine[_T]],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: Literal[False],
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        name: str,
        type_: Type[TypeEngine[_T]],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[Optional[_T]]: ...
    # Overloads with name and type_: TypeEngine[_T].
    @overload
    def __new__(  # type: ignore
        self,
        name: str,
        type_: TypeEngine[_T],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: Literal[True],
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        name: str,
        type_: TypeEngine[_T],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: Literal[False],
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        name: str,
        type_: TypeEngine[_T],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[Optional[_T]]: ...
    # Overloads with name and type_: ForeignKey.
    @overload
    def __new__(  # type: ignore
        self,
        name: str,
        type_: ForeignKey,
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: Literal[True],
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        name: str,
        type_: ForeignKey,
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: Literal[False],
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        name: str,
        type_: ForeignKey,
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[Optional[_T]]: ...
    # Now without a name argument.
    # Overloads with type_: Type[TypeEngine[_T]].
    @overload
    def __new__(  # type: ignore
        self,
        type_: Type[TypeEngine[_T]],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: Literal[True],
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        type_: Type[TypeEngine[_T]],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: Literal[False],
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        type_: Type[TypeEngine[_T]],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[Optional[_T]]: ...
    # Overloads with type_: TypeEngine[_T].
    @overload
    def __new__(  # type: ignore
        self,
        type_: TypeEngine[_T],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: Literal[True],
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        type_: TypeEngine[_T],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: Literal[False],
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        type_: TypeEngine[_T],
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[Optional[_T]]: ...
    # Overloads with type_: ForeignKey.
    @overload
    def __new__(  # type: ignore
        self,
        type_: ForeignKey,
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: Literal[True],
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        type_: ForeignKey,
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: Literal[False],
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[_T]: ...
    @overload
    def __new__(  # type: ignore
        self,
        type_: ForeignKey,
        *args: Any,
        autoincrement: Union[bool, str] = ...,
        default: Any = ...,
        doc: str = ...,
        key: str = ...,
        index: bool = ...,
        info: Mapping[str, Any] = ...,
        nullable: bool = ...,
        onupdate: Any = ...,
        primary_key: bool = ...,
        server_default: Any = ...,
        server_onupdate: Union[FetchedValue, FunctionElement] = ...,
        quote: Optional[bool] = ...,
        unique: bool = ...,
        system: bool = ...,
        comment: str = ...
    ) -> Column[Optional[_T]]: ...
    def references(self, column: Column[Any]) -> bool: ...
    def append_foreign_key(self, fk: ForeignKey) -> None: ...
    def copy(self: _C, **kw: Any) -> _C: ...
    def get_children(self, schema_visitor: bool = ..., **kwargs) -> List[Any]: ...
    @overload
    def __get__(self, instance: None, owner: Any) -> Column[_T]: ...
    @overload
    def __get__(self, instance: object, owner: Any) -> _T: ...

class ForeignKey(DialectKWArgs, SchemaItem):
    __visit_name__: str = ...
    constraint: Optional[ForeignKeyConstraint] = ...
    parent: Column[Any] = ...
    use_alter: bool = ...
    name: Optional[str] = ...
    onupdate: Optional[str] = ...
    ondelete: Optional[str] = ...
    deferrable: Optional[bool] = ...
    initially: Optional[str] = ...
    link_to_name: bool = ...
    match: Optional[str] = ...
    info: Optional[Mapping[str, Any]] = ...
    def __init__(
        self,
        column: Union[Column[Any], str],
        _constraint: Optional[Any] = ...,
        use_alter: bool = ...,
        name: Optional[str] = ...,
        onupdate: Optional[str] = ...,
        ondelete: Optional[str] = ...,
        deferrable: Optional[bool] = ...,
        initially: Optional[str] = ...,
        link_to_name: bool = ...,
        match: Optional[str] = ...,
        info: Optional[Mapping[str, Any]] = ...,
        **dialect_kw: Any
    ) -> None: ...
    def copy(self, schema: Optional[str] = ...) -> ForeignKey: ...
    target_fullname: str = ...
    def references(self, table: Table) -> bool: ...
    def get_referent(self, table: Table) -> Column[Any]: ...
    @property
    def column(self) -> Column[Any]: ...

class _NotAColumnExpr(object):
    __clause_element__: Any = ...
    self_group: Any = ...

class DefaultGenerator(_NotAColumnExpr, SchemaItem):
    __visit_name__: str = ...
    is_sequence: bool = ...
    is_server_default: bool = ...
    column: Column[Any] = ...
    for_update: bool = ...
    def __init__(self, for_update: bool = ...) -> None: ...
    def execute(
        self, bind: Optional[Union[Engine, Connection]] = ..., **kwargs: Any
    ) -> Any: ...
    @property
    def bind(self) -> Optional[Union[Engine, Connection]]: ...

class ColumnDefault(DefaultGenerator):
    arg: Any = ...
    def __init__(self, arg: Any, **kwargs: Any) -> None: ...
    @property
    def is_callable(self) -> bool: ...
    @property
    def is_clause_element(self) -> bool: ...
    @property
    def is_scalar(self) -> bool: ...
    __visit_name__: Any = ...

class Sequence(DefaultGenerator, Generic[_T]):
    __visit_name__: str = ...
    is_sequence: bool = ...
    name: str = ...
    start: Optional[int] = ...
    increment: Optional[int] = ...
    minvalue: Optional[int] = ...
    maxvalue: Optional[int] = ...
    nominvalue: Optional[int] = ...
    nomaxvalue: Optional[int] = ...
    cycle: Optional[bool] = ...
    optional: bool = ...
    schema: Optional[str] = ...
    metadata: Optional[MetaData] = ...
    def __init__(
        self,
        name: str,
        start: Optional[int] = ...,
        increment: Optional[int] = ...,
        minvalue: Optional[int] = ...,
        maxvalue: Optional[int] = ...,
        nominvalue: Optional[int] = ...,
        nomaxvalue: Optional[int] = ...,
        cycle: Optional[bool] = ...,
        schema: Optional[str] = ...,
        optional: bool = ...,
        quote: Optional[bool] = ...,
        metadata: Optional[MetaData] = ...,
        quote_schema: Optional[bool] = ...,
        for_update: bool = ...,
    ) -> None: ...
    @property
    def is_callable(self) -> bool: ...
    @property
    def is_clause_element(self) -> bool: ...
    def next_value(self) -> functions.next_value[_T]: ...
    @property
    def bind(self) -> Optional[Union[Engine, Connection]]: ...
    def create(
        self, bind: Optional[Union[Engine, Connection]] = ..., checkfirst: bool = ...
    ) -> None: ...
    def drop(
        self, bind: Optional[Union[Engine, Connection]] = ..., checkfirst: bool = ...
    ) -> None: ...

class FetchedValue(_NotAColumnExpr, SchemaEventTarget):
    is_server_default: bool = ...
    reflected: bool = ...
    has_argument: bool = ...
    for_update: bool = ...
    def __init__(self, for_update: bool = ...) -> None: ...

class DefaultClause(FetchedValue):
    has_argument: bool = ...
    arg: Any = ...
    reflected: bool = ...
    def __init__(
        self, arg: Any, for_update: bool = ..., _reflected: bool = ...
    ) -> None: ...

class PassiveDefault(DefaultClause):
    def __init__(self, *arg: Any, **kw: Any) -> None: ...

class Constraint(DialectKWArgs, SchemaItem):
    __visit_name__: str = ...
    name: Optional[str] = ...
    deferrable: Optional[bool] = ...
    initially: Optional[str] = ...
    info: Optional[Mapping[str, Any]] = ...
    def __init__(
        self,
        name: Optional[str] = ...,
        deferrable: Optional[bool] = ...,
        initially: Optional[str] = ...,
        _create_rule: Optional[Callable[[DDLCompiler], bool]] = ...,
        info: Optional[Mapping[str, Any]] = ...,
        _type_bound: bool = ...,
        **dialect_kw: Any
    ) -> None: ...
    @property
    def table(self) -> Table: ...
    def copy(self, **kw: Any) -> Any: ...

class ColumnCollectionMixin(object):
    columns: ColumnCollection = ...
    def __init__(self, *columns: Union[Column[Any], str], **kw: Any) -> None: ...

_CCC = TypeVar("_CCC", bound=ColumnCollectionConstraint)

class ColumnCollectionConstraint(ColumnCollectionMixin, Constraint):
    def __init__(
        self,
        *columns: Union[Column[Any], str],
        name: Optional[str] = ...,
        deferrable: Optional[bool] = ...,
        initially: Optional[str] = ...,
        _create_rule: Optional[Callable[[DDLCompiler], bool]] = ...,
        info: Optional[Mapping[str, Any]] = ...,
        _type_bound: bool = ...,
        **dialect_kw: Any
    ) -> None: ...
    def __contains__(self, x: Any) -> bool: ...
    def copy(self: _CCC, **kw: Any) -> _CCC: ...
    def contains_column(self, col: Column[Any]) -> bool: ...
    def __iter__(self) -> Iterator[Column[Any]]: ...
    def __len__(self) -> int: ...

class CheckConstraint(ColumnCollectionConstraint):
    sqltext: str = ...
    def __init__(
        self,
        sqltext: str,
        name: Optional[str] = ...,
        deferrable: Optional[bool] = ...,
        initially: Optional[str] = ...,
        table: Optional[Table] = ...,
        info: Optional[Mapping[str, Any]] = ...,
        _create_rule: Optional[Callable[[DDLCompiler], bool]] = ...,
        _autoattach: bool = ...,
        _type_bound: bool = ...,
    ) -> None: ...
    __visit_name__: Any = ...
    def copy(
        self, target_table: Optional[Table] = ..., **kw: Any
    ) -> CheckConstraint: ...

class ForeignKeyConstraint(ColumnCollectionConstraint):
    __visit_name__: str = ...
    onupdate: Optional[str] = ...
    ondelete: Optional[str] = ...
    link_to_name: bool = ...
    use_alter: bool = ...
    match: Optional[str] = ...
    elements: List[ForeignKey] = ...
    def __init__(
        self,
        columns: SequenceType[str],
        refcolumns: SequenceType[Union[str, Column[Any]]],
        name: Optional[str] = ...,
        onupdate: Optional[str] = ...,
        ondelete: Optional[str] = ...,
        deferrable: Optional[bool] = ...,
        initially: Optional[str] = ...,
        use_alter: bool = ...,
        link_to_name: bool = ...,
        match: Optional[str] = ...,
        table: Optional[Table] = ...,
        info: Optional[Mapping[str, Any]] = ...,
        **dialect_kw: Any
    ) -> None: ...
    @property
    def referred_table(self) -> Table: ...
    @property
    def column_keys(self) -> List[str]: ...
    def copy(
        self,
        schema: Optional[str] = ...,
        target_table: Optional[Table] = ...,
        **kw: Any
    ) -> ForeignKeyConstraint: ...

class PrimaryKeyConstraint(ColumnCollectionConstraint):
    __visit_name__: str = ...
    def __init__(
        self,
        *columns: Union[Column[Any], str],
        name: Optional[str] = ...,
        deferrable: Optional[bool] = ...,
        initially: Optional[str] = ...,
        _create_rule: Optional[Callable[[DDLCompiler], bool]] = ...,
        info: Optional[Mapping[str, Any]] = ...,
        _type_bound: bool = ...,
        **dialect_kw: Any
    ) -> None: ...
    @property
    def columns_autoinc_first(self) -> List[Column[Any]]: ...

class UniqueConstraint(ColumnCollectionConstraint):
    __visit_name__: str = ...

_I = TypeVar("_I", bound=Index)

class Index(DialectKWArgs, ColumnCollectionMixin, SchemaItem):
    __visit_name__: str = ...
    table: Optional[Table] = ...
    expressions: List[Union[Column[Any], str]] = ...
    name: str = ...
    unique: bool = ...
    info: Optional[Mapping[str, Any]] = ...
    def __init__(
        self,
        name: str,
        *expressions: Union[TextClause, ColumnElement[Any], str],
        unique: bool = ...,
        quote: Optional[bool] = ...,
        info: Optional[Mapping[str, Any]] = ...,
        **kw: Any
    ) -> None: ...
    @property
    def bind(self) -> Optional[Union[Engine, Connection]]: ...
    def create(self: _I, bind: Optional[Union[Engine, Connection]] = ...) -> _I: ...
    def drop(self, bind: Optional[Union[Engine, Connection]] = ...) -> None: ...

DEFAULT_NAMING_CONVENTION: util.immutabledict[str, str] = ...

class _MetaDataBind:
    @overload
    def __get__(self, instance: None, owner: Any) -> None: ...
    @overload
    def __get__(
        self, instance: MetaData, owner: Any
    ) -> Optional[Union[Engine, Connection]]: ...
    def __set__(
        self, instance: Any, value: Optional[Union[Engine, Connection, str, URL]]
    ) -> None: ...

class MetaData(SchemaItem):
    __visit_name__: str = ...
    tables: util.immutabledict[str, Table] = ...
    schema: Optional[str] = ...
    # `naming_convention` should be Mapping[Union[str, Index, Constraint], str] but because Mapping is invariant in the key type,
    # we must use Mapping[Any, Any] or list all subclasses of Index and Constraint in the Union
    naming_convention: Mapping[Any, Any] = ...
    info: Optional[Mapping[str, Any]] = ...
    bind: _MetaDataBind = ...
    def __init__(
        self,
        bind: Optional[Union[Engine, Connection]] = ...,
        reflect: bool = ...,
        schema: Optional[str] = ...,
        quote_schema: Optional[bool] = ...,
        naming_convention: Mapping[Any, Any] = ...,
        info: Optional[Mapping[str, Any]] = ...,
    ) -> None: ...
    def __contains__(self, table_or_key: Union[str, Table]) -> bool: ...
    def is_bound(self) -> bool: ...
    def clear(self) -> None: ...
    def remove(self, table: Table) -> None: ...
    @property
    def sorted_tables(self) -> List[Table]: ...
    def reflect(
        self,
        bind: Optional[Connectable] = ...,
        schema: Optional[str] = ...,
        views: bool = ...,
        only: Optional[Union[SequenceType[str], Callable[[str, MetaData], bool]]] = ...,
        extend_existing: bool = ...,
        autoload_replace: bool = ...,
        **dialect_kwargs: Any
    ) -> None: ...
    def append_ddl_listener(
        self, event_name: str, listener: Callable[[str, MetaData, Connection], None]
    ) -> None: ...
    def create_all(
        self,
        bind: Optional[Connectable] = ...,
        tables: Optional[SequenceType[Table]] = ...,
        checkfirst: bool = ...,
    ) -> None: ...
    def drop_all(
        self,
        bind: Optional[Connectable] = ...,
        tables: Optional[SequenceType[Table]] = ...,
        checkfirst: bool = ...,
    ) -> None: ...

class ThreadLocalMetaData(MetaData):
    __visit_name__: str = ...
    context: threading.local = ...
    bind: _MetaDataBind = ...
    def __init__(self) -> None: ...
    def is_bound(self) -> bool: ...
    def dispose(self) -> None: ...
