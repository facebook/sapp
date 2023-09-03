from datetime import timedelta
from typing import Any, Dict, Optional, Pattern, Set, Text, Type

from sqlalchemy.types import (
    BIGINT as BIGINT,
    BOOLEAN as BOOLEAN,
    CHAR as CHAR,
    DATE as DATE,
    FLOAT as FLOAT,
    INTEGER as INTEGER,
    NUMERIC as NUMERIC,
    REAL as REAL,
    SMALLINT as SMALLINT,
    TEXT as TEXT,
    VARCHAR as VARCHAR,
)

from ... import schema
from ...engine import default, reflection
from ...sql import compiler, expression, sqltypes, type_api

AUTOCOMMIT_REGEXP: Pattern[Text]
RESERVED_WORDS: Set[str]

class BYTEA(sqltypes.LargeBinary):
    __visit_name__: str = ...

class DOUBLE_PRECISION(sqltypes.Float):
    __visit_name__: str = ...

class INET(sqltypes.TypeEngine[str]):
    __visit_name__: str = ...

PGInet = INET

class CIDR(sqltypes.TypeEngine[str]):
    __visit_name__: str = ...

PGCidr = CIDR

class MACADDR(sqltypes.TypeEngine[str]):
    __visit_name__: str = ...

PGMacAddr = MACADDR

class MONEY(sqltypes.TypeEngine[float]):
    __visit_name__: str = ...

class OID(sqltypes.TypeEngine[int]):
    __visit_name__: str = ...

class REGCLASS(sqltypes.TypeEngine[str]):
    __visit_name__: str = ...

class TIMESTAMP(sqltypes.TIMESTAMP):
    precision: Optional[int] = ...
    def __init__(
        self, timezone: bool = ..., precision: Optional[int] = ...
    ) -> None: ...

class TIME(sqltypes.TIME):
    precision: Optional[int] = ...
    def __init__(
        self, timezone: bool = ..., precision: Optional[int] = ...
    ) -> None: ...

class INTERVAL(sqltypes.NativeForEmulated, sqltypes._AbstractInterval[timedelta]):
    __visit_name__: str = ...
    native: bool = ...
    precision: Optional[int] = ...
    fields: Optional[str] = ...
    def __init__(
        self, precision: Optional[int] = ..., fields: Optional[str] = ...
    ) -> None: ...
    # Return value of adapt_emulated_to_native incompatible with supertype "NativeForEmulated"
    @classmethod
    def adapt_emulated_to_native(cls, interval: Any, **kw: Any) -> INTERVAL: ...  # type: ignore
    @property
    def python_type(self) -> Type[timedelta]: ...

PGInterval = INTERVAL

class BIT(sqltypes.TypeEngine[str]):
    __visit_name__: str = ...
    length: Optional[int] = ...
    varying: bool = ...
    def __init__(self, length: Optional[int] = ..., varying: bool = ...) -> None: ...

PGBit = BIT

class UUID(sqltypes.TypeEngine[str]):
    __visit_name__: str = ...
    as_uuid: bool = ...
    def __init__(self, as_uuid: bool = ...) -> None: ...
    def bind_processor(self, dialect: Any): ...
    def result_processor(self, dialect: Any, coltype: Any): ...

PGUuid = UUID

class TSVECTOR(sqltypes.TypeEngine[str]):
    __visit_name__: str = ...

class ENUM(sqltypes.NativeForEmulated, sqltypes.Enum):
    native_enum: bool = ...
    create_type: Any = ...
    def __init__(self, *enums: Any, **kw: Any) -> None: ...
    @classmethod
    def adapt_emulated_to_native(cls, impl: Any, **kw: Any): ...
    def create(self, bind: Optional[Any] = ..., checkfirst: bool = ...): ...
    def drop(self, bind: Optional[Any] = ..., checkfirst: bool = ...): ...

colspecs: Dict[type_api.TypeEngine[Any], type_api.TypeEngine[Any]]
ischema_names: Dict[str, type_api.TypeEngine[Any]]

class PGCompiler(compiler.SQLCompiler):
    def visit_array(self, element: Any, **kw: Any): ...
    def visit_slice(self, element: Any, **kw: Any): ...
    def visit_json_getitem_op_binary(self, binary: Any, operator: Any, **kw: Any): ...
    def visit_json_path_getitem_op_binary(
        self, binary: Any, operator: Any, **kw: Any
    ): ...
    def visit_getitem_binary(self, binary: Any, operator: Any, **kw: Any): ...
    def visit_aggregate_order_by(self, element: Any, **kw: Any): ...
    def visit_match_op_binary(self, binary: Any, operator: Any, **kw: Any): ...
    def visit_ilike_op_binary(self, binary: Any, operator: Any, **kw: Any): ...
    def visit_notilike_op_binary(self, binary: Any, operator: Any, **kw: Any): ...
    def render_literal_value(self, value: Any, type_: Any): ...
    def visit_sequence(self, sequence: Any, **kw: Any) -> str: ...
    def limit_clause(self, select: Any, **kw: Any): ...
    def format_from_hint_text(
        self, sqltext: Any, table: Any, hint: Any, iscrud: Any
    ): ...
    def get_select_precolumns(self, select: Any, **kw: Any): ...
    def for_update_clause(self, select: Any, **kw: Any): ...
    def returning_clause(self, stmt: Any, returning_cols: Any): ...
    def visit_substring_func(self, func: Any, **kw: Any): ...
    def visit_on_conflict_do_nothing(self, on_conflict: Any, **kw: Any): ...
    def visit_on_conflict_do_update(self, on_conflict: Any, **kw: Any): ...
    def update_from_clause(
        self,
        update_stmt: Any,
        from_table: Any,
        extra_froms: Any,
        from_hints: Any,
        **kw: Any
    ): ...
    def delete_extra_from_clause(
        self,
        update_stmt: Any,
        from_table: Any,
        extra_froms: Any,
        from_hints: Any,
        **kw: Any
    ) -> str: ...

class PGDDLCompiler(compiler.DDLCompiler):
    def get_column_specification(self, column: Any, **kwargs: Any): ...
    def visit_create_enum_type(self, create: Any): ...
    def visit_drop_enum_type(self, drop: Any): ...
    # Signature of visit_create_index incompatible with supertype "DDLCompiler"
    def visit_create_index(self, create: Any) -> str: ...  # type: ignore
    def visit_drop_index(self, drop: Any): ...
    def visit_exclude_constraint(self, constraint: Any, **kw: Any): ...
    def post_create_table(self, table: Any): ...

class PGTypeCompiler(compiler.GenericTypeCompiler):
    def visit_TSVECTOR(self, type: Any, **kw: Any): ...
    def visit_INET(self, type_: Any, **kw: Any): ...
    def visit_CIDR(self, type_: Any, **kw: Any): ...
    def visit_MACADDR(self, type_: Any, **kw: Any): ...
    def visit_MONEY(self, type_: Any, **kw: Any): ...
    def visit_OID(self, type_: Any, **kw: Any): ...
    def visit_REGCLASS(self, type_: Any, **kw: Any): ...
    def visit_FLOAT(self, type_: Any, **kw: Any): ...
    def visit_DOUBLE_PRECISION(self, type_: Any, **kw: Any): ...
    def visit_BIGINT(self, type_: Any, **kw: Any): ...
    def visit_HSTORE(self, type_: Any, **kw: Any): ...
    def visit_JSON(self, type_: Any, **kw: Any): ...
    def visit_JSONB(self, type_: Any, **kw: Any): ...
    def visit_INT4RANGE(self, type_: Any, **kw: Any): ...
    def visit_INT8RANGE(self, type_: Any, **kw: Any): ...
    def visit_NUMRANGE(self, type_: Any, **kw: Any): ...
    def visit_DATERANGE(self, type_: Any, **kw: Any): ...
    def visit_TSRANGE(self, type_: Any, **kw: Any): ...
    def visit_TSTZRANGE(self, type_: Any, **kw: Any): ...
    def visit_datetime(self, type_: Any, **kw: Any): ...
    def visit_enum(self, type_: Any, **kw: Any): ...
    def visit_ENUM(self, type_: Any, **kw: Any): ...
    def visit_TIMESTAMP(self, type_: Any, **kw: Any): ...
    def visit_TIME(self, type_: Any, **kw: Any): ...
    def visit_INTERVAL(self, type_: Any, **kw: Any): ...
    def visit_BIT(self, type_: Any, **kw: Any): ...
    def visit_UUID(self, type_: Any, **kw: Any): ...
    def visit_large_binary(self, type_: Any, **kw: Any): ...
    def visit_BYTEA(self, type_: Any, **kw: Any): ...
    def visit_ARRAY(self, type_: Any, **kw: Any): ...

class PGIdentifierPreparer(compiler.IdentifierPreparer):
    reserved_words: Any = ...
    def format_type(self, type_: Any, use_schema: bool = ...): ...

class PGInspector(reflection.Inspector):
    def __init__(self, conn: Any) -> None: ...
    def get_table_oid(self, table_name: Any, schema: Optional[Any] = ...): ...
    def get_enums(self, schema: Optional[Any] = ...): ...
    def get_foreign_table_names(self, schema: Optional[Any] = ...): ...
    def get_view_names(self, schema: Optional[Any] = ..., include: Any = ...): ...

class CreateEnumType(schema._CreateDropBase[str]):
    __visit_name__: str = ...

class DropEnumType(schema._CreateDropBase[str]):
    __visit_name__: str = ...

class PGExecutionContext(default.DefaultExecutionContext):
    def fire_sequence(self, seq: Any, type_: Any): ...
    def get_insert_default(self, column: Any): ...
    def should_autocommit_text(self, statement: Any): ...

class PGDialect(default.DefaultDialect):
    name: str = ...
    supports_alter: bool = ...
    max_identifier_length: int = ...
    supports_sane_rowcount: bool = ...
    supports_native_enum: bool = ...
    supports_native_boolean: bool = ...
    supports_smallserial: bool = ...
    supports_sequences: bool = ...
    sequences_optional: bool = ...
    preexecute_autoincrement_sequences: bool = ...
    postfetch_lastrowid: bool = ...
    supports_comments: bool = ...
    supports_default_values: bool = ...
    supports_empty_insert: bool = ...
    supports_multivalues_insert: bool = ...
    default_paramstyle: str = ...
    ischema_names: Any = ...
    colspecs: Any = ...
    statement_compiler: Any = ...
    ddl_compiler: Any = ...
    type_compiler: Any = ...
    preparer: Any = ...
    execution_ctx_cls: Any = ...
    inspector: Any = ...
    isolation_level: Any = ...
    construct_arguments: Any = ...
    reflection_options: Any = ...
    def __init__(
        self,
        isolation_level: Optional[Any] = ...,
        json_serializer: Optional[Any] = ...,
        json_deserializer: Optional[Any] = ...,
        **kwargs: Any
    ) -> None: ...
    implicit_returning: Any = ...
    def initialize(self, connection: Any) -> None: ...
    def on_connect(self): ...
    def set_isolation_level(self, connection: Any, level: Any) -> None: ...
    def get_isolation_level(self, connection: Any): ...
    def do_begin_twophase(self, connection: Any, xid: Any) -> None: ...
    def do_prepare_twophase(self, connection: Any, xid: Any) -> None: ...
    def do_rollback_twophase(
        self, connection: Any, xid: Any, is_prepared: bool = ..., recover: bool = ...
    ) -> None: ...
    def do_commit_twophase(
        self, connection: Any, xid: Any, is_prepared: bool = ..., recover: bool = ...
    ) -> None: ...
    def do_recover_twophase(self, connection: Any): ...
    def has_schema(self, connection: Any, schema: Any): ...
    def has_table(
        self, connection: Any, table_name: Any, schema: Optional[Any] = ...
    ): ...
    def has_sequence(
        self, connection: Any, sequence_name: Any, schema: Optional[Any] = ...
    ): ...
    def has_type(
        self, connection: Any, type_name: Any, schema: Optional[Any] = ...
    ): ...
    def get_table_oid(
        self, connection: Any, table_name: Any, schema: Optional[Any] = ..., **kw: Any
    ): ...
    def get_schema_names(self, connection: Any, **kw: Any): ...
    def get_table_names(
        self, connection: Any, schema: Optional[Any] = ..., **kw: Any
    ): ...
    def get_view_names(
        self,
        connection: Any,
        schema: Optional[Any] = ...,
        include: Any = ...,
        **kw: Any
    ): ...
    def get_view_definition(
        self, connection: Any, view_name: Any, schema: Optional[Any] = ..., **kw: Any
    ): ...
    def get_columns(
        self, connection: Any, table_name: Any, schema: Optional[Any] = ..., **kw: Any
    ): ...
    def get_pk_constraint(
        self, connection: Any, table_name: Any, schema: Optional[Any] = ..., **kw: Any
    ): ...
    def get_foreign_keys(
        self,
        connection: Any,
        table_name: Any,
        schema: Optional[Any] = ...,
        postgresql_ignore_search_path: bool = ...,
        **kw: Any
    ): ...
    def get_indexes(
        self, connection: Any, table_name: Any, schema: Optional[Any] = ..., **kw: Any
    ): ...
    def get_unique_constraints(
        self, connection: Any, table_name: Any, schema: Optional[Any] = ..., **kw: Any
    ): ...
    def get_table_comment(
        self, connection: Any, table_name: Any, schema: Optional[Any] = ..., **kw: Any
    ): ...
    def get_check_constraints(
        self, connection: Any, table_name: Any, schema: Optional[Any] = ..., **kw: Any
    ): ...
