from typing import Any, Optional, Union

from sqlalchemy.schema import DDLElement, DefaultGenerator
from sqlalchemy.sql.expression import ClauseElement
from sqlalchemy.sql.functions import FunctionElement

from ..sql.compiler import Compiled as Compiled, TypeCompiler as TypeCompiler
from .base import Connection
from .result import ResultProxy

class Dialect(object):
    @property
    def name(self) -> str: ...
    def create_connect_args(self, url): ...
    @classmethod
    def type_descriptor(cls, typeobj): ...
    def initialize(self, connection): ...
    def reflecttable(self, connection, table, include_columns, exclude_columns): ...
    def get_columns(
        self, connection, table_name, schema: Optional[Any] = ..., **kw
    ): ...
    def get_primary_keys(
        self, connection, table_name, schema: Optional[Any] = ..., **kw
    ): ...
    def get_pk_constraint(
        self, connection, table_name, schema: Optional[Any] = ..., **kw
    ): ...
    def get_foreign_keys(
        self, connection, table_name, schema: Optional[Any] = ..., **kw
    ): ...
    def get_table_names(self, connection, schema: Optional[Any] = ..., **kw): ...
    def get_temp_table_names(self, connection, schema: Optional[Any] = ..., **kw): ...
    def get_view_names(self, connection, schema: Optional[Any] = ..., **kw): ...
    def get_temp_view_names(self, connection, schema: Optional[Any] = ..., **kw): ...
    def get_view_definition(
        self, connection, view_name, schema: Optional[Any] = ..., **kw
    ): ...
    def get_indexes(
        self, connection, table_name, schema: Optional[Any] = ..., **kw
    ): ...
    def get_unique_constraints(
        self, connection, table_name, schema: Optional[Any] = ..., **kw
    ): ...
    def get_check_constraints(
        self, connection, table_name, schema: Optional[Any] = ..., **kw
    ): ...
    def normalize_name(self, name): ...
    def denormalize_name(self, name): ...
    def has_table(self, connection, table_name, schema: Optional[Any] = ...): ...
    def has_sequence(self, connection, sequence_name, schema: Optional[Any] = ...): ...
    def do_begin(self, dbapi_connection): ...
    def do_rollback(self, dbapi_connection): ...
    def do_commit(self, dbapi_connection): ...
    def do_close(self, dbapi_connection): ...
    def create_xid(self): ...
    def do_savepoint(self, connection, name): ...
    def do_rollback_to_savepoint(self, connection, name): ...
    def do_release_savepoint(self, connection, name): ...
    def do_begin_twophase(self, connection, xid): ...
    def do_prepare_twophase(self, connection, xid): ...
    def do_rollback_twophase(
        self, connection, xid, is_prepared: bool = ..., recover: bool = ...
    ): ...
    def do_commit_twophase(
        self, connection, xid, is_prepared: bool = ..., recover: bool = ...
    ): ...
    def do_recover_twophase(self, connection): ...
    def do_executemany(
        self, cursor, statement, parameters, context: Optional[Any] = ...
    ): ...
    def do_execute(
        self, cursor, statement, parameters, context: Optional[Any] = ...
    ): ...
    def do_execute_no_params(
        self, cursor, statement, parameters, context: Optional[Any] = ...
    ): ...
    def is_disconnect(self, e, connection, cursor): ...
    def connect(self): ...
    def reset_isolation_level(self, dbapi_conn): ...
    def set_isolation_level(self, dbapi_conn, level): ...
    def get_isolation_level(self, dbapi_conn): ...
    @classmethod
    def get_dialect_cls(cls, url): ...
    @classmethod
    def engine_created(cls, engine): ...

class CreateEnginePlugin(object):
    url: Any = ...
    def __init__(self, url, kwargs) -> None: ...
    def handle_dialect_kwargs(self, dialect_cls, dialect_args): ...
    def handle_pool_kwargs(self, pool_cls, pool_args): ...
    def engine_created(self, engine): ...

class ExecutionContext(object):
    exception: Any = ...
    is_disconnect: bool = ...
    def create_cursor(self): ...
    def pre_exec(self): ...
    def post_exec(self): ...
    def result(self): ...
    def handle_dbapi_exception(self, e): ...
    def should_autocommit_text(self, statement): ...
    def lastrow_has_defaults(self): ...
    def get_rowcount(self): ...

class Connectable(object):
    def connect(self, **kwargs: Any) -> Connection: ...
    def contextual_connect(self) -> Connection: ...
    def create(self, entity, **kwargs): ...
    def drop(self, entity, **kwargs): ...
    def execute(
        self,
        object: Union[
            str, ClauseElement, FunctionElement, DDLElement, DefaultGenerator, Compiled
        ],
        *multiparams: Any,
        **params: Any
    ) -> ResultProxy: ...
    def scalar(self, object, *multiparams: Any, **params: Any) -> Any: ...

class ExceptionContext(object):
    connection: Any = ...
    engine: Any = ...
    cursor: Any = ...
    statement: Any = ...
    parameters: Any = ...
    original_exception: Any = ...
    sqlalchemy_exception: Any = ...
    chained_exception: Any = ...
    execution_context: Any = ...
    is_disconnect: bool = ...
    invalidate_pool_on_disconnect: bool = ...
