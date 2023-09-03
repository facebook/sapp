from typing import Any

from . import default as default
from .base import (
    Connection as Connection,
    Engine as Engine,
    NestedTransaction as NestedTransaction,
    RootTransaction as RootTransaction,
    Transaction as Transaction,
    TwoPhaseTransaction as TwoPhaseTransaction,
)
from .interfaces import (
    Compiled as Compiled,
    Connectable as Connectable,
    CreateEnginePlugin as CreateEnginePlugin,
    Dialect as Dialect,
    ExceptionContext as ExceptionContext,
    ExecutionContext as ExecutionContext,
    TypeCompiler as TypeCompiler,
)
from .result import (
    BaseRowProxy as BaseRowProxy,
    BufferedColumnResultProxy as BufferedColumnResultProxy,
    BufferedColumnRow as BufferedColumnRow,
    BufferedRowResultProxy as BufferedRowResultProxy,
    FullyBufferedResultProxy as FullyBufferedResultProxy,
    ResultProxy as ResultProxy,
    RowProxy as RowProxy,
)

def create_engine(*args: Any, **kwargs: Any) -> Engine: ...
def engine_from_config(
    configuration: Any, prefix: str = ..., **kwargs: Any
) -> Engine: ...
