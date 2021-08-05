from typing import Any

from . import default as default
from .base import Connection as Connection
from .base import Engine as Engine
from .base import NestedTransaction as NestedTransaction
from .base import RootTransaction as RootTransaction
from .base import Transaction as Transaction
from .base import TwoPhaseTransaction as TwoPhaseTransaction
from .interfaces import Compiled as Compiled
from .interfaces import Connectable as Connectable
from .interfaces import CreateEnginePlugin as CreateEnginePlugin
from .interfaces import Dialect as Dialect
from .interfaces import ExceptionContext as ExceptionContext
from .interfaces import ExecutionContext as ExecutionContext
from .interfaces import TypeCompiler as TypeCompiler
from .result import BaseRowProxy as BaseRowProxy
from .result import BufferedColumnResultProxy as BufferedColumnResultProxy
from .result import BufferedColumnRow as BufferedColumnRow
from .result import BufferedRowResultProxy as BufferedRowResultProxy
from .result import FullyBufferedResultProxy as FullyBufferedResultProxy
from .result import ResultProxy as ResultProxy
from .result import RowProxy as RowProxy

def create_engine(*args: Any, **kwargs: Any) -> Engine: ...
def engine_from_config(
    configuration: Any, prefix: str = ..., **kwargs: Any
) -> Engine: ...
