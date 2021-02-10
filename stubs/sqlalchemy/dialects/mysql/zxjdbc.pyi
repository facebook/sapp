# Stubs for sqlalchemy.dialects.mysql.zxjdbc (Python 3.6)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any
from ...connectors.zxJDBC import ZxJDBCConnector as ZxJDBCConnector
from .base import (
    BIT as BIT,
    MySQLDialect as MySQLDialect,
    MySQLExecutionContext as MySQLExecutionContext,
)

class _ZxJDBCBit(BIT):
    def result_processor(self, dialect, coltype): ...

class MySQLExecutionContext_zxjdbc(MySQLExecutionContext):
    def get_lastrowid(self): ...

class MySQLDialect_zxjdbc(ZxJDBCConnector, MySQLDialect):
    jdbc_db_name: str = ...
    jdbc_driver_name: str = ...
    execution_ctx_cls: Any = ...
    colspecs: Any = ...

dialect: Any = ...