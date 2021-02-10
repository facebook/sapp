from typing import Any, Optional

class PoolListener(object):
    def connect(self, dbapi_con, con_record): ...
    def first_connect(self, dbapi_con, con_record): ...
    def checkout(self, dbapi_con, con_record, con_proxy): ...
    def checkin(self, dbapi_con, con_record): ...

class ConnectionProxy(object):
    def execute(self, conn, execute, clauseelement, *multiparams, **params): ...
    def cursor_execute(
        self, execute, cursor, statement, parameters, context, executemany
    ): ...
    def begin(self, conn, begin): ...
    def rollback(self, conn, rollback): ...
    def commit(self, conn, commit): ...
    def savepoint(self, conn, savepoint, name: Optional[Any] = ...): ...
    def rollback_savepoint(self, conn, rollback_savepoint, name, context): ...
    def release_savepoint(self, conn, release_savepoint, name, context): ...
    def begin_twophase(self, conn, begin_twophase, xid): ...
    def prepare_twophase(self, conn, prepare_twophase, xid): ...
    def rollback_twophase(self, conn, rollback_twophase, xid, is_prepared): ...
    def commit_twophase(self, conn, commit_twophase, xid, is_prepared): ...
