# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""
This file defines the underlying db used by SAPP library.
"""

import logging
from contextlib import contextmanager
from typing import Any, Iterator, Optional, Type

import sqlalchemy
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import scoped_session, Session, sessionmaker
from sqlalchemy.pool import AssertionPool, Pool

from . import errors
from .decorators import retryable

LOG: logging.Logger = logging.getLogger("sapp")


class DBType(sqlalchemy.Enum):
    XDB = "xdb"  # not yet implemented
    SQLITE = "sqlite"
    MEMORY = "memory"


class DB:
    """Interact with the database type requested"""

    """File-based DB when using SQLITE"""
    DEFAULT_DB_FILE = "sapp.db"

    def __init__(
        self,
        dbtype: str,
        dbname: Optional[str] = None,
        debug: bool = False,
        read_only: bool = False,
        assertions: bool = False,
    ) -> None:
        self.dbtype = dbtype
        self.dbname: str = dbname or self.DEFAULT_DB_FILE
        self.debug = debug
        self.read_only = read_only
        self.assertions = assertions
        self.engine: Engine

        self.poolclass: Optional[Type[Pool]] = AssertionPool if assertions else None

        if dbtype == DBType.MEMORY:
            self.engine = sqlalchemy.create_engine(
                sqlalchemy.engine.url.URL("sqlite", database=":memory:"),
                echo=debug,
                poolclass=self.poolclass,
            )
        elif dbtype == DBType.SQLITE:
            self.engine = sqlalchemy.create_engine(
                sqlalchemy.engine.url.URL("sqlite", database=self.dbname),
                echo=debug,
                poolclass=self.poolclass,
            )
        elif dbtype == DBType.XDB:
            self._create_xdb_engine()
        else:
            raise errors.AIException(f"Invalid db type: {dbtype}")

    def is_local_only(self) -> bool:
        return self.dbtype == DBType.MEMORY or self.dbtype == DBType.SQLITE

    def _create_xdb_engine(self) -> None:
        raise NotImplementedError

    @contextmanager
    def make_session(self, *args: Any, **kwargs: Any) -> Iterator[Session]:
        session = self.make_session_object(*args, **kwargs)
        try:
            yield session
        finally:
            self.close_session(session)

    @retryable(num_tries=2, retryable_exs=[OperationalError])
    def make_session_object(self, *args: Any, **kwargs: Any) -> Session:
        # use scoped_session so sessionmaker generates the same session in
        # different threads. This is useful for UTs.
        session = scoped_session(sessionmaker(bind=self.engine))(*args, **kwargs)
        ping_db(session)
        if self.dbtype == DBType.XDB:
            # Make sure SQL doesn't quit on us after 10s. Sometimes merging data takes
            # longer.
            session.execute("SET SESSION wait_timeout = %d" % 60)

        return session

    @retryable(num_tries=2, retryable_exs=[OperationalError])
    def close_session(self, session: Session) -> None:
        session.close()


def ping_db(session: Session) -> None:
    session.execute("SELECT 1")
