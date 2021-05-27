# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import json
import logging
from pathlib import Path

from sqlalchemy import Table
from sqlalchemy.engine import Connection

from . import models
from .db import DB
from .models import WarningMessage

log: logging.Logger = logging.getLogger()


def upsert_entry(
    database_connection: Connection,
    warning_messages_table: Table,
    code: int,
    message: str,
) -> None:
    warning = database_connection.execute(
        warning_messages_table.select().where(warning_messages_table.c.code == code)
    ).first()

    if warning and warning.message != message:
        database_connection.execute(
            warning_messages_table.update()
            .where(warning_messages_table.c.code == code)
            .values(message=message)
        )
        log.info(f"Updated - {code}: {message}")
    elif not warning:
        database_connection.execute(
            warning_messages_table.insert().values(code=code, message=message)
        )
        log.info(f"Added - {code}: {message}")


def update_warning_messages(database: DB, metadata_file: Path) -> None:
    warning_messages_from_metadata_file = json.loads(metadata_file.read_text())["codes"]
    warning_messages = {
        int(code): message
        for code, message in warning_messages_from_metadata_file.items()
    }

    # TODO(T89343050)
    models.create(database)

    warning_messages_table = Table(
        WarningMessage.__tablename__, WarningMessage.metadata
    )

    with database.make_session() as session:
        with session.connection() as database_connection:
            for code, message in warning_messages.items():
                upsert_entry(database_connection, warning_messages_table, code, message)
            session.commit()
