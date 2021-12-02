# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import json
import pathlib
import tempfile
from contextlib import ExitStack
from unittest import TestCase

from sqlalchemy import Table

from ..db import DB, DBType
from ..models import WarningMessage, create as create_model
from ..warning_messages import update_warning_messages, upsert_entry

test_metadata = {
    "codes": {
        "1001": "Updated warning message from test",
        "1002": "Updated warning message from test 2",
    },
    "codes2": {
        "2001": "Updated warning message from another test",
        "2002": "Updated warning message from another test 2",
    },
}


class WarningMessagesTest(TestCase):
    def setUp(self) -> None:
        self.db = DB(DBType.MEMORY)
        create_model(self.db)

    def test_update_warning_messages(self) -> None:
        with ExitStack() as stack:
            temp = stack.enter_context(tempfile.NamedTemporaryFile(mode="w+"))
            json.dump(test_metadata, temp)
            session = stack.enter_context(self.db.make_session())
            update_warning_messages(self.db, pathlib.Path(temp.name))
            code1001 = (
                session.query(WarningMessage).filter_by(code="1001").one_or_none()
            )
            code1002 = (
                session.query(WarningMessage).filter_by(code="1002").one_or_none()
            )
            self.assertIsNotNone(code1001)
            self.assertEqual(
                code1001.message,
                test_metadata["codes"]["1001"],
            )
            self.assertIsNotNone(code1002)
            self.assertEqual(
                code1002.message,
                test_metadata["codes"]["1002"],
            )

    def test_upsert_entry(self) -> None:
        warning_messages_table = Table(
            WarningMessage.__tablename__, WarningMessage.metadata
        )
        codes = test_metadata["codes2"]
        with self.db.make_session() as session:
            with session.connection() as database_connection:
                for code, message in codes.items():
                    # Test for insertion
                    upsert_entry(
                        database_connection, warning_messages_table, int(code), message
                    )

                self.assertEqual(
                    database_connection.execute(
                        warning_messages_table.select().where(
                            warning_messages_table.c.code == "2001"
                        )
                    )
                    .first()
                    .message,
                    "Updated warning message from another test",
                )
                self.assertEqual(
                    database_connection.execute(
                        warning_messages_table.select().where(
                            warning_messages_table.c.code == "2002"
                        )
                    )
                    .first()
                    .message,
                    "Updated warning message from another test 2",
                )
                # Test for Updation
                upsert_entry(
                    database_connection, warning_messages_table, 2001, "Testing Update"
                )
                self.assertEqual(
                    database_connection.execute(
                        warning_messages_table.select().where(
                            warning_messages_table.c.code == "2001"
                        )
                    )
                    .first()
                    .message,
                    "Testing Update",
                )
