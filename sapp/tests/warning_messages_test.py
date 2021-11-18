import json
import pathlib
from unittest import TestCase

from sqlalchemy import Table

from ..db import DB, DBType
from ..models import WarningMessage, create as create_model
from ..warning_messages import update_warning_messages, upsert_entry
from .fake_object_generator import FakeObjectGenerator

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
        self.fakes = FakeObjectGenerator()

        with open("sample_metadata.json", "w") as outfile:
            json.dump(test_metadata, outfile)

    def tearDown(self) -> None:
        pathlib.Path("sample_metadata.json").unlink()

    def test_update_warning_messages(self) -> None:
        with self.db.make_session() as session:
            update_warning_messages(self.db, pathlib.Path("sample_metadata.json"))
            self.assertEqual(
                session.query(WarningMessage)
                .filter(WarningMessage.code == "1001")
                .first()
                .__dict__["message"],
                test_metadata["codes"]["1001"],
            )
            self.assertEqual(
                session.query(WarningMessage)
                .filter(WarningMessage.code == "1002")
                .first()
                .__dict__["message"],
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
