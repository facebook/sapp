import json
import pathlib
from unittest import TestCase

from ..db import DB, DBType
from ..models import WarningMessage, create as create_model
from ..warning_messages import update_warning_messages
from .fake_object_generator import FakeObjectGenerator

test_metadata = {
    "codes": {
        "1001": "Updated warning message from test",
        "1002": "Updated warning message from test 2",
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

    def testUpdateWarningMessages(self):
        with self.db.make_session() as session:
            update_warning_messages(self.db, pathlib.Path("sample_metadata.json"))
            self.assertEqual(
                session.query(WarningMessage)
                .filter(WarningMessage.code == "1001")
                .first()
                .message,
                "Updated warning message from test",
            )
            self.assertEqual(
                session.query(WarningMessage)
                .filter(WarningMessage.code == "1002")
                .first()
                .message,
                "Updated warning message from test 2",
            )
