# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from unittest import TestCase

from tools.sapp.sapp.models import IssueDBID

from ..db import DB, DBType
from ..models import create as create_tables, Issue, PrimaryKey, PrimaryKeyGenerator

from .fake_object_generator import FakeObjectGenerator


class PrimaryKeyGeneratorTest(TestCase):
    def setUp(self) -> None:
        self.db = DB(DBType.MEMORY)
        create_tables(self.db)
        self.fakes = FakeObjectGenerator()

    def test_empty_database_init(self) -> None:
        with self.db.make_session() as session:
            generator = PrimaryKeyGenerator()
            generator.reserve(session, [Issue], {Issue.__name__: 10})

            key_row = session.query(PrimaryKey).one()

            # We should have reserved ids [1, 10] and written 10 as the last used id
            self.assertEqual(key_row.current_id, 10)
            self.assertEqual(key_row.table_name, "Issue")

    def test_backfill_from_highest_value(self) -> None:
        with self.db.make_session() as session:
            # Bypass the bulk saver to avoid creating PrimaryKey rows
            # to simulate a backfill scenario
            session.add(
                Issue(
                    id=IssueDBID(4),
                    handle="1",
                    code=6015,
                    callable_id=11111,
                    detected_time=10,
                )
            )
            session.add(
                Issue(
                    id=IssueDBID(7),
                    handle="2",
                    code=6015,
                    callable_id=11111,
                    detected_time=10,
                )
            )
            session.commit()
            self.assertEqual(session.query(PrimaryKey).count(), 0)

            generator = PrimaryKeyGenerator()
            generator.reserve(session, [Issue], {Issue.__name__: 3})

            key_row = session.query(PrimaryKey).one()
            # We should have seen the highest pre-existing Issue id of 7,
            # reserved [8, 10] and written 10 as the last used id
            self.assertEqual(key_row.current_id, 10)
            self.assertEqual(key_row.table_name, "Issue")

    def test_two_generators(self) -> None:
        with self.db.make_session() as session:
            generator1 = PrimaryKeyGenerator()
            generator1.reserve(session, [Issue], {Issue.__name__: 2})

            key_row = session.query(PrimaryKey).one()
            self.assertEqual(key_row.current_id, 2)

            generator2 = PrimaryKeyGenerator()
            generator2.reserve(session, [Issue], {Issue.__name__: 2})

            key_row = session.query(PrimaryKey).one()
            self.assertEqual(key_row.current_id, 4)

        # It doesn't matter which order get is called in, each generator
        # should only vend ids it has reserved itself
        self.assertEquals(generator2.get(Issue), 3)
        self.assertEquals(generator1.get(Issue), 1)
        self.assertEquals(generator1.get(Issue), 2)
        self.assertEquals(generator2.get(Issue), 4)

        # Generators should never vend ids beyond what they reserved
        with self.assertRaisesRegex(AssertionError, "range exhausted"):
            generator2.get(Issue)
