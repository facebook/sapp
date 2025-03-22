# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from unittest import TestCase

from ..db import DB, DBType
from ..models import (
    create as create_tables,
    DBID,
    Issue,
    IssueDBID,
    PrimaryKey,
    PrimaryKeyGenerator,
    SharedText,
    TraceFrame,
)
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
                    callable_id=DBID(11111),
                    detected_time=10,
                )
            )
            session.add(
                Issue(
                    id=IssueDBID(7),
                    handle="2",
                    code=6015,
                    callable_id=DBID(11111),
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

    def test_pk_generator(self) -> None:
        with self.db.make_session() as session:
            pk_gen = PrimaryKeyGenerator().reserve(
                session,
                [SharedText],
                {SharedText.__name__: 2},
            )
        self.assertEqual(pk_gen.get(SharedText), 1)
        self.assertEqual(pk_gen.get(SharedText), 2)

    def test_pk_gen_failures(self) -> None:
        with self.db.make_session() as session:
            pk_gen = PrimaryKeyGenerator().reserve(session, [SharedText])
        with self.assertRaises(AssertionError):
            pk_gen.get(TraceFrame)
        self.assertEqual(pk_gen.get(SharedText), 1)
        with self.assertRaises(AssertionError):
            pk_gen.get(SharedText)

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
        self.assertEqual(generator2.get(Issue), 3)
        self.assertEqual(generator1.get(Issue), 1)
        self.assertEqual(generator1.get(Issue), 2)
        self.assertEqual(generator2.get(Issue), 4)

        # Generators should never vend ids beyond what they reserved
        with self.assertRaisesRegex(AssertionError, "range exhausted"):
            generator2.get(Issue)

    def test_allowed_id_range_with_empty_databse(self) -> None:
        with self.db.make_session() as session:
            generator = PrimaryKeyGenerator(allowed_id_range=range(150, 200))
            generator.reserve(session, [Issue], {Issue.__name__: 10})

            key_row = session.query(PrimaryKey).one()

            # We should have reserved ids [150, 159] and written 159 as the last used id
            self.assertEqual(key_row.current_id, 159)
            self.assertEqual(key_row.table_name, "Issue")

    def test_allowed_id_range_with_two_generators(self) -> None:
        with self.db.make_session() as session:
            generator1 = PrimaryKeyGenerator(allowed_id_range=range(150, 200))
            generator1.reserve(session, [Issue], {Issue.__name__: 2})

            key_row = session.query(PrimaryKey).one()
            self.assertEqual(key_row.current_id, 151)

            generator2 = PrimaryKeyGenerator(allowed_id_range=range(150, 200))
            generator2.reserve(session, [Issue], {Issue.__name__: 2})

            key_row = session.query(PrimaryKey).one()
            self.assertEqual(key_row.current_id, 153)

        # It doesn't matter which order get is called in, each generator
        # should only vend ids it has reserved itself
        self.assertEqual(generator2.get(Issue), 152)
        self.assertEqual(generator1.get(Issue), 150)
        self.assertEqual(generator1.get(Issue), 151)
        self.assertEqual(generator2.get(Issue), 153)

        with self.assertRaisesRegex(AssertionError, "range exhausted"):
            generator2.get(Issue)

    def test_allowed_id_range_with_overflow(self) -> None:
        with self.db.make_session() as session:
            generator = PrimaryKeyGenerator(allowed_id_range=range(150, 200))

            with self.assertRaisesRegex(
                AssertionError, "would be outside the allowed range"
            ):
                generator.reserve(session, [Issue], {Issue.__name__: 100})

    def test_allowed_id_range_existing_data_outside_allowed_range(
        self,
    ) -> None:
        with self.db.make_session() as session:
            # Bypass the bulk saver to avoid creating PrimaryKey rows
            # to simulate a backfill scenario
            session.add(
                Issue(
                    id=IssueDBID(4),
                    handle="1",
                    code=6015,
                    callable_id=DBID(11111),
                    detected_time=10,
                )
            )
            session.add(
                Issue(
                    id=IssueDBID(7),
                    handle="2",
                    code=6015,
                    callable_id=DBID(11111),
                    detected_time=10,
                )
            )
            session.commit()
            self.assertEqual(session.query(PrimaryKey).count(), 0)

            generator = PrimaryKeyGenerator(allowed_id_range=range(150, 200))

            with self.assertRaisesRegex(
                AssertionError, "already outside of the allowed range"
            ):
                generator.reserve(session, [Issue], {Issue.__name__: 10})

    def test_allowed_id_range_old_allocation_outside_allowed_range(
        self,
    ) -> None:
        with self.db.make_session() as session:
            generator = PrimaryKeyGenerator(allowed_id_range=range(150, 200))
            generator.reserve(session, [Issue], {Issue.__name__: 10})

        with self.db.make_session() as session:
            generator = PrimaryKeyGenerator(allowed_id_range=range(400, 500))
            with self.assertRaisesRegex(
                AssertionError, "would be outside the allowed range"
            ):
                generator.reserve(session, [Issue], {Issue.__name__: 10})
