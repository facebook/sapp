# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from unittest import TestCase

from pyre_extensions import none_throws

from ..db import DB, DBType

from ..models import create as create_tables, Issue, IssueInstance, PrimaryKey

from .fake_object_generator import FakeObjectGenerator


class BulkSaverTest(TestCase):
    def setUp(self) -> None:
        self.db = DB(DBType.MEMORY)
        create_tables(self.db)
        self.fakes = FakeObjectGenerator()

    def test_duplicate_issue_handle_race(self) -> None:
        # Simulate another "speedy" run of the script racing us and inserting
        # an issue with the same handle after we merge duplicates but
        # before we do the bulk insert
        speedy_penguin_id = None

        def insert_duplicate() -> None:
            other_fakes = FakeObjectGenerator()
            other_fakes.issue(handle="penguin")
            other_fakes.save_all(self.db)

            with self.db.make_session() as session:
                nonlocal speedy_penguin_id
                speedy_penguin_id = (
                    session.query(Issue).filter(Issue.handle == "penguin").one()
                ).id.resolved()

        slow_penguin = self.fakes.issue(handle="penguin")
        # Create a few other issues to make sure those save correctly too
        for _ in range(9):
            self.fakes.issue()
        self.fakes.instance(issue_id=slow_penguin.id)

        self.fakes.save_all(self.db, before_save=insert_duplicate)
        speedy_penguin_id = none_throws(speedy_penguin_id)

        with self.db.make_session() as session:
            issues = session.query(Issue).all()
            db_penguin = session.query(Issue).filter(Issue.handle == "penguin").one()
            db_instance = session.query(IssueInstance).one()

        # Expect 10 total issues (9 normal + 1 pengin)
        self.assertEqual(len(issues), 10)

        # The ids of the pengin objects should all be resolved to the same value
        self.assertEqual(slow_penguin.id.resolved(), speedy_penguin_id)
        self.assertEqual(db_penguin.id.resolved(), speedy_penguin_id)

        # The issue instance must end up pointing at the same id too
        self.assertEqual(db_instance.issue_id.resolved(), speedy_penguin_id)

    def test_duplicate_class_type_interval_key(self) -> None:
        # The `_save_batch` retry logic should fail here since ClassTypeInterval.merge
        # has no logic to merge duplicate records with the same (run_id, class_name)
        self.fakes.class_type_interval(run_id=1, class_name="Foo")
        self.fakes.class_type_interval(run_id=1, class_name="Foo")

        with self.assertRaisesRegex(
            ValueError, "was not resolved by ClassTypeInterval.merge"
        ):
            self.fakes.save_all(self.db)

    def test_backfill_primary_keys(self) -> None:
        # PrimaryKeyGenerator should be able to backfill the `primary_keys` table
        # with the highest existing ID values after the table is deleted
        issue1 = self.fakes.issue()
        self.fakes.instance(issue_id=issue1.id)
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.query(PrimaryKey).delete()
            session.commit()

        issue2 = self.fakes.issue()
        self.fakes.instance(issue_id=issue2.id)
        self.fakes.save_all(self.db)
