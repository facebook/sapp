# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from unittest import TestCase

from ..db import DB, DBType
from ..db_support import DBID, dbid_resolution_context
from ..models import create as create_tables, SharedText, SharedTextKind


class DBSupportTest(TestCase):
    def setUp(self) -> None:
        DBID.enforce_dbid_freezing = True

    def test_dbid_basic(self) -> None:
        primary_key = DBID()
        foreign_key = DBID(primary_key)

        primary_key.resolve(42)

        self.assertEqual(primary_key.resolved(), 42)
        self.assertEqual(foreign_key.resolved(), 42)

    def test_dbid_reassign_final(self) -> None:
        primary_key = DBID()
        primary_key.resolve(1)
        with self.assertRaisesRegex(ValueError, "Cannot reassign"):
            primary_key.resolve(2)
        self.assertEqual(primary_key.resolved(), 1)

    def test_dbid_reassign_provisional(self) -> None:
        primary_key = DBID()
        primary_key.resolve_provisional(1)
        primary_key.resolve(2)
        self.assertEqual(primary_key.resolved(), 2)

    def test_dbid_initialized_to_none(self) -> None:
        primary_key = DBID()
        self.assertIsNone(primary_key._id)
        self.assertIsNone(primary_key.resolved_allow_provisional())

    def test_dbid_initialized_to_value(self) -> None:
        primary_key = DBID(2)
        self.assertEqual(primary_key.resolved(), 2)

    def test_dbid_resolution_context(self) -> None:
        primary_key = DBID()
        foreign_key = DBID(primary_key)
        with dbid_resolution_context():
            primary_key.resolve(1)
            self.assertEqual(primary_key.resolved(), 1)
            self.assertEqual(foreign_key.resolved(), 1)
        self.assertIsNone(primary_key._id)
        self.assertEqual(foreign_key._id, primary_key)
        primary_key.resolve_provisional(2)
        with dbid_resolution_context():
            primary_key.resolve(3)
            self.assertEqual(primary_key.resolved(), 3)
            self.assertEqual(foreign_key.resolved(), 3)
        self.assertEqual(primary_key.resolved_allow_provisional(), 2)
        self.assertEqual(foreign_key.resolved_allow_provisional(), 2)

    def test_merge_by_key_duplicate_in_database(self) -> None:
        db = DB(DBType.MEMORY)
        create_tables(db)

        with db.make_session() as session:
            session.add(
                SharedText(id=DBID(5), contents="A", kind=SharedTextKind.feature)
            )
            session.commit()

        a_id = DBID()
        a = SharedText.Record(id=a_id, contents="A", kind=SharedTextKind.feature)

        b_id = DBID()
        b = SharedText.Record(id=b_id, contents="B", kind=SharedTextKind.feature)

        merged = list(SharedText.merge(db, [a, b]))
        # Merging should not return "a" as it is already in the database
        self.assertEqual(merged, [b])

        # Merging should have resolved "a_id" to match the record in the database
        self.assertEqual(a_id.resolved(), 5)

    def test_merge_by_key_duplicate_in_items(self) -> None:
        db = DB(DBType.MEMORY)
        create_tables(db)

        a_id = DBID()
        a = SharedText.Record(id=a_id, contents="A", kind=SharedTextKind.feature)

        b1_id = DBID()
        b1 = SharedText.Record(id=b1_id, contents="B", kind=SharedTextKind.feature)
        b2_id = DBID()
        b2 = SharedText.Record(id=b2_id, contents="B", kind=SharedTextKind.feature)

        merged = list(SharedText.merge(db, [a, b1, b2]))
        # Merging should not return "b2" as it is duplicated with "b1"
        self.assertEqual(merged, [a, b1])

        # Merging should have resolved "b2_id" to point to "b1_id"
        self.assertEqual(b2_id._id, b1_id)
        b1_id.resolve(3)
        self.assertEqual(b2_id.resolved(), 3)

    def test_freezing_detects_out_of_order_writes(self) -> None:
        issue_id = DBID()
        instance_issue_id = issue_id

        issue_id.resolve_provisional(2)

        with self.assertRaisesRegex(ValueError, "was not frozen before being resolved"):
            instance_issue_id.resolved()

        issue_id.resolve(1)
        self.assertEqual(issue_id.resolved(), 1)
