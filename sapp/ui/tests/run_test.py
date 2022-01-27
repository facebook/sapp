# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from unittest import TestCase

from ...db import DB, DBType
from ...models import (
    create as create_models,
)
from ...tests.fake_object_generator import FakeObjectGenerator
from ..run import EmptyDeletionError, delete_run, runs, latest


class RunTest(TestCase):
    def setUp(self) -> None:
        self.db = DB(DBType.MEMORY)
        create_models(self.db)
        self.fakes = FakeObjectGenerator()

        if self.shortDescription() == "No setUp":
            # setUp does not run if the test has docstring "No setUp"
            return

        run1 = self.fakes.run()
        run2 = self.fakes.run()
        run3 = self.fakes.run()

        with self.db.make_session() as session:
            session.add(run1)
            session.add(run2)
            session.add(run3)
            session.commit()

    def testRuns(self) -> None:
        with self.db.make_session() as session:
            allruns = runs(session)

            self.assertEqual(len(allruns), 3)
            # pyre-ignore[6]: graphene too dynamic.
            self.assertEqual(int(allruns[0].run_id), 3)
            # pyre-ignore[6]: graphene too dynamic.
            self.assertEqual(int(allruns[1].run_id), 2)
            # pyre-ignore[6]: graphene too dynamic.
            self.assertEqual(int(allruns[2].run_id), 1)

    def testLatestRun(self) -> None:
        with self.db.make_session() as session:
            id = latest(session)
            self.assertEqual(int(id), 3)

    def testLatestRunWithNoRuns(self) -> None:
        """No setUp"""
        with self.db.make_session() as session:
            id = latest(session)
            self.assertEqual(str(id), "None")

    def testDeleteRun(self) -> None:
        with self.db.make_session() as session:
            delete_run(session, "1")
            remainingRuns = runs(session)
            # pyre-ignore[6]: graphene too dynamic.
            remainingRunsId = [int(r.run_id) for r in remainingRuns]
            self.assertEqual(len(remainingRuns), 2)
            self.assertNotIn(1, remainingRunsId)

    def testDeleteNonExistentRun(self) -> None:
        with self.db.make_session() as session:
            self.assertRaises(EmptyDeletionError, delete_run, session, 10)
            allruns = runs(session)
            self.assertEqual(len(allruns), 3)
