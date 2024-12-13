#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import os
import sys
from datetime import datetime
from io import StringIO
from typing import cast, List, Union
from unittest import TestCase
from unittest.mock import mock_open, patch

from sqlalchemy.orm import Session

from ...db import DB, DBType
from ...decorators import UserError
from ...models import (
    create as create_models,
    DBID,
    IssueInstanceSharedTextAssoc,
    IssueInstanceTraceFrameAssoc,
    IssueStatus,
    Run,
    RunStatus,
    SharedText,
    SharedTextKind,
    SourceLocation,
    TraceFrame,
    TraceFrameLeafAssoc,
    TraceKind,
)
from ...pipeline.pysa_taint_parser import Parser
from ...tests.fake_object_generator import FakeObjectGenerator
from ..interactive import (
    Interactive,
    IssueQueryResult,
    TraceFrameQueryResult,
    TraceTuple,
)


class InteractiveTest(TestCase):
    def setUp(self) -> None:
        self.db = DB(DBType.MEMORY)
        create_models(self.db)
        self.interactive = Interactive(
            database=self.db, repository_directory="", parser_class=Parser
        )
        self.stdout = StringIO()
        self.stderr = StringIO()
        sys.stdout = self.stdout  # redirect output
        sys.stderr = self.stderr  # redirect output
        self.fakes = FakeObjectGenerator()

    def tearDown(self) -> None:
        sys.stdout = sys.__stdout__  # reset redirect
        sys.stderr = sys.__stderr__  # reset redirect

    def _clear_stdout(self) -> None:
        self.stdout = StringIO()
        sys.stdout = self.stdout

    def _add_to_session(
        self,
        session: Session,
        data: Union[List[IssueInstanceSharedTextAssoc], List[Run], List[SharedText]],
    ) -> None:
        if not isinstance(data, list):
            session.add(data)
            return

        for row in data:
            session.add(row)

    def _frame_to_query_result(
        self, session: Session, trace_frame: TraceFrame
    ) -> TraceFrameQueryResult:
        caller = (
            session.query(SharedText.contents)
            .filter(SharedText.id == trace_frame.caller_id)
            .scalar()
        )
        callee = (
            session.query(SharedText.contents)
            .filter(SharedText.id == trace_frame.callee_id)
            .scalar()
        )
        filename = (
            session.query(SharedText.contents)
            .filter(SharedText.id == trace_frame.filename_id)
            .scalar()
        )
        return TraceFrameQueryResult(
            id=trace_frame.id,
            caller=caller,
            caller_port=trace_frame.caller_port,
            callee=callee,
            callee_port=trace_frame.callee_port,
            caller_id=trace_frame.caller_id,
            callee_id=trace_frame.callee_id,
            callee_location=trace_frame.callee_location,
            # pyre-fixme[6]: For 9th param expected `Optional[TraceKind]` but got `str`.
            kind=trace_frame.kind,
            filename=filename,
        )

    def testState(self) -> None:
        self.interactive._current_run_id = DBID(1)
        self.interactive.current_issue_instance_id = DBID(2)
        self.interactive.current_frame_id = DBID(3)
        self.interactive.sources = {"1"}
        self.interactive.sinks = {"2"}

        self.interactive.state()
        output = self.stdout.getvalue()
        self.assertIn("Database: memory:sapp.db", output)
        self.assertIn("Repository directory: ", output)
        self.assertIn("Current run: 1", output)
        self.assertIn("Current issue instance: 2", output)
        self.assertIn("Current trace frame: 3", output)
        self.assertIn("Sources filter: {'1'}", output)
        self.assertIn("Sinks filter: {'2'}", output)

    def testListIssuesBasic(self) -> None:
        run = self.fakes.run()
        self.fakes.issue(callable="module.function1")
        self.fakes.instance(
            message="message1", filename="file.py", callable="module.function1"
        )
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        self.interactive.setup()
        self.interactive.issues()
        output = self.stdout.getvalue().strip()

        self.assertIn("Issue 1", output)
        self.assertIn("Code: 6016", output)
        self.assertIn("Message: message1", output)
        self.assertIn("Callable: module.function1", output)
        self.assertIn("Location: file.py:6|7|8", output)

    def testListIssuesFromLatestRun(self) -> None:
        self.fakes.issue()
        run1 = self.fakes.run()
        self.fakes.instance()  # part of run1
        self.fakes.save_all(self.db)  # early flush to resolve DBID's

        run2 = self.fakes.run()
        self.fakes.instance()  # part of run2
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run1)
            session.add(run2)
            session.commit()

        self.interactive.setup()
        self.interactive.issues()
        output = self.stdout.getvalue().strip()

        self.assertNotIn("Issue 1", output)
        self.assertIn("Issue 2", output)

    def _list_issues_filter_setup(self) -> None:
        run = self.fakes.run()

        issue1 = self.fakes.issue(status="do_not_care", callable="module.sub.function1")
        self.fakes.instance(
            issue_id=issue1.id,
            callable="module.sub.function1",
            filename="module/sub.py",
            min_trace_length_to_sources=1,
            min_trace_length_to_sinks=1,
        )
        self.fakes.save_all(self.db)

        issue2 = self.fakes.issue(status="valid_bug", callable="module.sub.function2")
        self.fakes.instance(
            issue_id=issue2.id,
            callable="module.sub.function2",
            filename="module/sub.py",
            min_trace_length_to_sources=2,
            min_trace_length_to_sinks=2,
        )
        self.fakes.save_all(self.db)

        issue3 = self.fakes.issue(status="bad_practice", callable="module.function3")
        self.fakes.instance(
            issue_id=issue3.id,
            callable="module.function3",
            filename="module/__init__.py",
            min_trace_length_to_sources=3,
            min_trace_length_to_sinks=3,
        )
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

    def testListIssuesFilterCodes(self) -> None:
        self._list_issues_filter_setup()

        self.interactive.setup()
        # pyre-ignore[6]: Intentional wrong type for testing.
        self.interactive.issues(codes="a string")
        stderr = self.stderr.getvalue().strip()
        self.assertIn("'codes' should be", stderr)

        self.interactive.issues(codes=6016)
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertNotIn("Issue 2", output)
        self.assertNotIn("Issue 3", output)

        self._clear_stdout()
        self.interactive.issues(codes=[6017, 6018])
        output = self.stdout.getvalue().strip()
        self.assertNotIn("Issue 1", output)
        self.assertIn("Issue 2", output)
        self.assertIn("Issue 3", output)

    def testListIssuesFilterCallables(self) -> None:
        self._list_issues_filter_setup()

        self.interactive.setup()
        # pyre-ignore[6]: Intentional wrong type for testing.
        self.interactive.issues(callables=1234)
        stderr = self.stderr.getvalue().strip()
        self.assertIn("'callables' should be", stderr)

        self.interactive.issues(callables="%sub%")
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertIn("Issue 2", output)
        self.assertNotIn("Issue 3", output)

        self._clear_stdout()
        self.interactive.issues(callables=["%function3"])
        output = self.stdout.getvalue().strip()
        self.assertNotIn("Issue 1", output)
        self.assertNotIn("Issue 2", output)
        self.assertIn("Issue 3", output)

    def testListIssuesFilterFilenames(self) -> None:
        self._list_issues_filter_setup()

        self.interactive.setup()
        # pyre-ignore[6]: Intentional wrong type for testing.
        self.interactive.issues(filenames=1234)
        stderr = self.stderr.getvalue().strip()
        self.assertIn("'filenames' should be", stderr)

        self.interactive.issues(filenames="module/s%")
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertIn("Issue 2", output)
        self.assertNotIn("Issue 3", output)

        self._clear_stdout()
        self.interactive.issues(filenames=["%__init__.py"])
        output = self.stdout.getvalue().strip()
        self.assertNotIn("Issue 1", output)
        self.assertNotIn("Issue 2", output)
        self.assertIn("Issue 3", output)

    def testListIssuesFilterMinTraceLength(self) -> None:
        self._list_issues_filter_setup()

        self.interactive.setup()

        # pyre-ignore[6]: Intentional wrong type for testing.
        self.interactive.issues(exact_trace_length_to_sources="1")
        stderr = self.stderr.getvalue().strip()
        self.assertIn("'exact_trace_length_to_sources' should be", stderr)
        self._clear_stdout()

        # pyre-ignore[6]: Intentional wrong type for testing.
        self.interactive.issues(exact_trace_length_to_sinks="1")
        stderr = self.stderr.getvalue().strip()
        self.assertIn("'exact_trace_length_to_sinks' should be", stderr)
        self._clear_stdout()

        # pyre-ignore[6]: Intentional wrong type for testing.
        self.interactive.issues(max_trace_length_to_sources="1")
        stderr = self.stderr.getvalue().strip()
        self.assertIn("'max_trace_length_to_sources' should be", stderr)
        self._clear_stdout()

        # pyre-ignore[6]: Intentional wrong type for testing.
        self.interactive.issues(max_trace_length_to_sinks="1")
        stderr = self.stderr.getvalue().strip()
        self.assertIn("'max_trace_length_to_sinks' should be", stderr)
        self._clear_stdout()

        self.interactive.issues(
            exact_trace_length_to_sources=1, max_trace_length_to_sources=1
        )
        stderr = self.stderr.getvalue().strip()
        self.assertIn("can't be set together", stderr)
        self._clear_stdout()

        self.interactive.issues(
            exact_trace_length_to_sinks=1, max_trace_length_to_sinks=1
        )
        stderr = self.stderr.getvalue().strip()
        self.assertIn("can't be set together", stderr)
        self._clear_stdout()

        self.interactive.issues(exact_trace_length_to_sources=1)
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertNotIn("Issue 2", output)
        self.assertNotIn("Issue 3", output)
        self._clear_stdout()

        self.interactive.issues(exact_trace_length_to_sinks=1)
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertNotIn("Issue 2", output)
        self.assertNotIn("Issue 3", output)
        self._clear_stdout()

        self.interactive.issues(max_trace_length_to_sources=1)
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertNotIn("Issue 2", output)
        self.assertNotIn("Issue 3", output)
        self._clear_stdout()

        self.interactive.issues(max_trace_length_to_sinks=1)
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertNotIn("Issue 2", output)
        self.assertNotIn("Issue 3", output)
        self._clear_stdout()

        self.interactive.issues(max_trace_length_to_sources=2)
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertIn("Issue 2", output)
        self.assertNotIn("Issue 3", output)
        self._clear_stdout()

        self.interactive.issues(max_trace_length_to_sinks=2)
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertIn("Issue 2", output)
        self.assertNotIn("Issue 3", output)
        self._clear_stdout()

        self.interactive.issues(
            max_trace_length_to_sources=1, max_trace_length_to_sinks=1
        )
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertNotIn("Issue 2", output)
        self.assertNotIn("Issue 3", output)
        self._clear_stdout()

        self.interactive.issues(
            max_trace_length_to_sources=1, max_trace_length_to_sinks=2
        )
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertNotIn("Issue 2", output)
        self.assertNotIn("Issue 3", output)
        self._clear_stdout()

    def testListIssuesFilterAllFeature(self) -> None:
        self._list_issues_filter_setup()

        self.fakes.instance()
        feature1 = self.fakes.feature("via:feature1")
        feature2 = self.fakes.feature("via:feature2")
        self.fakes.feature("via:feature3")

        self.fakes.save_all(self.db)

        assocs = [
            IssueInstanceSharedTextAssoc(
                shared_text_id=feature1.id, issue_instance_id=DBID(1)
            ),
            IssueInstanceSharedTextAssoc(
                shared_text_id=feature2.id, issue_instance_id=DBID(1)
            ),
        ]

        with self.db.make_session() as session:
            self._add_to_session(session, assocs)
            session.commit()
            self.interactive.setup()

            self.interactive.issues(all_features="via:feature1")
            output = self.stdout.getvalue().strip()
            self.assertIn("Issue 1", output)

            self._clear_stdout()
            self.interactive.issues(all_features=["via:feature1", "via:feature2"])
            output = self.stdout.getvalue().strip()
            self.assertIn("Issue 1", output)

            self._clear_stdout()
            self.interactive.issues(all_features=["via:feature3"])
            output = self.stdout.getvalue().strip()
            self.assertNotIn("Issue 1", output)

            self._clear_stdout()
            self.interactive.issues(all_features=["via:feature1", "via:feature3"])
            output = self.stdout.getvalue().strip()
            self.assertNotIn("Issue 1", output)

    def testListIssuesFilterAnyFeature(self) -> None:
        self._list_issues_filter_setup()

        self.fakes.instance()
        feature1 = self.fakes.feature("via:feature1")
        feature2 = self.fakes.feature("via:feature2")
        self.fakes.feature("via:feature3")

        self.fakes.save_all(self.db)

        assocs = [
            IssueInstanceSharedTextAssoc(
                shared_text_id=feature1.id, issue_instance_id=DBID(1)
            ),
            IssueInstanceSharedTextAssoc(
                shared_text_id=feature2.id, issue_instance_id=DBID(1)
            ),
        ]

        with self.db.make_session() as session:
            self._add_to_session(session, assocs)
            session.commit()
            self.interactive.setup()

            self.interactive.issues(any_features="via:feature1")
            output = self.stdout.getvalue().strip()
            self.assertIn("Issue 1", output)

            self._clear_stdout()
            self.interactive.issues(any_features=["via:feature1", "via:feature2"])
            output = self.stdout.getvalue().strip()
            self.assertIn("Issue 1", output)

            self._clear_stdout()
            self.interactive.issues(any_features=["via:feature1", "via:feature3"])
            output = self.stdout.getvalue().strip()
            self.assertIn("Issue 1", output)

            self._clear_stdout()
            self.interactive.issues(any_features=["via:feature3"])
            output = self.stdout.getvalue().strip()
            self.assertNotIn("Issue 1", output)

    def testListIssuesFilterExcludeFeature(self) -> None:
        self._list_issues_filter_setup()

        self.fakes.instance()
        feature1 = self.fakes.feature("via:feature1")
        feature2 = self.fakes.feature("via:feature2")
        self.fakes.feature("via:feature3")

        self.fakes.save_all(self.db)

        assocs = [
            IssueInstanceSharedTextAssoc(
                shared_text_id=feature1.id, issue_instance_id=DBID(1)
            ),
            IssueInstanceSharedTextAssoc(
                shared_text_id=feature2.id, issue_instance_id=DBID(1)
            ),
        ]

        with self.db.make_session() as session:
            self._add_to_session(session, assocs)
            session.commit()
            self.interactive.setup()

            self.interactive.issues(exclude_features="via:feature1")
            output = self.stdout.getvalue().strip()
            self.assertNotIn("Issue 1", output)

            self._clear_stdout()
            self.interactive.issues(exclude_features=["via:feature1", "via:feature2"])
            output = self.stdout.getvalue().strip()
            self.assertNotIn("Issue 1", output)

            self._clear_stdout()
            self.interactive.issues(exclude_features=["via:feature1", "via:feature3"])
            output = self.stdout.getvalue().strip()
            self.assertNotIn("Issue 1", output)

            self._clear_stdout()
            self.interactive.issues(exclude_features=["via:feature3"])
            output = self.stdout.getvalue().strip()
            self.assertIn("Issue 1", output)

    def testListIssuesFilterAllFeatureAndAnyFeature(self) -> None:
        self._list_issues_filter_setup()

        feature1 = self.fakes.feature("via:feature1")
        feature2 = self.fakes.feature("via:feature2")
        feature3 = self.fakes.feature("via:feature3")

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            self._add_to_session(
                session,
                [
                    IssueInstanceSharedTextAssoc(
                        shared_text_id=feature1.id, issue_instance_id=DBID(1)
                    ),
                    IssueInstanceSharedTextAssoc(
                        shared_text_id=feature2.id, issue_instance_id=DBID(1)
                    ),
                    IssueInstanceSharedTextAssoc(
                        shared_text_id=feature3.id, issue_instance_id=DBID(1)
                    ),
                    IssueInstanceSharedTextAssoc(
                        shared_text_id=feature1.id, issue_instance_id=DBID(2)
                    ),
                    IssueInstanceSharedTextAssoc(
                        shared_text_id=feature2.id, issue_instance_id=DBID(2)
                    ),
                ],
            )
            session.commit()
            self.interactive.setup()

            self.interactive.issues(
                any_features=["via:feature2", "via:feature3"],
                all_features="via:feature1",
            )
            output = self.stdout.getvalue().strip()
            self.assertIn("Issue 1", output)
            self.assertIn("Issue 2", output)

    def testListIssuesFilterStatuses(self) -> None:
        self._list_issues_filter_setup()

        self.interactive.setup()
        # pyre-ignore[6]: Intentional wrong type for testing.
        self.interactive.issues(statuses=1234)
        stderr = self.stderr.getvalue().strip()
        self.assertIn("'statuses' should be", stderr)

        self.interactive.issues(statuses=["do_not_care", "bad_practice"])
        output = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", output)
        self.assertNotIn("Issue 2", output)
        self.assertIn("Issue 3", output)

    def testNoRunsFound(self) -> None:
        self.interactive.setup()
        stderr = self.stderr.getvalue().strip()
        self.assertIn("No runs found.", stderr)

    def testListRuns(self) -> None:
        runs = [
            Run(id=DBID(1), date=datetime.now(), status=RunStatus.FINISHED),
            Run(id=DBID(2), date=datetime.now(), status=RunStatus.INCOMPLETE),
            Run(id=DBID(3), date=datetime.now(), status=RunStatus.FINISHED),
        ]

        with self.db.make_session() as session:
            self._add_to_session(session, runs)
            session.commit()

        self.interactive.setup()
        self.interactive.runs()
        output = self.stdout.getvalue().strip()

        self.assertIn("Run 1", output)
        self.assertNotIn("Run 2", output)
        self.assertIn("Run 3", output)

    def testSetRun(self) -> None:
        self.fakes.issue()
        run1 = self.fakes.run()
        self.fakes.instance(message="Issue message")
        self.fakes.save_all(self.db)

        run2 = self.fakes.run()
        self.fakes.instance(message="Issue message")
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run1)
            session.add(run2)
            session.commit()

        self.interactive.setup()
        self.interactive.run(cast(DBID, 1))
        self.interactive.issues()
        output = self.stdout.getvalue().strip()

        self.assertIn("Issue 1", output)
        self.assertNotIn("Issue 2", output)

    def testSetRunNonExistent(self) -> None:
        runs = [
            Run(id=DBID(1), date=datetime.now(), status=RunStatus.FINISHED),
            Run(id=DBID(2), date=datetime.now(), status=RunStatus.INCOMPLETE),
        ]

        with self.db.make_session() as session:
            self._add_to_session(session, runs)
            session.commit()

        self.interactive.setup()
        self.interactive.run(cast(DBID, 2))
        self.interactive.run(cast(DBID, 3))
        stderr = self.stderr.getvalue().strip()

        self.assertIn("Run 2 doesn't exist", stderr)
        self.assertIn("Run 3 doesn't exist", stderr)

    def testSetLatestRun(self) -> None:
        runs = [
            Run(id=DBID(1), date=datetime.now(), status=RunStatus.FINISHED, kind="a"),
            Run(id=DBID(2), date=datetime.now(), status=RunStatus.FINISHED, kind="a"),
            Run(id=DBID(3), date=datetime.now(), status=RunStatus.FINISHED, kind="a"),
            Run(id=DBID(4), date=datetime.now(), status=RunStatus.FINISHED, kind="b"),
            Run(id=DBID(5), date=datetime.now(), status=RunStatus.FINISHED, kind="b"),
            Run(id=DBID(6), date=datetime.now(), status=RunStatus.FINISHED, kind="c"),
        ]

        with self.db.make_session() as session:
            self._add_to_session(session, runs)
            session.commit()

        self.interactive.latest_run("c")
        self.assertEqual(int(self.interactive._current_run_id), 6)

        self.interactive.latest_run("b")
        self.assertEqual(int(self.interactive._current_run_id), 5)

        self.interactive.latest_run("a")
        self.assertEqual(int(self.interactive._current_run_id), 3)

        self.interactive.latest_run("d")
        self.assertEqual(int(self.interactive._current_run_id), 3)
        self.assertIn("No runs with kind 'd'", self.stderr.getvalue())

    def testSetIssue(self) -> None:
        run = self.fakes.run()
        self.fakes.issue()
        self.fakes.instance(message="Issue message")
        self.fakes.instance(message="Issue message")
        self.fakes.instance(message="Issue message")
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        self.interactive.setup()

        self.interactive.issue(cast(DBID, 2))
        self.assertEqual(int(self.interactive.current_issue_instance_id), 2)
        stdout = self.stdout.getvalue().strip()
        self.assertNotIn("Issue 1", stdout)
        self.assertIn("Issue 2", stdout)
        self.assertNotIn("Issue 3", stdout)

        self.interactive.issue(cast(DBID, 1))
        self.assertEqual(int(self.interactive.current_issue_instance_id), 1)
        stdout = self.stdout.getvalue().strip()
        self.assertIn("Issue 1", stdout)
        self.assertNotIn("Issue 3", stdout)

    def testSetIssueNonExistent(self) -> None:
        run = self.fakes.run()

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        self.interactive.setup()
        self.interactive.issue(cast(DBID, 1))
        stderr = self.stderr.getvalue().strip()

        self.assertIn("Issue 1 doesn't exist", stderr)

    def testSetIssueUpdatesRun(self) -> None:
        self.fakes.issue()
        run1 = self.fakes.run()
        self.fakes.instance()
        self.fakes.save_all(self.db)

        run2 = self.fakes.run()
        self.fakes.instance()
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run1)
            session.add(run2)
            session.commit()

        self.interactive.setup()
        self.assertEqual(int(self.interactive._current_run_id), 2)
        self.interactive.issue(cast(DBID, 1))
        self.assertEqual(int(self.interactive._current_run_id), 1)

    def testGetSources(self) -> None:
        self.fakes.instance()
        source1 = self.fakes.source("source1")
        source2 = self.fakes.source("source2")
        self.fakes.source("source3")
        self.fakes.save_all(self.db)
        assocs = [
            IssueInstanceSharedTextAssoc(
                shared_text_id=source1.id, issue_instance_id=DBID(1)
            ),
            IssueInstanceSharedTextAssoc(
                shared_text_id=source2.id, issue_instance_id=DBID(1)
            ),
        ]

        with self.db.make_session() as session:
            self._add_to_session(session, assocs)
            session.commit()

            self.interactive.setup()
            sources = self.interactive._get_leaves_issue_instance(
                session,
                # pyre-fixme[6]: For 2nd param expected `DBID` but got `int`.
                1,
                SharedTextKind.SOURCE,
            )

        self.assertEqual(len(sources), 2)
        self.assertIn("source1", sources)
        self.assertIn("source2", sources)

    def testGetSinks(self) -> None:
        self.fakes.instance()
        sink1 = self.fakes.sink("sink1")
        sink2 = self.fakes.sink("sink2")
        self.fakes.sink("sink3")
        self.fakes.save_all(self.db)
        assocs = [
            IssueInstanceSharedTextAssoc(
                shared_text_id=sink1.id, issue_instance_id=DBID(1)
            ),
            IssueInstanceSharedTextAssoc(
                shared_text_id=sink2.id, issue_instance_id=DBID(1)
            ),
        ]

        with self.db.make_session() as session:
            self._add_to_session(session, assocs)
            session.commit()

            self.interactive.setup()
            sinks = self.interactive._get_leaves_issue_instance(
                session,
                # pyre-fixme[6]: For 2nd param expected `DBID` but got `int`.
                1,
                SharedTextKind.SINK,
            )

        self.assertEqual(len(sinks), 2)
        self.assertIn("sink1", sinks)
        self.assertIn("sink2", sinks)

    def testGetFeatures(self) -> None:
        self.fakes.instance()
        feature1 = self.fakes.feature("via:feature1")
        feature2 = self.fakes.feature("via:feature2")
        self.fakes.feature("via:feature3")
        self.fakes.save_all(self.db)
        assocs = [
            IssueInstanceSharedTextAssoc(
                shared_text_id=feature1.id, issue_instance_id=DBID(1)
            ),
            IssueInstanceSharedTextAssoc(
                shared_text_id=feature2.id, issue_instance_id=DBID(1)
            ),
        ]

        with self.db.make_session() as session:
            self._add_to_session(session, assocs)
            session.commit()

            self.interactive.setup()
            features = self.interactive._get_leaves_issue_instance(
                session,
                # pyre-fixme[6]: For 2nd param expected `DBID` but got `int`.
                1,
                SharedTextKind.FEATURE,
            )

        self.assertEqual(len(features), 2)
        self.assertIn("via:feature1", features)
        self.assertIn("via:feature2", features)

    def _basic_trace_frames(self) -> List[TraceFrame]:
        return [
            self.fakes.precondition(
                caller="call1",
                caller_port="root",
                callee="call2",
                callee_port="param0",
                location=(1, 1, 1),
            ),
            self.fakes.precondition(
                caller="call2",
                caller_port="param0",
                callee="leaf",
                callee_port="sink",
                location=(1, 2, 1),
            ),
        ]

    def testCreateTraceTuples(self) -> None:
        # reverse order
        postcondition_traces = [
            (
                TraceFrameQueryResult(
                    id=DBID(1),
                    callee="call3",
                    callee_port="result",
                    filename="file3.py",
                    callee_location=SourceLocation(1, 1, 3),
                    caller="main",
                    caller_port="root",
                ),
                1,
            ),
            (
                TraceFrameQueryResult(
                    id=DBID(2),
                    callee="call2",
                    callee_port="result",
                    caller="dummy caller",
                    caller_port="dummy caller",
                    filename="file2.py",
                    callee_location=SourceLocation(1, 1, 2),
                ),
                2,
            ),
            (
                TraceFrameQueryResult(
                    id=DBID(3),
                    callee="leaf",
                    callee_port="source",
                    caller="dummy caller",
                    caller_port="dummy caller",
                    filename="file1.py",
                    callee_location=SourceLocation(1, 1, 1),
                ),
                3,
            ),
        ]
        trace_tuples = self.interactive._create_trace_tuples(postcondition_traces)
        self.assertEqual(len(trace_tuples), 3)
        self.assertEqual(
            trace_tuples,
            [
                TraceTuple(postcondition_traces[0][0], 1),
                TraceTuple(postcondition_traces[1][0], 2),
                TraceTuple(postcondition_traces[2][0], 3),
            ],
        )

    def testOutputTraceTuples(self) -> None:
        features = [
            SharedText(kind=SharedTextKind.FEATURE, contents="one"),
            SharedText(kind=SharedTextKind.FEATURE, contents="two"),
            SharedText(kind=SharedTextKind.FEATURE, contents="three"),
        ]
        trace_tuples = [
            TraceTuple(
                trace_frame=TraceFrameQueryResult(
                    id=DBID(1),
                    caller="unused",
                    caller_port="unused",
                    callee="leaf",
                    callee_port="source",
                    filename="file1.py",
                    callee_location=SourceLocation(1, 1, 1),
                )
            ),
            TraceTuple(
                trace_frame=TraceFrameQueryResult(
                    id=DBID(2),
                    caller="unused",
                    caller_port="unused",
                    callee="call2",
                    callee_port="result",
                    filename="file2.py",
                    callee_location=SourceLocation(1, 1, 2),
                    shared_texts=[features[0], features[1]],
                )
            ),
            TraceTuple(
                trace_frame=TraceFrameQueryResult(
                    id=DBID(3),
                    caller="unused",
                    caller_port="unused",
                    callee="call3",
                    callee_port="result",
                    filename="file3.py",
                    callee_location=SourceLocation(1, 1, 3),
                )
            ),
            TraceTuple(
                trace_frame=TraceFrameQueryResult(
                    id=DBID(4),
                    caller="unused",
                    caller_port="unused",
                    callee="main",
                    callee_port="root",
                    filename="file4.py",
                    callee_location=SourceLocation(1, 1, 4),
                    shared_texts=[features[1], features[2]],
                )
            ),
            TraceTuple(
                trace_frame=TraceFrameQueryResult(
                    id=DBID(5),
                    caller="unused",
                    caller_port="unused",
                    callee="call4",
                    callee_port="param0",
                    filename="file4.py",
                    callee_location=SourceLocation(1, 1, 4),
                )
            ),
            TraceTuple(
                trace_frame=TraceFrameQueryResult(
                    id=DBID(6),
                    caller="unused",
                    caller_port="unused",
                    callee="call5",
                    callee_port="param1",
                    filename="file5.py",
                    callee_location=SourceLocation(1, 1, 5),
                    shared_texts=[features[0], features[1], features[2]],
                )
            ),
            TraceTuple(
                trace_frame=TraceFrameQueryResult(
                    id=DBID(7),
                    caller="unused",
                    caller_port="unused",
                    callee="leaf",
                    callee_port="sink",
                    filename="file6.py",
                    callee_location=SourceLocation(1, 1, 6),
                )
            ),
        ]
        self.interactive.current_trace_frame_index = 1
        self.interactive._output_trace_tuples(trace_tuples)
        output = self.stdout.getvalue()
        self.assertEqual(
            output.split("\n"),
            [
                "     # ⎇  [callable] [port] [location]",
                "     1    leaf       source file1.py:1|1|1",
                " --> 2    call2      result file2.py:1|1|2",
                "     3    call3      result file3.py:1|1|3",
                "     4    main       root   file4.py:1|1|4",
                "     5    call4      param0 file4.py:1|1|4",
                "     6    call5      param1 file5.py:1|1|5",
                "     7    leaf       sink   file6.py:1|1|6",
                "",
            ],
        )

        self._clear_stdout()
        self.interactive._output_trace_tuples(trace_tuples, True)
        output = self.stdout.getvalue()
        self.assertEqual(
            output.split("\n"),
            [
                "     # ⎇  [callable] [port] [location]",
                "     1    leaf       source file1.py:1|1|1",
                " --> 2    call2      result file2.py:1|1|2",
                "           --F: ['one', 'two']",
                "     3    call3      result file3.py:1|1|3",
                "     4    main       root   file4.py:1|1|4",
                "           --F: ['two', 'three']",
                "     5    call4      param0 file4.py:1|1|4",
                "     6    call5      param1 file5.py:1|1|5",
                "           --F: ['one', 'two', 'three']",
                "     7    leaf       sink   file6.py:1|1|6",
                "",
            ],
        )

        self._clear_stdout()
        self.interactive.current_trace_frame_index = 4
        self.interactive._output_trace_tuples(trace_tuples)
        output = self.stdout.getvalue()
        self.assertEqual(
            output.split("\n"),
            [
                "     # ⎇  [callable] [port] [location]",
                "     1    leaf       source file1.py:1|1|1",
                "     2    call2      result file2.py:1|1|2",
                "     3    call3      result file3.py:1|1|3",
                "     4    main       root   file4.py:1|1|4",
                " --> 5    call4      param0 file4.py:1|1|4",
                "     6    call5      param1 file5.py:1|1|5",
                "     7    leaf       sink   file6.py:1|1|6",
                "",
            ],
        )

        self._clear_stdout()
        self.interactive.current_trace_frame_index = 4
        self.interactive._output_trace_tuples(trace_tuples, True)
        output = self.stdout.getvalue()
        self.assertEqual(
            output.split("\n"),
            [
                "     # ⎇  [callable] [port] [location]",
                "     1    leaf       source file1.py:1|1|1",
                "     2    call2      result file2.py:1|1|2",
                "           --F: ['one', 'two']",
                "     3    call3      result file3.py:1|1|3",
                "     4    main       root   file4.py:1|1|4",
                "           --F: ['two', 'three']",
                " --> 5    call4      param0 file4.py:1|1|4",
                "     6    call5      param1 file5.py:1|1|5",
                "           --F: ['one', 'two', 'three']",
                "     7    leaf       sink   file6.py:1|1|6",
                "",
            ],
        )

    def testTraceFromIssue(self) -> None:
        run = self.fakes.run()
        self.fakes.issue()
        instance = self.fakes.instance()
        source = self.fakes.source()
        frames = [
            self.fakes.postcondition(
                caller="call1",
                caller_port="root",
                callee="leaf",
                callee_port="source",
                location=(1, 1, 1),
            ),
            self.fakes.precondition(
                caller="call1",
                caller_port="root",
                callee="leaf",
                callee_port="sink",
                location=(1, 1, 2),
            ),
        ]
        self.fakes.saver.add_all(
            [
                IssueInstanceTraceFrameAssoc.Record(
                    trace_frame_id=frames[0].id, issue_instance_id=instance.id
                ),
                IssueInstanceTraceFrameAssoc.Record(
                    trace_frame_id=frames[1].id, issue_instance_id=instance.id
                ),
            ]
        )
        self.fakes.saver.add_all(
            [
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[0].id, leaf_id=source.id, trace_length=0
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[1].id, leaf_id=source.id, trace_length=0
                ),
            ]
        )

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        self.interactive.setup()
        self.interactive.trace()
        stderr = self.stderr.getvalue().strip()
        self.assertIn("Use 'issue ID' or 'frame ID'", stderr)

        self.interactive.issue(cast(DBID, 1))
        self._clear_stdout()
        self.interactive.trace()
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                "     # ⎇  [callable]    [port] [location]",
                "     1    leaf          source lib/server/posts/response.py:1|1|1",
                " --> 2    Foo.barMethod root   /r/some/filename.py:6|7|8",
                "     3    leaf          sink   lib/server/posts/request.py:1|1|2",
                "",
            ],
        )

    def testTraceFromFrame(self) -> None:
        run = self.fakes.run()
        frames = self._basic_trace_frames()
        sink = self.fakes.sink("sink")
        self.fakes.saver.add_all(
            [
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[0].id, leaf_id=sink.id, trace_length=1
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[1].id, leaf_id=sink.id, trace_length=0
                ),
            ]
        )
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        self.interactive.setup()
        self.interactive.frame(int(frames[0].id))

        self._clear_stdout()
        self.interactive.trace()
        self.assertEqual(self.interactive.sinks, {"sink"})
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                "     # ⎇  [callable] [port] [location]",
                " --> 1    call1      root   lib/server/posts/request.py:1|1|1",
                "     2    call2      param0 lib/server/posts/request.py:1|1|1",
                "     3    leaf       sink   lib/server/posts/request.py:1|2|1",
                "",
            ],
        )

    def testTraceMissingFrames(self) -> None:
        run = self.fakes.run()
        self.fakes.issue()
        instance = self.fakes.instance()
        source = self.fakes.source()
        frames = [
            self.fakes.postcondition(
                caller="call1",
                caller_port="root",
                callee="leaf",
                callee_port="source",
                location=(1, 1, 1),
            ),
            self.fakes.precondition(
                caller="call1",
                caller_port="root",
                callee="call2",
                callee_port="param0",
                location=(1, 1, 1),
            ),
        ]
        self.fakes.saver.add_all(
            [
                IssueInstanceTraceFrameAssoc.Record(
                    trace_frame_id=frames[0].id, issue_instance_id=instance.id
                ),
                IssueInstanceTraceFrameAssoc.Record(
                    trace_frame_id=frames[1].id, issue_instance_id=instance.id
                ),
            ]
        )
        self.fakes.saver.add_all(
            [
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[0].id, leaf_id=source.id, trace_length=0
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[1].id, leaf_id=source.id, trace_length=0
                ),
            ]
        )
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        self.interactive.setup()
        self.interactive.issue(cast(DBID, 1))
        self.interactive.trace()
        stdout = self.stdout.getvalue().strip()
        self.assertIn("Missing trace frame: call2:param0", stdout)

    def testTraceCursorLocation(self) -> None:
        run = self.fakes.run()
        self.fakes.issue(callable="Issue callable")
        instance = self.fakes.instance(callable="Issue callable")
        source = self.fakes.source()
        frames = [
            self.fakes.postcondition(
                caller="call1",
                caller_port="root",
                callee="leaf",
                callee_port="source",
                location=(1, 1, 1),
            ),
            self.fakes.precondition(
                caller="call1",
                caller_port="root",
                callee="leaf",
                callee_port="sink",
                location=(1, 2, 1),
            ),
        ]
        self.fakes.saver.add_all(
            [
                IssueInstanceTraceFrameAssoc.Record(
                    trace_frame_id=frames[0].id, issue_instance_id=instance.id
                ),
                IssueInstanceTraceFrameAssoc.Record(
                    trace_frame_id=frames[1].id, issue_instance_id=instance.id
                ),
            ]
        )
        self.fakes.saver.add_all(
            [
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[0].id, leaf_id=source.id, trace_length=0
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[1].id, leaf_id=source.id, trace_length=0
                ),
            ]
        )
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        self.interactive.setup()

        self.assertIsNone(self.interactive.callable())

        self.interactive.issue(cast(DBID, 1))
        self.assertEqual(self.interactive.callable(), "Issue callable")
        self.assertEqual(self.interactive.current_trace_frame_index, 1)

        self.interactive.next_cursor_location()
        self.assertEqual(self.interactive.current_trace_frame_index, 2)
        self.assertEqual(self.interactive.callable(), "leaf")
        self.interactive.next_cursor_location()
        self.assertEqual(self.interactive.current_trace_frame_index, 2)
        self.interactive.prev_cursor_location()
        self.assertEqual(self.interactive.current_trace_frame_index, 1)
        self.interactive.prev_cursor_location()
        self.assertEqual(self.interactive.current_trace_frame_index, 0)
        self.interactive.prev_cursor_location()
        self.assertEqual(self.interactive.current_trace_frame_index, 0)

    def testJumpToLocation(self) -> None:
        run = self.fakes.run()
        self.fakes.issue()
        instance = self.fakes.instance()
        source = self.fakes.source()
        frames = [
            self.fakes.postcondition(
                caller="call1", caller_port="root", callee="leaf", callee_port="source"
            ),
            self.fakes.precondition(
                caller="call1", caller_port="root", callee="leaf", callee_port="sink"
            ),
        ]
        self.fakes.saver.add_all(
            [
                IssueInstanceTraceFrameAssoc.Record(
                    trace_frame_id=frames[0].id, issue_instance_id=instance.id
                ),
                IssueInstanceTraceFrameAssoc.Record(
                    trace_frame_id=frames[1].id, issue_instance_id=instance.id
                ),
            ]
        )
        self.fakes.saver.add_all(
            [
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[0].id, leaf_id=source.id, trace_length=0
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[1].id, leaf_id=source.id, trace_length=0
                ),
            ]
        )

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        self.interactive.setup()
        self.interactive.issue(cast(DBID, 1))
        self.assertEqual(self.interactive.current_trace_frame_index, 1)

        self.interactive.jump(1)
        self.assertEqual(self.interactive.current_trace_frame_index, 0)

        self.interactive.jump(3)
        self.assertEqual(self.interactive.current_trace_frame_index, 2)

        self.interactive.jump(4)
        self.assertEqual(self.interactive.current_trace_frame_index, 2)

        self.interactive.jump(0)
        self.assertEqual(self.interactive.current_trace_frame_index, 2)

    def testTraceNoSinks(self) -> None:
        run = self.fakes.run()
        self.fakes.issue()
        instance = self.fakes.instance()
        source = self.fakes.source("source1")
        frame = self.fakes.postcondition(
            caller="call1", caller_port="root", callee="leaf", callee_port="source"
        )
        self.fakes.saver.add(
            IssueInstanceTraceFrameAssoc.Record(
                trace_frame_id=frame.id, issue_instance_id=instance.id
            )
        )
        self.fakes.saver.add(
            TraceFrameLeafAssoc.Record(
                trace_frame_id=frame.id, leaf_id=source.id, trace_length=0
            )
        )

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        self.interactive.setup()
        self.interactive.sources = {"source1"}
        self.interactive.issue(cast(DBID, 1))
        self._clear_stdout()
        self.interactive.trace()
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                "     # ⎇  [callable]    [port] [location]",
                "     1    leaf          source lib/server/posts/response.py:4|5|6",
                " --> 2    Foo.barMethod root   /r/some/filename.py:6|7|8",
                "",
            ],
        )

    def _set_up_branched_trace(self) -> List[TraceFrame]:
        run = self.fakes.run()
        self.fakes.issue()
        instance = self.fakes.instance()
        source = self.fakes.source("source1")
        sink = self.fakes.sink("sink1")
        self.fakes.saver.add_all(
            [
                IssueInstanceSharedTextAssoc.Record(
                    issue_instance_id=instance.id, shared_text_id=source.id
                ),
                IssueInstanceSharedTextAssoc.Record(
                    issue_instance_id=instance.id, shared_text_id=sink.id
                ),
            ]
        )
        frames = []
        for i in range(6):
            if i < 2:  # 2 postconditions
                frames.append(
                    self.fakes.postcondition(
                        caller="call1",
                        caller_port="root",
                        callee="leaf",
                        callee_port="source",
                        location=(i, i, i),
                    )
                )
                self.fakes.saver.add(
                    TraceFrameLeafAssoc.Record(
                        trace_frame_id=frames[-1].id, leaf_id=source.id, trace_length=i
                    )
                )
                self.fakes.saver.add(
                    IssueInstanceTraceFrameAssoc.Record(
                        trace_frame_id=frames[-1].id, issue_instance_id=instance.id
                    )
                )
            elif i < 4:
                frames.append(
                    self.fakes.precondition(
                        caller="call1",
                        caller_port="root",
                        callee="call2",
                        callee_port="param2",
                        location=(i, i, i),
                    )
                )
                self.fakes.saver.add(
                    TraceFrameLeafAssoc.Record(
                        trace_frame_id=frames[-1].id, leaf_id=sink.id, trace_length=i
                    )
                )
                self.fakes.saver.add(
                    IssueInstanceTraceFrameAssoc.Record(
                        trace_frame_id=frames[-1].id, issue_instance_id=instance.id
                    )
                )
            else:
                frames.append(
                    self.fakes.precondition(
                        caller="call2",
                        caller_port="param2",
                        callee="leaf",
                        callee_port="sink",
                        location=(i, i, i),
                    )
                )
                self.fakes.saver.add(
                    TraceFrameLeafAssoc.Record(
                        trace_frame_id=frames[-1].id,
                        leaf_id=sink.id,
                        trace_length=5 - i,
                    )
                )

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        return frames

    def testTraceBranchNumber(self) -> None:
        self._set_up_branched_trace()

        self.interactive.setup()
        self.interactive.issue(cast(DBID, 1))

        self.assertEqual(self.interactive.sources, {"source1"})
        self.assertEqual(self.interactive.sinks, {"sink1"})

        self._clear_stdout()
        self.interactive.trace()
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                "     # ⎇  [callable]    [port] [location]",
                "     1 +2 leaf          source lib/server/posts/response.py:0|0|0",
                " --> 2    Foo.barMethod root   /r/some/filename.py:6|7|8",
                "     3 +2 call2         param2 lib/server/posts/request.py:2|2|2",
                "     4 +2 leaf          sink   lib/server/posts/request.py:5|5|5",
                "",
            ],
        )

    def testShowBranches(self) -> None:
        self._set_up_branched_trace()

        self.interactive.setup()
        self.interactive.issue(cast(DBID, 1))
        # Parent at root
        self.interactive.prev_cursor_location()
        with patch("click.prompt", return_value=0):
            self.interactive.branch()
        output = self.stdout.getvalue().strip()
        self.assertIn(
            "[*] leaf : source\n"
            "        [0 hops: source1]\n"
            "        [lib/server/posts/response.py:0|0|0]",
            output,
        )
        self.assertIn(
            "[2] leaf : source\n"
            "        [1 hops: source1]\n"
            "        [lib/server/posts/response.py:1|1|1]",
            output,
        )

        self._clear_stdout()
        # Move to call2:param2
        self.interactive.next_cursor_location()
        self.interactive.next_cursor_location()
        with patch("click.prompt", return_value=0):
            self.interactive.branch()
        output = self.stdout.getvalue().strip()
        self.assertIn(
            "[*] call2 : param2\n"
            "        [2 hops: sink1]\n"
            "        [lib/server/posts/request.py:2|2|2]",
            output,
        )
        self.assertIn(
            "[2] call2 : param2\n"
            "        [3 hops: sink1]\n"
            "        [lib/server/posts/request.py:3|3|3]",
            output,
        )

        self._clear_stdout()
        # Move to leaf:sink
        self.interactive.next_cursor_location()
        with patch("click.prompt", return_value=0):
            self.interactive.branch()
        output = self.stdout.getvalue().strip()
        self.assertIn(
            "[*] leaf : sink\n"
            "        [0 hops: sink1]\n"
            "        [lib/server/posts/request.py:5|5|5]",
            output,
        )
        self.assertIn(
            "[2] leaf : sink\n"
            "        [1 hops: sink1]\n"
            "        [lib/server/posts/request.py:4|4|4]",
            output,
        )

    def testGetTraceFrameBranches(self) -> None:
        frames = self._set_up_branched_trace()

        self.interactive.setup()
        self.interactive.issue(cast(DBID, 1))
        # Parent at root
        self.interactive.prev_cursor_location()

        with self.db.make_session() as session:
            branches = self.interactive._get_trace_frame_branches(session)
            self.assertEqual(len(branches), 2)
            self.assertEqual(int(branches[0].id), int(frames[0].id))
            self.assertEqual(int(branches[1].id), int(frames[1].id))

            # Parent is no longer root
            self.interactive.next_cursor_location()
            self.interactive.next_cursor_location()
            self.interactive.next_cursor_location()

            branches = self.interactive._get_trace_frame_branches(session)
            self.assertEqual(len(branches), 2)
            self.assertEqual(int(branches[0].id), int(frames[5].id))
            self.assertEqual(int(branches[1].id), int(frames[4].id))

    def testBranch(self) -> None:
        self._set_up_branched_trace()

        self.interactive.setup()
        self.interactive.issue(cast(DBID, 1))
        self.interactive.prev_cursor_location()

        # We are testing for the source location, which differs between branches
        self._clear_stdout()
        self.interactive.branch(2)  # location 0|0|0 -> 1|1|1
        output = self.stdout.getvalue().strip()
        self.assertIn(
            " --> 1 +2 leaf          source lib/server/posts/response.py:1|1|1", output
        )

        self._clear_stdout()
        self.interactive.branch(1)  # location 1|1|1 -> 0|0|0
        output = self.stdout.getvalue().strip()
        self.assertIn(
            " --> 1 +2 leaf          source lib/server/posts/response.py:0|0|0", output
        )

        self.interactive.next_cursor_location()
        self.interactive.next_cursor_location()

        self._clear_stdout()
        self.interactive.branch(2)  # location 2|2|2 -> 3|3|3
        output = self.stdout.getvalue().strip()
        self.assertIn(
            " --> 3 +2 call2         param2 lib/server/posts/request.py:3|3|3", output
        )

        self.interactive.next_cursor_location()

        self._clear_stdout()
        self.interactive.branch(2)  # location 4|4|4 -> 5|5|5
        output = self.stdout.getvalue().strip()
        self.assertIn(
            "     3 +2 call2         param2 lib/server/posts/request.py:3|3|3", output
        )
        self.assertIn(
            " --> 4 +2 leaf          sink   lib/server/posts/request.py:4|4|4", output
        )

        self.interactive.branch(3)  # location 4|4|4 -> 5|5|5
        stderr = self.stderr.getvalue().strip()
        self.assertIn("Branch number invalid", stderr)

    def testBranchPrefixLengthChanges(self) -> None:
        run = self.fakes.run()
        self.fakes.issue()
        instance = self.fakes.instance()
        source = self.fakes.source("source1")
        sink = self.fakes.sink("sink1")
        frames = [
            self.fakes.postcondition(
                caller="call1", caller_port="root", callee="leaf", callee_port="source"
            ),
            self.fakes.postcondition(
                caller="call1",
                caller_port="root",
                callee="prev_call",
                callee_port="result",
            ),
            self.fakes.postcondition(
                caller="prev_call",
                caller_port="result",
                callee="leaf",
                callee_port="source",
            ),
            self.fakes.precondition(
                caller="call1", caller_port="root", callee="leaf", callee_port="sink"
            ),
        ]
        self.fakes.saver.add_all(
            [
                IssueInstanceSharedTextAssoc.Record(
                    issue_instance_id=instance.id, shared_text_id=source.id
                ),
                IssueInstanceSharedTextAssoc.Record(
                    issue_instance_id=instance.id, shared_text_id=sink.id
                ),
            ]
        )
        self.fakes.saver.add_all(
            [
                IssueInstanceTraceFrameAssoc.Record(
                    issue_instance_id=instance.id, trace_frame_id=frames[0].id
                ),
                IssueInstanceTraceFrameAssoc.Record(
                    issue_instance_id=instance.id, trace_frame_id=frames[1].id
                ),
                IssueInstanceTraceFrameAssoc.Record(
                    issue_instance_id=instance.id, trace_frame_id=frames[3].id
                ),
            ]
        )
        self.fakes.saver.add_all(
            [
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[0].id, leaf_id=source.id, trace_length=0
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[1].id, leaf_id=source.id, trace_length=1
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[2].id, leaf_id=source.id, trace_length=0
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[3].id, leaf_id=sink.id, trace_length=0
                ),
            ]
        )

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        self.interactive.setup()
        self.interactive.issue(cast(DBID, 1))

        self._clear_stdout()
        self.interactive.prev_cursor_location()
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                "     # ⎇  [callable]    [port] [location]",
                " --> 1 +2 leaf          source lib/server/posts/response.py:4|5|6",
                "     2    Foo.barMethod root   /r/some/filename.py:6|7|8",
                "     3    leaf          sink   lib/server/posts/request.py:4|5|6",
                "",
            ],
        )

        self._clear_stdout()
        self.interactive.branch(2)
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                "     # ⎇  [callable]    [port] [location]",
                "     1    leaf          source lib/server/posts/response.py:4|5|6",
                " --> 2 +2 prev_call     result lib/server/posts/response.py:4|5|6",
                "     3    Foo.barMethod root   /r/some/filename.py:6|7|8",
                "     4    leaf          sink   lib/server/posts/request.py:4|5|6",
                "",
            ],
        )

        self._clear_stdout()
        with patch("click.prompt", return_value=0):
            self.interactive.branch()
        output = self.stdout.getvalue().strip()
        self.assertIn("[*] prev_call : result", output)
        self.assertIn("        [1 hops: source1]", output)

    def testCurrentBranchIndex(self) -> None:
        # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
        trace_frames = [TraceFrame(id=1), TraceFrame(id=2), TraceFrame(id=3)]

        self.interactive.current_trace_frame_index = 0
        # pyre-fixme[6]: For 1st param expected `TraceFrameQueryResult` but got
        #  `TraceFrame`.
        # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
        self.interactive.trace_tuples = [TraceTuple(trace_frame=TraceFrame(id=1))]

        # pyre-fixme[6]: For 1st param expected `List[TraceFrameQueryResult]` but
        #  got `List[TraceFrame]`.
        self.assertEqual(0, self.interactive._current_branch_index(trace_frames))
        # pyre-fixme[41]: Cannot reassign final attribute `id`.
        self.interactive.trace_tuples[0].trace_frame.id = 2
        # pyre-fixme[6]: For 1st param expected `List[TraceFrameQueryResult]` but
        #  got `List[TraceFrame]`.
        self.assertEqual(1, self.interactive._current_branch_index(trace_frames))
        # pyre-fixme[41]: Cannot reassign final attribute `id`.
        self.interactive.trace_tuples[0].trace_frame.id = 3
        # pyre-fixme[6]: For 1st param expected `List[TraceFrameQueryResult]` but
        #  got `List[TraceFrame]`.
        self.assertEqual(2, self.interactive._current_branch_index(trace_frames))

        # pyre-fixme[41]: Cannot reassign final attribute `id`.
        self.interactive.trace_tuples[0].trace_frame.id = 4
        # pyre-fixme[6]: For 1st param expected `List[TraceFrameQueryResult]` but
        #  got `List[TraceFrame]`.
        self.assertEqual(-1, self.interactive._current_branch_index(trace_frames))

    def testVerifyEntrypointSelected(self) -> None:
        self.interactive.current_issue_instance_id = DBID(-1)
        self.interactive.current_frame_id = DBID(-1)
        with self.assertRaises(UserError):
            self.interactive._verify_entrypoint_selected()

        self.interactive.current_issue_instance_id = DBID(1)
        try:
            self.interactive._verify_entrypoint_selected()
        except UserError:
            self.fail("Unexpected UserError")

        self.interactive.current_issue_instance_id = DBID(-1)
        self.interactive.current_frame_id = DBID(1)
        try:
            self.interactive._verify_entrypoint_selected()
        except UserError:
            self.fail("Unexpected UserError")

        self.interactive.current_issue_instance_id = DBID(1)
        with self.assertRaises(AssertionError):
            self.interactive._verify_entrypoint_selected()

    def testVerifyMultipleBranches(self) -> None:
        self.interactive.current_trace_frame_index = 0
        self.interactive.trace_tuples = [
            # pyre-fixme[6]: For 1st param expected `TraceFrameQueryResult` but got
            #  `TraceFrame`.
            # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
            TraceTuple(trace_frame=TraceFrame(id=1), branches=1),
            # pyre-fixme[6]: For 1st param expected `TraceFrameQueryResult` but got
            #  `TraceFrame`.
            # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
            TraceTuple(trace_frame=TraceFrame(id=2), branches=2),
        ]
        with self.assertRaises(UserError):
            self.interactive._verify_multiple_branches()

        self.interactive.current_trace_frame_index = 1
        try:
            self.interactive._verify_multiple_branches()
        except UserError:
            self.fail("Unexpected UserError")

    def testAddListOrElementFilterErrors(self) -> None:
        with self.assertRaises(UserError):
            self.interactive._add_list_or_element_filter_to_query(
                "not a list",
                # pyre-fixme[6]: For 2nd param expected `Query[Variable[T]]` but got
                #  `None`.
                None,
                # pyre-fixme[6]: For 3rd param expected `InstrumentedAttribute` but
                #  got `None`.
                None,
                "arg0",
                int,
            )

        with self.assertRaises(UserError):
            self.interactive._add_list_or_element_filter_to_query(
                [],
                # pyre-fixme[6]: For 2nd param expected `Query[Variable[T]]` but got
                #  `None`.
                None,
                # pyre-fixme[6]: For 3rd param expected `InstrumentedAttribute` but
                #  got `None`.
                None,
                "arg0",
                str,
            )

    def testAddListOrStringFilterToQuery(self) -> None:
        shared_texts = [
            # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
            SharedText(id=1, contents="prefix"),
            # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
            SharedText(id=2, contents="suffix"),
            # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
            SharedText(id=3, contents="prefix_suffix"),
            # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
            SharedText(id=4, contents="fix"),
        ]

        with self.db.make_session() as session:
            self._add_to_session(session, shared_texts)
            session.commit()

            query = session.query(SharedText.contents)
            self.assertEqual(
                self.interactive._add_list_or_string_filter_to_query(
                    ["prefix", "suffix"],
                    query,
                    # pyre-fixme[6]: For 3rd param expected `InstrumentedAttribute`
                    #  but got `str`.
                    SharedText.contents,
                    "contents",
                ).all(),
                [("prefix",), ("suffix",)],
            )
            self.assertEqual(
                self.interactive._add_list_or_string_filter_to_query(
                    ["%prefix%"],
                    query,
                    # pyre-fixme[6]: For 3rd param expected `InstrumentedAttribute`
                    #  but got `str`.
                    SharedText.contents,
                    "contents",
                ).all(),
                [("prefix",), ("prefix_suffix",)],
            )
            self.assertEqual(
                self.interactive._add_list_or_string_filter_to_query(
                    ["%fix%"],
                    query,
                    # pyre-fixme[6]: For 3rd param expected `InstrumentedAttribute`
                    #  but got `str`.
                    SharedText.contents,
                    "contents",
                ).all(),
                [("prefix",), ("suffix",), ("prefix_suffix",), ("fix",)],
            )

    def testCreateIssueOutputStringNoSourcesNoSinks(self) -> None:
        issue = IssueQueryResult(
            # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
            issue_id=1,
            # pyre-fixme[6]: For 2nd param expected `DBID` but got `int`.
            issue_instance_id=1,
            filename="module.py",
            location=SourceLocation(1, 2, 3),
            code=1000,
            callable="module.function1",
            message="root",
            min_trace_length_to_sources=1,
            min_trace_length_to_sinks=1,
            # pyre-fixme[6]: For 10th param expected `FrozenSet[str]` but got
            #  `Set[Variable[_T]]`.
            features=set(),
            is_new_issue=False,
            # pyre-fixme[6]: For 12th param expected `FrozenSet[str]` but got `None`.
            source_names=None,
            # pyre-fixme[6]: For 13th param expected `FrozenSet[str]` but got `None`.
            source_kinds=None,
            # pyre-fixme[6]: For 14th param expected `FrozenSet[str]` but got `None`.
            sink_names=None,
            # pyre-fixme[6]: For 15th param expected `FrozenSet[str]` but got
            #  `List[str]`.
            sink_kinds=["sink1", "sink2"],
            status=IssueStatus.UNCATEGORIZED.name,
            detected_time=datetime.today(),
            # pyre-fixme[6]: For 18th param expected `Set[SimilarIssue]` but got
            #  `Set[Tuple[int, str]]`.
            similar_issues={(2, "0.24")},
            # pyre-fixme[6]: For 19th param expected `DBID` but got `int`.
            run_id=1,
        )
        sources = []
        sinks = ["sink1", "sink2"]
        features = []
        result = self.interactive._create_issue_output_string(
            issue,
            # pyre-fixme[6]: For 2nd param expected `Set[str]` but got
            #  `List[typing.Any]`.
            sources,
            # pyre-fixme[6]: For 3rd param expected `Set[str]` but got `List[str]`.
            sinks,
            # pyre-fixme[6]: For 4th param expected `Set[str]` but got
            #  `List[typing.Any]`.
            features,
        )
        self.assertIn("Sources: No sources", result)
        self.assertIn("Sinks: sink1", result)

        sources = ["source1", "source2"]
        sinks = []
        result = self.interactive._create_issue_output_string(
            issue,
            # pyre-fixme[6]: For 2nd param expected `Set[str]` but got `List[str]`.
            sources,
            # pyre-fixme[6]: For 3rd param expected `Set[str]` but got
            #  `List[typing.Any]`.
            sinks,
            # pyre-fixme[6]: For 4th param expected `Set[str]` but got
            #  `List[typing.Any]`.
            features,
        )
        self.assertIn("Sources: source1", result)
        self.assertIn("Sinks: No sinks", result)

    def testCreateIssueOutputStringNoFeatures(self) -> None:
        issue = IssueQueryResult(
            # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
            issue_id=1,
            # pyre-fixme[6]: For 2nd param expected `DBID` but got `int`.
            issue_instance_id=1,
            filename="module.py",
            location=SourceLocation(1, 2, 3),
            code=1000,
            callable="module.function1",
            message="root",
            min_trace_length_to_sources=1,
            min_trace_length_to_sinks=1,
            # pyre-fixme[6]: For 10th param expected `FrozenSet[str]` but got
            #  `Set[Variable[_T]]`.
            features=set(),
            is_new_issue=False,
            # pyre-fixme[6]: For 12th param expected `FrozenSet[str]` but got `None`.
            source_names=None,
            # pyre-fixme[6]: For 13th param expected `FrozenSet[str]` but got `None`.
            source_kinds=None,
            # pyre-fixme[6]: For 14th param expected `FrozenSet[str]` but got `None`.
            sink_names=None,
            # pyre-fixme[6]: For 15th param expected `FrozenSet[str]` but got
            #  `List[str]`.
            sink_kinds=["sink1"],
            status=cast(str, IssueStatus.UNCATEGORIZED),
            detected_time=datetime.today(),
            # pyre-fixme[6]: For 18th param expected `Set[SimilarIssue]` but got
            #  `Set[Tuple[int, str]]`.
            similar_issues={(2, "0.24")},
            # pyre-fixme[6]: For 19th param expected `DBID` but got `int`.
            run_id=1,
        )
        sources = []
        sinks = ["sink1"]
        features = []
        result = self.interactive._create_issue_output_string(
            issue,
            # pyre-fixme[6]: For 2nd param expected `Set[str]` but got
            #  `List[typing.Any]`.
            sources,
            # pyre-fixme[6]: For 3rd param expected `Set[str]` but got `List[str]`.
            sinks,
            # pyre-fixme[6]: For 4th param expected `Set[str]` but got
            #  `List[typing.Any]`.
            features,
        )
        self.assertIn("Features: No features", result)

        sources = []
        sinks = ["sink1"]
        features = ["via:feature1"]
        result = self.interactive._create_issue_output_string(
            issue,
            # pyre-fixme[6]: For 2nd param expected `Set[str]` but got
            #  `List[typing.Any]`.
            sources,
            # pyre-fixme[6]: For 3rd param expected `Set[str]` but got `List[str]`.
            sinks,
            # pyre-fixme[6]: For 4th param expected `Set[str]` but got `List[str]`.
            features,
        )
        self.assertIn("Features: via:feature1", result)

    def testCreateIssueOutputStringTraceLength(self) -> None:
        issue1 = IssueQueryResult(
            # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
            issue_id=1,
            # pyre-fixme[6]: For 2nd param expected `DBID` but got `int`.
            issue_instance_id=1,
            filename="module.py",
            location=SourceLocation(1, 2, 3),
            code=1000,
            callable="module.function1",
            message="root",
            min_trace_length_to_sources=0,
            min_trace_length_to_sinks=6,
            # pyre-fixme[6]: For 10th param expected `FrozenSet[str]` but got
            #  `Set[Variable[_T]]`.
            features=set(),
            is_new_issue=False,
            # pyre-fixme[6]: For 12th param expected `FrozenSet[str]` but got `None`.
            source_names=None,
            # pyre-fixme[6]: For 13th param expected `FrozenSet[str]` but got `None`.
            source_kinds=None,
            # pyre-fixme[6]: For 14th param expected `FrozenSet[str]` but got `None`.
            sink_names=None,
            # pyre-fixme[6]: For 15th param expected `FrozenSet[str]` but got
            #  `List[str]`.
            sink_kinds=["sink1", "sink2"],
            status=cast(str, IssueStatus.UNCATEGORIZED),
            detected_time=datetime.today(),
            # pyre-fixme[6]: For 18th param expected `Set[SimilarIssue]` but got
            #  `Set[Tuple[int, str]]`.
            similar_issues={(2, "0.24")},
            # pyre-fixme[6]: For 19th param expected `DBID` but got `int`.
            run_id=1,
        )
        sources = []
        sinks = ["sink1", "sink2"]
        features = []
        result = self.interactive._create_issue_output_string(
            issue1,
            # pyre-fixme[6]: For 2nd param expected `Set[str]` but got
            #  `List[typing.Any]`.
            sources,
            # pyre-fixme[6]: For 3rd param expected `Set[str]` but got `List[str]`.
            sinks,
            # pyre-fixme[6]: For 4th param expected `Set[str]` but got
            #  `List[typing.Any]`.
            features,
        )
        self.assertIn("Min Trace Length: Source (0) | Sink (6)", result)

        issue2 = IssueQueryResult(
            # pyre-fixme[6]: For 1st param expected `DBID` but got `int`.
            issue_id=1,
            # pyre-fixme[6]: For 2nd param expected `DBID` but got `int`.
            issue_instance_id=1,
            filename="module.py",
            location=SourceLocation(1, 2, 3),
            code=1000,
            callable="module.function1",
            message="root",
            min_trace_length_to_sources=3,
            min_trace_length_to_sinks=1,
            # pyre-fixme[6]: For 10th param expected `FrozenSet[str]` but got
            #  `Set[Variable[_T]]`.
            features=set(),
            is_new_issue=False,
            # pyre-fixme[6]: For 12th param expected `FrozenSet[str]` but got `None`.
            source_names=None,
            # pyre-fixme[6]: For 13th param expected `FrozenSet[str]` but got `None`.
            source_kinds=None,
            # pyre-fixme[6]: For 14th param expected `FrozenSet[str]` but got `None`.
            sink_names=None,
            # pyre-fixme[6]: For 15th param expected `FrozenSet[str]` but got
            #  `List[str]`.
            sink_kinds=["sink1", "sink2"],
            status=cast(str, IssueStatus.UNCATEGORIZED),
            detected_time=datetime.today(),
            # pyre-fixme[6]: For 18th param expected `Set[SimilarIssue]` but got
            #  `Set[Tuple[int, str]]`.
            similar_issues={(2, "0.24")},
            # pyre-fixme[6]: For 19th param expected `DBID` but got `int`.
            run_id=1,
        )
        sources = []
        sinks = ["sink1", "sink2"]
        result = self.interactive._create_issue_output_string(
            issue2,
            # pyre-fixme[6]: For 2nd param expected `Set[str]` but got
            #  `List[typing.Any]`.
            sources,
            # pyre-fixme[6]: For 3rd param expected `Set[str]` but got `List[str]`.
            sinks,
            # pyre-fixme[6]: For 4th param expected `Set[str]` but got
            #  `List[typing.Any]`.
            features,
        )
        self.assertIn("Min Trace Length: Source (3) | Sink (1)", result)

    def testListSourceCode(self) -> None:
        mock_data = """if this_is_true:
    print("This was true")
else:
    print("This was false")
        """
        self.interactive.setup()
        # pyre-fixme[8]: Attribute has type `DBID`; used as `int`.
        self.interactive.current_issue_instance_id = 1

        self.interactive.current_trace_frame_index = 0
        self.interactive.trace_tuples = [
            TraceTuple(
                trace_frame=TraceFrameQueryResult(
                    id=DBID(0),
                    filename="file.py",
                    caller="",
                    caller_port="",
                    callee="callee",
                    callee_port="",
                    callee_location=SourceLocation(2, 10, 25),
                ),
                placeholder=True,
            )
        ]
        with patch("builtins.open", mock_open(read_data=mock_data)) as mock_file:
            self._clear_stdout()
            self.interactive.list_source_code(2)
            mock_file.assert_called_once_with(f"{os.getcwd()}/file.py", "r")
            output = self.stdout.getvalue()
            self.assertEqual(
                output.split("\n"),
                [
                    "In callee [file.py:2|10|25]",
                    "     1  if this_is_true:",
                    ' --> 2      print("This was true")',
                    "                  ^^^^^^^^^^^^^^^",
                    "     3  else:",
                    '     4      print("This was false")',
                    "",
                ],
            )

            mock_file.reset_mock()
            self._clear_stdout()
            self.interactive.list_source_code(1)
            mock_file.assert_called_once_with(f"{os.getcwd()}/file.py", "r")
            output = self.stdout.getvalue()
            self.assertEqual(
                output.split("\n"),
                [
                    "In callee [file.py:2|10|25]",
                    "     1  if this_is_true:",
                    ' --> 2      print("This was true")',
                    "                  ^^^^^^^^^^^^^^^",
                    "     3  else:",
                    "",
                ],
            )

    def testListSourceCodeFileNotFound(self) -> None:
        self.interactive.setup()
        # pyre-fixme[8]: Attribute has type `DBID`; used as `int`.
        self.interactive.current_issue_instance_id = 1

        self.interactive.current_trace_frame_index = 0
        self.interactive.trace_tuples = [
            TraceTuple(
                trace_frame=TraceFrameQueryResult(
                    id=DBID(0),
                    caller="",
                    caller_port="",
                    callee="",
                    callee_port="",
                    filename="file.py",
                    callee_location=SourceLocation(2, 1, 1),
                )
            )
        ]
        with patch("builtins.open", mock_open(read_data="not read")) as mock_file:
            mock_file.side_effect = FileNotFoundError()
            self.interactive.list_source_code()
            self.assertIn("Couldn't open", self.stderr.getvalue())
            self.assertNotIn("file.py", self.stdout.getvalue())

    def testGroupTraceFrames(self) -> None:
        trace_frames = [
            TraceFrameQueryResult(
                id=DBID(1),
                caller="caller1",
                caller_port="port1",
                callee="",
                callee_port="",
            ),
            TraceFrameQueryResult(
                id=DBID(2),
                caller="caller1",
                caller_port="port1",
                callee="",
                callee_port="",
            ),
            TraceFrameQueryResult(
                id=DBID(3),
                caller="caller2",
                caller_port="port2",
                callee="",
                callee_port="",
            ),
            TraceFrameQueryResult(
                id=DBID(4),
                caller="caller2",
                caller_port="port2",
                callee="",
                callee_port="",
            ),
            TraceFrameQueryResult(
                id=DBID(5),
                caller="caller2",
                caller_port="port3",
                callee="",
                callee_port="",
            ),
        ]

        buckets = self.interactive._group_trace_frames(trace_frames, 5)

        self.assertEqual(3, len(buckets.keys()))
        self.assertIn(("caller1", "port1"), buckets.keys())
        self.assertIn(("caller2", "port2"), buckets.keys())
        self.assertIn(("caller2", "port3"), buckets.keys())

        self.assertEqual(
            [1, 2], [int(frame.id) for frame in buckets[("caller1", "port1")]]
        )
        self.assertEqual(
            [3, 4], [int(frame.id) for frame in buckets[("caller2", "port2")]]
        )
        self.assertEqual(
            [5], [int(frame.id) for frame in buckets[("caller2", "port3")]]
        )

    def testListTracesBasic(self) -> None:
        self.fakes.run()
        post1 = self.fakes.postcondition(
            caller="caller1", caller_port="port1", callee="callee1", callee_port="port1"
        )
        post2 = self.fakes.postcondition(
            caller="caller1", caller_port="port1", callee="callee2", callee_port="port2"
        )
        post3 = self.fakes.postcondition(
            caller="caller2", caller_port="port2", callee="callee3", callee_port="port3"
        )
        post4 = self.fakes.postcondition(
            caller="caller2", caller_port="port2", callee="callee4", callee_port="port4"
        )
        post5 = self.fakes.postcondition(
            caller="caller2", caller_port="port3", callee="callee5", callee_port="port5"
        )
        self.fakes.save_all(self.db)

        # pyre-fixme[8]: Attribute has type `DBID`; used as `int`.
        self.interactive._current_run_id = 1
        self._clear_stdout()
        self.interactive.frames(kind=TraceKind.POSTCONDITION)
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                "[id] [caller:caller_port -> callee:callee_port]",
                "---- caller1:port1 ->",
                f"{post1.id}        callee1:port1",
                f"{post2.id}        callee2:port2",
                "---- caller2:port2 ->",
                f"{post3.id}        callee3:port3",
                f"{post4.id}        callee4:port4",
                "---- caller2:port3 ->",
                f"{post5.id}        callee5:port5",
                "",
            ],
        )

        self._clear_stdout()
        self.interactive.frames(kind=TraceKind.PRECONDITION)
        self.assertEqual(self.stdout.getvalue().strip(), "No trace frames found.")

    def testListTracesFilterCallersCallees(self) -> None:
        run = self.fakes.run()
        frames = self._basic_trace_frames()
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        # pyre-fixme[8]: Attribute has type `DBID`; used as `int`.
        self.interactive._current_run_id = 1
        self._clear_stdout()
        self.interactive.frames(callers=["call2"])
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                "[id] [caller:caller_port -> callee:callee_port]",
                "---- call2:param0 ->",
                f"{frames[1].id}        leaf:sink",
                "",
            ],
        )

        self._clear_stdout()
        self.interactive.frames(callees=["call2"])
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                "[id] [caller:caller_port -> callee:callee_port]",
                "---- call1:root ->",
                f"{frames[0].id}        call2:param0",
                "",
            ],
        )

    def testListFramesWithLimit(self) -> None:
        frames = self._set_up_branched_trace()
        self.interactive.run(cast(DBID, 1))

        self._clear_stdout()
        self.interactive.frames(limit=3)
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                "[id] [caller:caller_port -> callee:callee_port]",
                "---- call1:root ->",
                f"{frames[2].id}        call2:param2",
                f"{frames[3].id}        call2:param2",
                f"{frames[0].id}        leaf:source",
                "...",
                "Showing 3/6 matching frames. To see more, call 'frames' with "
                "the 'limit' argument.",
                "",
            ],
        )

    def testSetFrame(self) -> None:
        frames = self._basic_trace_frames()
        sink = self.fakes.sink("sink")
        self.fakes.saver.add_all(
            [
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[0].id, leaf_id=sink.id, trace_length=1
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[1].id, leaf_id=sink.id, trace_length=0
                ),
            ]
        )
        self.fakes.save_all(self.db)

        self.interactive.setup()

        self.interactive.frame(0)
        self.assertIn("Trace frame 0 doesn't exist.", self.stderr.getvalue())

        self._clear_stdout()
        self.interactive.frame(1)
        self.assertIn("Trace frame 1", self.stdout.getvalue())
        self.assertNotIn("Trace frame 2", self.stdout.getvalue())

        self._clear_stdout()
        self.interactive.frame(2)
        self.assertNotIn("Trace frame 1", self.stdout.getvalue())
        self.assertIn("Trace frame 2", self.stdout.getvalue())

    def testSetFrameUpdatesRun(self) -> None:
        run1 = self.fakes.run()
        frames = [
            self.fakes.precondition(
                caller="call1",
                caller_port="root",
                callee="call2",
                callee_port="param0",
                location=(1, 1, 1),
            ),
            self.fakes.precondition(
                caller="call2",
                caller_port="param1",
                callee="call3",
                callee_port="param2",
                location=(1, 1, 1),
            ),
        ]
        run2 = self.fakes.run()
        sink = self.fakes.sink("sink1")
        self.fakes.saver.add_all(
            [
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[0].id, leaf_id=sink.id, trace_length=1
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[1].id, leaf_id=sink.id, trace_length=0
                ),
            ]
        )
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run1)
            session.add(run2)
            session.commit()

        self.interactive.setup()
        self.assertEqual(int(self.interactive._current_run_id), 2)
        self.interactive.frame(int(frames[0].id))
        self.assertEqual(int(self.interactive._current_run_id), 1)

    def testIsBeforeRoot(self) -> None:
        self.interactive.trace_tuples = [
            # pyre-fixme[6]: For 1st param expected `TraceFrameQueryResult` but got
            #  `TraceFrame`.
            TraceTuple(trace_frame=TraceFrame(kind=TraceKind.POSTCONDITION)),
            # pyre-fixme[6]: For 1st param expected `TraceFrameQueryResult` but got
            #  `TraceFrame`.
            TraceTuple(trace_frame=TraceFrame(kind=TraceKind.PRECONDITION)),
        ]

        self.interactive.current_trace_frame_index = 0
        self.assertTrue(self.interactive._is_before_root())

        self.interactive.current_trace_frame_index = 1
        self.assertFalse(self.interactive._is_before_root())

    def testIsRootTraceTuple(self) -> None:
        # pyre-fixme[6]: For 1st param expected `TraceFrameQueryResult` but got
        #  `TraceFrame`.
        trace_tuple = TraceTuple(trace_frame=TraceFrame(callee_port="root"))
        self.assertTrue(self.interactive._is_root_trace_tuple(trace_tuple))

        # pyre-fixme[6]: For 1st param expected `TraceFrameQueryResult` but got
        #  `TraceFrame`.
        trace_tuple = TraceTuple(trace_frame=TraceFrame(callee_port="not_root"))
        self.assertFalse(self.interactive._is_root_trace_tuple(trace_tuple))

    def testParents(self) -> None:
        self._set_up_branched_trace()
        self.interactive.setup()

        self.interactive.frame(3)
        self.interactive.current_trace_frame_index = 1

        self._clear_stdout()
        with patch("click.prompt", return_value=0):
            self.interactive.parents()
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            ["[1] call1 : root", "[2] call1 : root", ""],
        )

        self._clear_stdout()
        self.interactive.current_trace_frame_index = 0
        self.interactive.parents()
        self.assertIn("No parents calling", self.stdout.getvalue())

        self.interactive.current_trace_frame_index = 2
        self.interactive.parents()
        self.assertIn("Try running from a non-leaf node", self.stderr.getvalue())

    def testParentsSelectParent(self) -> None:
        self._set_up_branched_trace()
        self.interactive.setup()

        self.interactive.frame(3)
        self.interactive.current_trace_frame_index = 1

        self._clear_stdout()
        with patch("click.prompt", return_value=1):
            self.interactive.parents()
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                "[1] call1 : root",
                "[2] call1 : root",
                "",
                "     # ⎇  [callable] [port] [location]",
                " --> 1    call1      root   lib/server/posts/request.py:2|2|2",
                "     2    call2      param2 lib/server/posts/request.py:2|2|2",
                "     3 +2 leaf       sink   lib/server/posts/request.py:5|5|5",
                "",
            ],
        )

    def testUpdateTraceTuplesNewParent(self) -> None:
        frames = [
            self.fakes.postcondition(callee="A"),
            self.fakes.postcondition(callee="B"),
            self.fakes.postcondition(callee="C"),
            self.fakes.postcondition(callee="D"),
            self.fakes.postcondition(callee="E"),
        ]
        self.fakes.save_all(self.db)

        self.interactive.setup()
        # Test postcondition
        self.interactive.current_trace_frame_index = 2
        with self.db.make_session() as session:
            self.interactive.trace_tuples = [
                TraceTuple(trace_frame=self._frame_to_query_result(session, frames[0])),
                TraceTuple(trace_frame=self._frame_to_query_result(session, frames[1])),
                TraceTuple(trace_frame=self._frame_to_query_result(session, frames[2])),
                TraceTuple(trace_frame=self._frame_to_query_result(session, frames[3])),
                TraceTuple(trace_frame=self._frame_to_query_result(session, frames[4])),
            ]

        trace_frame = TraceFrameQueryResult(
            id=DBID(0),
            caller="caller",
            caller_port="caller_port",
            callee="F",
            callee_port="callee_port",
            filename="file.py",
            callee_location=SourceLocation(1, 1, 1),
            kind=TraceKind.POSTCONDITION,
        )
        self.interactive._update_trace_tuples_new_parent(trace_frame)
        self.assertEqual(self.interactive.current_trace_frame_index, 3)
        self.assertEqual(
            [
                self.interactive._get_callable_from_trace_tuple(trace_tuple)[0]
                for trace_tuple in self.interactive.trace_tuples
            ],
            ["A", "B", "F", "caller"],
        )
        self.assertTrue(self.interactive.trace_tuples[-1].placeholder)

        # Test precondition
        self.interactive.current_trace_frame_index = 2
        with self.db.make_session() as session:
            self.interactive.trace_tuples = [
                TraceTuple(trace_frame=self._frame_to_query_result(session, frames[0])),
                TraceTuple(trace_frame=self._frame_to_query_result(session, frames[1])),
                TraceTuple(trace_frame=self._frame_to_query_result(session, frames[2])),
                TraceTuple(trace_frame=self._frame_to_query_result(session, frames[3])),
                TraceTuple(trace_frame=self._frame_to_query_result(session, frames[4])),
            ]

        trace_frame = TraceFrameQueryResult(
            id=DBID(0),
            caller="caller",
            caller_port="caller_port",
            callee="F",
            callee_port="callee_port",
            filename="file.py",
            callee_location=SourceLocation(1, 1, 1),
            kind=TraceKind.PRECONDITION,
        )
        self.interactive._update_trace_tuples_new_parent(trace_frame)
        self.assertEqual(self.interactive.current_trace_frame_index, 0)
        self.assertEqual(
            [
                self.interactive._get_callable_from_trace_tuple(trace_tuple)[0]
                for trace_tuple in self.interactive.trace_tuples
            ],
            ["caller", "F", "D", "E"],
        )
        self.assertTrue(self.interactive.trace_tuples[0].placeholder)

    def testDetails(self) -> None:
        run = self.fakes.run()
        frames = [
            self.fakes.precondition(
                caller="call1",
                caller_port="root",
                callee="call2",
                callee_port="param0",
                location=(1, 1, 1),
            ),
            self.fakes.precondition(
                caller="call2",
                caller_port="param1",
                callee="call3",
                callee_port="param2",
                location=(1, 1, 1),
            ),
        ]
        issues = [
            self.fakes.issue(callable="call2"),
            self.fakes.issue(callable="call3"),
            self.fakes.issue(callable="call2"),
        ]
        self.fakes.instance(issue_id=issues[0].id, callable="call2")
        self.fakes.instance(issue_id=issues[1].id, callable="call3")
        self.fakes.instance(issue_id=issues[2].id, callable="call2")
        self.fakes.save_all(self.db)

        with self.db.make_session(expire_on_commit=False) as session:
            session.add(run)
            session.commit()

        self.interactive.setup()
        with self.db.make_session() as session:
            self.interactive.trace_tuples = [
                TraceTuple(trace_frame=self._frame_to_query_result(session, frames[0]))
            ]
        # pyre-fixme[8]: Attribute has type `DBID`; used as `int`.
        self.interactive.current_issue_instance_id = 1
        self.interactive.current_trace_frame_index = 0

        self._clear_stdout()
        self.interactive.details()
        self.assertEqual(
            self.stdout.getvalue().split("\n"),
            [
                f"Trace frame {frames[0].id}",
                "     Caller: call1 : root",
                "     Callee: call2 : param0",
                "       Kind: TraceKind.precondition",
                "      Sinks: ",
                "   Location: lib/server/posts/request.py:1|1|1",
                "",
                "Issues in callable (call2): 2",
                "",
                "Postconditions with caller (call2):",
                "No trace frames found.",
                "",
                "Preconditions with caller (call2):",
                "[id] [caller:caller_port -> callee:callee_port]",
                "---- call2:param1 ->",
                f"{frames[1].id}        call3:param2",
                "",
            ],
        )

    def testListLeaves(self) -> None:
        run = self.fakes.run()
        self.fakes.issue()
        instance = self.fakes.instance()
        sink_detail_1 = self.fakes.sink_detail("sink_detail_1")
        sink_detail_2 = self.fakes.sink_detail("sink_detail_2")
        self.fakes.save_all(self.db)

        assocs = [
            IssueInstanceSharedTextAssoc(
                shared_text_id=sink_detail_1.id,
                issue_instance_id=instance.id,
            ),
            IssueInstanceSharedTextAssoc(
                shared_text_id=sink_detail_2.id,
                issue_instance_id=instance.id,
            ),
        ]
        with self.db.make_session() as session:
            session.add(run)
            self._add_to_session(session, assocs)
            session.commit()

        self.interactive.setup()
        self.interactive.leaves()

        output = self.stdout.getvalue()
        self.assertIn("sink_detail_1", output)
        self.assertIn("sink_detail_2", output)

    def mock_pager(self, output_string: str) -> None:
        # pyre-fixme[16]: `InteractiveTest` has no attribute `pager_calls`.
        self.pager_calls += 1

    def testPager(self) -> None:
        run = self.fakes.run()
        self.fakes.issue()
        self.fakes.instance()
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

        # Default is no pager in tests
        # pyre-fixme[16]: `InteractiveTest` has no attribute `pager_calls`.
        self.pager_calls = 0
        with patch("IPython.core.page.page", self.mock_pager):
            self.interactive.setup()
            self.interactive.issues(use_pager=False)
            self.interactive.runs(use_pager=False)
        self.assertEqual(self.pager_calls, 0)

        self.pager_calls = 0
        with patch("IPython.core.page.page", self.mock_pager):
            self.interactive.setup()
            self.interactive.issues(use_pager=True)
            self.interactive.runs(use_pager=True)
        self.assertEqual(self.pager_calls, 2)
