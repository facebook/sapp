#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-unsafe

import json
import sys
from datetime import datetime
from io import StringIO
from typing import List
from unittest import TestCase
from unittest.mock import patch

import jsonschema
import requests

from sapp.sarif import SARIF

from sqlalchemy.orm import Session

from ...db import DB, DBType
from ...models import (
    create as create_models,
    DBID,
    IssueStatus,
    SharedText,
    SourceLocation,
    TraceFrame,
    TraceKind,
)
from ...pipeline.pysa_taint_parser import Parser
from ...tests.fake_object_generator import FakeObjectGenerator
from ..interactive import Interactive, IssueQueryResult, TraceFrameQueryResult


class SarifTest(TestCase):
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

    def testSarifSchemaCheckWithIssuesNoTraces(self) -> None:
        run = self.fakes.run()
        issues = [
            IssueQueryResult(
                issue_id=DBID(1),
                issue_instance_id=DBID(1),
                filename="SelfServicePortalController.java",
                location=SourceLocation(1, 2, 3),
                code=6,
                callable="Response SelfServicePortalController.getSelfServiceLogs(Cookie, AuditLogRequest)",
                message="root",
                min_trace_length_to_sources=0,
                min_trace_length_to_sinks=2,
                features=frozenset(),
                is_new_issue=False,
                source_names=frozenset(["source1"]),
                source_kinds=frozenset(["source_kind1"]),
                sink_names=frozenset(["sink1"]),
                sink_kinds=frozenset(["sink_kind1", "sink_kind2"]),
                status=IssueStatus.UNCATEGORIZED,
                detected_time=datetime.today(),
                similar_issues=set(),
                run_id=DBID(1),
            )
        ]
        self.fakes.save_all(self.db)
        with self.db.make_session() as session:
            session.add(run)
            session.commit()
            sarif = SARIF("mariana-trench", session, set(issues))
            output = sarif.to_json()
            output = json.loads(output)
            try:
                response = requests.get(SARIF.schema)
                response.raise_for_status()
                schema = response.json()
                jsonschema.Draft202012Validator(schema).validate(output)
            except Exception as e:
                print(f"Error downloading schema: {e}")
                raise e

    def testSarifSchemaCheckWithIssuesWithTraces(self) -> None:
        run = self.fakes.run()
        issues = [
            IssueQueryResult(
                issue_id=DBID(1),
                issue_instance_id=DBID(1),
                filename="SelfServicePortalController.java",
                location=SourceLocation(1, 2, 3),
                code=6,
                callable="Response SelfServicePortalController.getSelfServiceLogs(Cookie, AuditLogRequest)",
                message="root",
                min_trace_length_to_sources=0,
                min_trace_length_to_sinks=2,
                features=frozenset(),
                is_new_issue=False,
                source_names=frozenset(["source1"]),
                source_kinds=frozenset(["source_kind1"]),
                sink_names=frozenset(["sink1"]),
                sink_kinds=frozenset(["sink_kind1", "sink_kind2"]),
                status=IssueStatus.UNCATEGORIZED,
                detected_time=datetime.today(),
                similar_issues=set(),
                run_id=DBID(1),
            ),
            IssueQueryResult(
                issue_id=DBID(2),
                issue_instance_id=DBID(2),
                filename="SelfServicePortalController.java",
                location=SourceLocation(1, 2, 3),
                code=4,
                callable="Response SelfServicePortalController.getSelfServiceLogs(Cookie, AuditLogRequest)",
                message="root",
                min_trace_length_to_sources=0,
                min_trace_length_to_sinks=2,
                features=frozenset(),
                is_new_issue=False,
                source_names=frozenset(["source1"]),
                source_kinds=frozenset(["source_kind1"]),
                sink_names=frozenset(["sink1"]),
                sink_kinds=frozenset(["sink_kind1", "sink_kind2"]),
                status=IssueStatus.UNCATEGORIZED,
                detected_time=datetime.today(),
                similar_issues=set(),
                run_id=DBID(1),
            ),
        ]
        source_frames: List[TraceFrame] = [
            self.fakes.postcondition(
                caller="PostCondCallerA",
                callee="PostCondCalleeA",
                filename="file1.java",
            ),
            self.fakes.postcondition(
                caller="PostCondCallerB",
                callee="PostCondCalleeB",
                filename="file2.java",
            ),
        ]
        sink_frames: List[TraceFrame] = [
            self.fakes.precondition(
                caller="PreCondCallerA", callee="PreCondCalleeA", filename="file3.java"
            ),
            self.fakes.precondition(
                caller="PreCondCallerB", callee="PreCondCalleeB", filename="file4.java"
            ),
        ]
        self.fakes.save_all(self.db)
        with self.db.make_session() as session:
            session.add(run)
            session.commit()
            source_frames_query_results: List[TraceFrameQueryResult] = [
                self._frame_to_query_result(session, source_frames[0]),
                self._frame_to_query_result(session, source_frames[1]),
            ]
            sink_frames_query_results: List[TraceFrameQueryResult] = [
                self._frame_to_query_result(session, sink_frames[0]),
                self._frame_to_query_result(session, sink_frames[1]),
            ]
            with patch("sapp.ui.trace.initial_frames") as mock_trace:
                input_return_map = {
                    (session, issues[0].issue_instance_id, TraceKind.POSTCONDITION): [
                        source_frames_query_results[0],
                        source_frames_query_results[1],
                    ],
                    (session, issues[0].issue_instance_id, TraceKind.PRECONDITION): [
                        sink_frames_query_results[0],
                        sink_frames_query_results[1],
                    ],
                }
                mock_trace.side_effect = lambda *args: input_return_map.get(args)
                sarif = SARIF("mariana-trench", session, set(issues))
                output = sarif.to_json()
                output = json.loads(output)
                try:
                    response = requests.get(SARIF.schema)
                    response.raise_for_status()
                    schema = response.json()
                    jsonschema.Draft202012Validator(schema).validate(output)
                except Exception as e:
                    print(f"Error downloading schema: {e}")
                    raise e
