# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""End-to-end tests for the Prophecy SAPP pipeline.

Runs the full pipeline (Parser -> CreateDatabase -> ModelGenerator ->
TrimTraceGraph -> DatabaseSaver) against a SQLite DB and verifies every
table is correctly populated. Also tests multi-run deduplication.
"""

import json
import os
import tempfile
import unittest

from ...analysis_output import AnalysisOutput, Metadata, Rule
from ...db import DB, DBType
from ...models import (
    Issue,
    IssueInstance,
    IssueInstanceFixInfo,
    IssueInstanceSharedTextAssoc,
    IssueInstanceTraceFrameAssoc,
    PrimaryKeyGenerator,
    Run,
    RunStatus,
    SharedText,
    SharedTextKind,
    TraceFrame,
    TraceFrameLeafAssoc,
    TraceKind,
)
from .. import PipelineBuilder, Summary
from ..add_features import AddFeatures
from ..create_database import CreateDatabase
from ..database_saver import DatabaseSaver
from ..model_generator import ModelGenerator
from ..prophecy_parser import Parser
from ..trim_trace_graph import TrimTraceGraph

# -- Test fixture data --------------------------------------------------------

METADATA = Metadata(
    repo_roots={"/repo"},
    analysis_tool_version="1.0.0",
    tool="prophecy",
    repository_name="fbsource",
    project="prophecy",
    rules={
        9001: Rule(name="Prophecy-RCE", description="Remote Code Execution"),
        9003: Rule(name="Prophecy-XSS", description="Cross-Site Scripting"),
        9004: Rule(name="Prophecy-SSRF", description="Server-Side Request Forgery"),
    },
)

# RCE finding: has fix_info, propagation_steps, TITOs
FINDING_RCE = (
    '{"kind": "issue", "code": 9001, '
    '"callable": "src/exec.ts::runCommand", "callable_line": 10, '
    '"filename": "src/exec.ts", '
    '"position": {"line": 25, "start": 5, "end": 40}, '
    '"description": "Data from [UserInput] may reach [CommandExec]", '
    '"traces": ['
    '{"forward": {"trace_leaf": {"position": {"line": 10, "start": 3, "end": 20}}, '
    '"kind": "UserInput", "leaves": [{"name": "req.query.cmd"}], '
    '"local_trace": {"positions": [{"line": 15, "start": 5, "end": 12}]}}}, '
    '{"backward": {"trace_leaf": {"position": {"line": 25, "start": 5, "end": 40}}, '
    '"kind": "CommandExec", "leaves": [{"name": "child_process.exec"}], '
    '"local_trace": {"positions": []}}}], '
    '"fix_info": {"filePath": "src/exec.ts", "original": "exec(cmd)", '
    '"replacement": "exec(sanitize(cmd))", "applicability": "unsafe"}, '
    '"features": ["prophecy-severity:critical", "prophecy-category:rce"], '
    '"propagation_steps": ['
    '{"kind": "assignment", "location": {"line": 12, "start": 5, "end": 20}, '
    '"description": "Tainted value assigned to cmd"}, '
    '{"kind": "argument", "location": {"line": 25, "start": 5, "end": 40}, '
    '"description": "Passed as argument to exec()"}]}'
)

# XSS finding: no fix_info
FINDING_XSS = (
    '{"kind": "issue", "code": 9003, '
    '"callable": "src/render.ts::renderPage", "callable_line": 30, '
    '"filename": "src/render.ts", '
    '"position": {"line": 45, "start": 8, "end": 35}, '
    '"description": "Data from [UserInput] may reach [InnerHTML]", '
    '"traces": ['
    '{"forward": {"trace_leaf": {"position": {"line": 32, "start": 10, "end": 25}}, '
    '"kind": "UserInput", "leaves": [{"name": "req.body.name"}], '
    '"local_trace": {"positions": []}}}, '
    '{"backward": {"trace_leaf": {"position": {"line": 45, "start": 8, "end": 35}}, '
    '"kind": "InnerHTML", "leaves": [{"name": "document.innerHTML"}], '
    '"local_trace": {"positions": []}}}], '
    '"features": ["prophecy-severity:high", "prophecy-category:xss"]}'
)

# SSRF finding: two source leaves
FINDING_SSRF = (
    '{"kind": "issue", "code": 9004, '
    '"callable": "src/api.ts::fetchUrl", "callable_line": 50, '
    '"filename": "src/api.ts", '
    '"position": {"line": 60, "start": 3, "end": 30}, '
    '"description": "Data from [UserInput] may reach [HttpRequest]", '
    '"traces": ['
    '{"forward": {"trace_leaf": {"position": {"line": 52, "start": 5, "end": 18}}, '
    '"kind": "UserInput", '
    '"leaves": [{"name": "req.query.url"}, {"name": "req.body.target"}], '
    '"local_trace": {"positions": []}}}, '
    '{"backward": {"trace_leaf": {"position": {"line": 60, "start": 3, "end": 30}}, '
    '"kind": "HttpRequest", "leaves": [{"name": "node-fetch"}], '
    '"local_trace": {"positions": []}}}], '
    '"features": ["prophecy-severity:high", "prophecy-category:ssrf"]}'
)

ALL_FINDINGS = "\n".join([FINDING_RCE, FINDING_XSS, FINDING_SSRF])


# -- Helpers ------------------------------------------------------------------


def _create_fixture_dir() -> str:
    """Write SAPP-format fixture files to a temp directory."""
    d = tempfile.mkdtemp(prefix="prophecy_sapp_e2e_")
    with open(os.path.join(d, "metadata.json"), "w") as f:
        json.dump(
            {
                "version": "1.0.0",
                "root": "/repo",
                "repo_root": "/repo",
                "tool": "prophecy",
                "filename_spec": "prophecy-output.json",
                "repository_name": "fbsource",
                "project": "prophecy",
                "rules": [
                    {"code": c, "name": r.name, "description": r.description}
                    for c, r in METADATA.rules.items()
                ],
            },
            f,
        )
    with open(os.path.join(d, "prophecy-output.json"), "w") as f:
        f.write(ALL_FINDINGS)
    return d


def _run_pipeline(db: DB, fixture_dir: str, job_id: str = "test-1") -> None:
    """Run the full SAPP pipeline against a fixture directory."""
    analysis_output = AnalysisOutput.from_directory(fixture_dir)
    summary = Summary(
        repository="fbsource",
        branch="main",
        commit_hash="abc123",
        job_id=job_id,
        run_kind="master",
    )
    pipeline = (
        PipelineBuilder()
        .append(Parser())
        .append(CreateDatabase(db))
        .append(AddFeatures(None))
        .append(ModelGenerator())
        .append(TrimTraceGraph())
        .append(DatabaseSaver(db, Run, PrimaryKeyGenerator()))
        .build()
    )
    pipeline.run(analysis_output, summary)


# -- Tests --------------------------------------------------------------------


class TestProphecyE2E(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture_dir = _create_fixture_dir()
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.db_fd)
        self.db = DB(DBType.SQLITE, self.db_path, assertions=True)

    def tearDown(self) -> None:
        os.unlink(self.db_path)
        for f in os.listdir(self.fixture_dir):
            os.unlink(os.path.join(self.fixture_dir, f))
        os.rmdir(self.fixture_dir)

    def _ingest(self, job_id: str = "test-1") -> None:
        _run_pipeline(self.db, self.fixture_dir, job_id)

    # -- Single-run tests -----------------------------------------------------

    def test_run_created(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            runs = s.query(Run).all()
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0].status, RunStatus.finished)

    def test_issue_count_and_codes(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            issues = s.query(Issue).all()
            self.assertEqual(len(issues), 3)
            codes = sorted(i.code for i in issues)
            self.assertEqual(codes, [9001, 9003, 9004])

    def test_issue_handles_unique(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            handles = [i.handle for i in s.query(Issue).all()]
            self.assertEqual(len(handles), len(set(handles)))
            for h in handles:
                self.assertTrue(len(h) > 0)
                self.assertTrue(len(h) <= 255)

    def test_issue_handle_contains_callable(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            rce = s.query(Issue).filter(Issue.code == 9001).one()
            self.assertIn("src/exec.ts::runCommand", rce.handle)

    def test_issue_instance_count(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            instances = s.query(IssueInstance).all()
            self.assertEqual(len(instances), 3)

    def test_issue_instance_locations(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            rce = s.query(Issue).filter(Issue.code == 9001).one()
            inst = s.query(IssueInstance).filter(IssueInstance.issue_id == rce.id).one()
            self.assertEqual(inst.location.line_no, 25)
            self.assertEqual(inst.location.begin_column, 5)
            self.assertEqual(inst.location.end_column, 40)

    def test_trace_frame_count(self) -> None:
        """3 preconditions + 4 postconditions = 7 total."""
        self._ingest()
        with self.db.make_session() as s:
            frames = s.query(TraceFrame).all()
            self.assertEqual(len(frames), 7)

    def test_trace_frame_kinds(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            pre = (
                s.query(TraceFrame)
                .filter(TraceFrame.kind == TraceKind.precondition)
                .count()
            )
            post = (
                s.query(TraceFrame)
                .filter(TraceFrame.kind == TraceKind.postcondition)
                .count()
            )
            self.assertEqual(pre, 3)
            self.assertEqual(post, 4)  # SSRF has 2 source leaves

    def test_ssrf_has_two_postconditions(self) -> None:
        """The SSRF finding has two source leaves, producing two postcondition
        trace frames."""
        self._ingest()
        with self.db.make_session() as s:
            ssrf = s.query(Issue).filter(Issue.code == 9004).one()
            ssrf_inst = (
                s.query(IssueInstance).filter(IssueInstance.issue_id == ssrf.id).one()
            )
            assoc_ids = {
                int(a.trace_frame_id)
                for a in s.query(IssueInstanceTraceFrameAssoc)
                .filter(IssueInstanceTraceFrameAssoc.issue_instance_id == ssrf_inst.id)
                .all()
            }
            post_frames = (
                s.query(TraceFrame)
                .filter(TraceFrame.id.in_(assoc_ids))
                .filter(TraceFrame.kind == TraceKind.postcondition)
                .all()
            )
            self.assertEqual(len(post_frames), 2)

    def test_shared_text_sources(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            sources = {
                st.contents
                for st in s.query(SharedText)
                .filter(SharedText.kind == SharedTextKind.source)
                .all()
            }
            self.assertEqual(sources, {"UserInput"})

    def test_shared_text_sinks(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            sinks = {
                st.contents
                for st in s.query(SharedText)
                .filter(SharedText.kind == SharedTextKind.sink)
                .all()
            }
            self.assertEqual(sinks, {"CommandExec", "InnerHTML", "HttpRequest"})

    def test_shared_text_filenames(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            filenames = {
                st.contents
                for st in s.query(SharedText)
                .filter(SharedText.kind == SharedTextKind.filename)
                .all()
            }
            self.assertEqual(filenames, {"src/exec.ts", "src/render.ts", "src/api.ts"})

    def test_shared_text_features(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            features = {
                st.contents
                for st in s.query(SharedText)
                .filter(SharedText.kind == SharedTextKind.feature)
                .all()
            }
            self.assertIn("prophecy-severity:critical", features)
            self.assertIn("prophecy-severity:high", features)
            self.assertIn("prophecy-category:rce", features)
            self.assertIn("prophecy-category:xss", features)
            self.assertIn("prophecy-category:ssrf", features)

    def test_propagation_steps_in_features(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            features = {
                st.contents
                for st in s.query(SharedText)
                .filter(SharedText.kind == SharedTextKind.feature)
                .all()
            }
            step_features = {f for f in features if f.startswith("prophecy-step-")}
            self.assertTrue(len(step_features) >= 2)

    def test_shared_text_source_details(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            details = {
                st.contents
                for st in s.query(SharedText)
                .filter(SharedText.kind == SharedTextKind.source_detail)
                .all()
            }
            self.assertIn("req.query.cmd", details)
            self.assertIn("req.body.name", details)
            self.assertIn("req.query.url", details)
            self.assertIn("req.body.target", details)

    def test_shared_text_sink_details(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            details = {
                st.contents
                for st in s.query(SharedText)
                .filter(SharedText.kind == SharedTextKind.sink_detail)
                .all()
            }
            self.assertEqual(
                details,
                {"child_process.exec", "document.innerHTML", "node-fetch"},
            )

    def test_fix_info(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            fix_infos = s.query(IssueInstanceFixInfo).all()
            self.assertEqual(len(fix_infos), 1)
            fi = json.loads(fix_infos[0].fix_info)
            self.assertEqual(fi["filePath"], "src/exec.ts")
            self.assertEqual(fi["original"], "exec(cmd)")
            self.assertEqual(fi["replacement"], "exec(sanitize(cmd))")
            self.assertEqual(fi["applicability"], "unsafe")

    def test_leaf_assocs(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            assocs = s.query(TraceFrameLeafAssoc).all()
            self.assertEqual(len(assocs), 7)

    def test_instance_trace_frame_assocs(self) -> None:
        self._ingest()
        with self.db.make_session() as s:
            assocs = s.query(IssueInstanceTraceFrameAssoc).all()
            self.assertEqual(len(assocs), 7)

    def test_instance_shared_text_assocs(self) -> None:
        """Each instance gets assocs for features, sources, sinks, and details."""
        self._ingest()
        with self.db.make_session() as s:
            assocs = s.query(IssueInstanceSharedTextAssoc).all()
            # At least 7 per instance (features + source/sink kinds + details)
            # but exact count depends on dedup behavior.
            self.assertGreaterEqual(len(assocs), 18)

    # -- Multi-run dedup tests ------------------------------------------------

    def test_dedup_issue_count_stable(self) -> None:
        """Same findings ingested twice should not create duplicate Issues."""
        self._ingest("run-1")
        self._ingest("run-2")
        with self.db.make_session() as s:
            self.assertEqual(s.query(Issue).count(), 3)

    def test_dedup_run_count(self) -> None:
        self._ingest("run-1")
        self._ingest("run-2")
        with self.db.make_session() as s:
            self.assertEqual(s.query(Run).count(), 2)

    def test_dedup_instance_count(self) -> None:
        """Each run creates new IssueInstances: 3 per run = 6 total."""
        self._ingest("run-1")
        self._ingest("run-2")
        with self.db.make_session() as s:
            self.assertEqual(s.query(IssueInstance).count(), 6)

    def test_dedup_instances_per_issue(self) -> None:
        """Each issue should have exactly 2 instances (one per run)."""
        self._ingest("run-1")
        self._ingest("run-2")
        with self.db.make_session() as s:
            for issue in s.query(Issue).all():
                count = (
                    s.query(IssueInstance)
                    .filter(IssueInstance.issue_id == issue.id)
                    .count()
                )
                self.assertEqual(
                    count, 2, f"Issue code={issue.code} has {count} instances"
                )

    def test_dedup_shared_text_stable(self) -> None:
        """SharedText should be deduped across runs."""
        self._ingest("run-1")
        count_after_first = None
        with self.db.make_session() as s:
            count_after_first = s.query(SharedText).count()
        self._ingest("run-2")
        with self.db.make_session() as s:
            count_after_second = s.query(SharedText).count()
        self.assertEqual(count_after_first, count_after_second)

    def test_dedup_trace_frames_per_run(self) -> None:
        """TraceFrames are per-run, so they double on second ingest."""
        self._ingest("run-1")
        self._ingest("run-2")
        with self.db.make_session() as s:
            self.assertEqual(s.query(TraceFrame).count(), 14)
            runs = s.query(Run).all()
            for run in runs:
                per_run = (
                    s.query(TraceFrame).filter(TraceFrame.run_id == run.id).count()
                )
                self.assertEqual(per_run, 7)
