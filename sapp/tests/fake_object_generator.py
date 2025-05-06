#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import datetime
from typing import Callable, cast, List, Optional, Tuple

from ..bulk_saver import BulkSaver
from ..db import DB
from ..models import (
    ClassTypeInterval,
    DBID,
    FrameReachability,
    Issue,
    IssueDBID,
    IssueInstance,
    IssueInstanceFixInfo,
    MetaRun,
    PurgeStatusForInstance,
    Run,
    RunStatus,
    SharedText,
    SharedTextKind,
    SourceLocation,
    TraceFrame,
    TraceKind,
)
from ..trace_graph import LeafMapping, TraceGraph


class FakeObjectGenerator:
    def __init__(self, graph: Optional[TraceGraph] = None, run_id: int = 0) -> None:
        self.reinit(run_id)
        self.graph = graph

    def reinit(self, run_id: int) -> None:
        self.saver = BulkSaver()
        self.handle = 0
        self.source_name_id = 0
        self.sink_name_id = 0
        self.shared_text_name_id = 0
        self.run_id = run_id
        self.metarun_id = 0

    def save_all(
        self, db: DB, before_save: Optional[Callable[[], None]] = None
    ) -> None:
        if self.graph:
            self.graph.update_bulk_saver(self.saver)
        self.saver.prepare_all(db)
        if before_save is not None:
            before_save()
        self.saver.save_all(db)
        self.saver = BulkSaver()

    def issue(
        self,
        callable: str = "Foo.barMethod",
        handle: Optional[str] = None,
        code: Optional[int] = None,
        status: str = "uncategorized",
    ) -> Issue:
        self.handle += 1
        now = datetime.datetime.now()
        callable_shared_text = self.callable(callable)
        result = cast(
            Issue,
            Issue.Record(
                id=IssueDBID(),
                handle=str(self.handle) if not handle else handle,
                code=code or (6015 + self.handle),
                callable_id=callable_shared_text.id,
                status=status,
                detected_time=int(now.timestamp()),
                first_instance_id=DBID(10072),
                update_time=0,
                triage_duration=0,
            ),
        )
        if self.graph:
            self.graph.add_issue(result)
        else:
            self.saver.add(result)
        return result

    def precondition(
        self,
        caller: str = "double_meh",
        caller_port: str = "at the end of universe",
        callee: str = "triple_meh",
        callee_port: str = "at the beginning of time",
        filename: str = "lib/server/posts/request.py",
        location: Tuple[int, ...] = (4, 5, 6),
        leaves: Optional[List[Tuple[SharedText, object]]] = None,
        reachability: FrameReachability = FrameReachability.UNREACHABLE,
        preserves_type_context: bool = False,
        type_interval_lower: int = 5,
        type_interval_upper: int = 7,
        run_id: Optional[int] = None,
        titos: Optional[List[SourceLocation]] = None,
    ) -> TraceFrame:
        leaves = leaves or []
        filename_record = self.filename(filename)
        caller_record = self.callable(caller)
        callee_record = self.callable(callee)
        trace_frame = TraceFrame.Record(
            extra_fields=["leaf_mapping"],
            leaf_mapping={
                LeafMapping(leaf.id.local_id, leaf.id.local_id, leaf.id.local_id)
                for (leaf, _) in leaves
                if leaf.kind == SharedTextKind.source
                or leaf.kind == SharedTextKind.sink
            },
            id=DBID(),
            kind=TraceKind.PRECONDITION,
            caller_id=caller_record.id,
            caller_port=caller_port,
            callee_id=callee_record.id,
            callee_port=callee_port,
            callee_location=SourceLocation(location[0], location[1], location[2]),
            filename_id=filename_record.id,
            titos=titos or [],
            run_id=run_id or self.run_id,
            type_interval_lower=type_interval_lower,
            type_interval_upper=type_interval_upper,
            preserves_type_context=preserves_type_context,
            reachability=reachability,
        )
        if self.graph:
            self.graph.add_trace_frame(trace_frame)
            for leaf, depth in leaves:
                # pyre-fixme[16]: `Optional` has no attribute
                #  `add_trace_frame_leaf_assoc`.
                self.graph.add_trace_frame_leaf_assoc(trace_frame, leaf, depth)
        else:
            self.saver.add(trace_frame)
        return trace_frame

    def postcondition(
        self,
        caller: str = "quadruple_meh",
        caller_port: str = "caller_meh",
        callee: str = "quintuple_meh",
        callee_port: str = "callee_meh",
        filename: str = "lib/server/posts/response.py",
        location: Tuple[int, ...] = (4, 5, 6),
        leaves: Optional[List[Tuple[SharedText, object]]] = None,
        preserves_type_context: bool = False,
        type_interval_lower: int = 5,
        type_interval_upper: int = 7,
        run_id: Optional[int] = None,
        titos: Optional[List[SourceLocation]] = None,
    ) -> TraceFrame:
        leaves = leaves or []
        filename_record = self.filename(filename)
        caller_record = self.callable(caller)
        callee_record = self.callable(callee)
        trace_frame = TraceFrame.Record(
            extra_fields=["leaf_mapping"],
            leaf_mapping={
                LeafMapping(leaf.id.local_id, leaf.id.local_id, leaf.id.local_id)
                for (leaf, _) in leaves
                if leaf.kind == SharedTextKind.source
                or leaf.kind == SharedTextKind.sink
            },
            id=DBID(),
            kind=TraceKind.POSTCONDITION,
            caller_id=caller_record.id,
            caller_port=caller_port,
            callee_id=callee_record.id,
            callee_port=callee_port,
            callee_location=SourceLocation(location[0], location[1], location[2]),
            filename_id=filename_record.id,
            titos=titos or [],
            run_id=run_id or self.run_id,
            type_interval_lower=type_interval_lower,
            type_interval_upper=type_interval_upper,
            preserves_type_context=preserves_type_context,
            reachability=FrameReachability.UNREACHABLE,
        )
        if self.graph:
            self.graph.add_trace_frame(trace_frame)
            for leaf, depth in leaves:
                # pyre-fixme[16]: `Optional` has no attribute
                #  `add_trace_frame_leaf_assoc`.
                self.graph.add_trace_frame_leaf_assoc(trace_frame, leaf, depth)
        else:
            self.saver.add(trace_frame)
        return trace_frame

    def shared_text(self, contents: str, kind: SharedTextKind) -> SharedText:
        if self.graph:
            shared_text = self.graph.get_shared_text(kind, contents)
            if shared_text is not None:
                return shared_text

        result = SharedText.Record(id=DBID(), contents=contents, kind=kind)
        if self.graph:
            self.graph.add_shared_text(result)
        else:
            self.saver.add(result)
        return result

    def run(
        self,
        differential_id: Optional[int] = None,
        job_id: Optional[str] = None,
        kind: Optional[str] = None,
    ) -> Run:
        self.run_id += 1
        # Not added to bulksaver or graph
        return Run(
            id=DBID(self.run_id),
            date=datetime.datetime.now(),
            hh_version="1234567890",
            revision_id=12345,
            differential_id=differential_id,
            job_id=job_id,
            kind=kind,
        )

    def metarun(
        self, status: RunStatus = RunStatus.FINISHED, kind: str = "test_metarun"
    ) -> MetaRun:
        self.metarun_id += 1
        # Not added to bulksaver or graph
        return MetaRun(
            id=DBID(self.metarun_id),
            date=datetime.datetime.now(),
            kind=kind,
            status=status,
        )

    def feature(self, name: str = "via:feature") -> SharedText:
        return self.shared_text(contents=name, kind=SharedTextKind.FEATURE)

    def source(self, name: str = "source") -> SharedText:
        return self.shared_text(contents=name, kind=SharedTextKind.SOURCE)

    def source_detail(self, name: str = "source_detail") -> SharedText:
        return self.shared_text(contents=name, kind=SharedTextKind.SOURCE_DETAIL)

    def sink(self, name: str = "sink") -> SharedText:
        return self.shared_text(contents=name, kind=SharedTextKind.SINK)

    def sink_detail(self, name: str = "sink_detail") -> SharedText:
        return self.shared_text(contents=name, kind=SharedTextKind.SINK_DETAIL)

    def filename(self, name: str = "/r/some/filename.py") -> SharedText:
        return self.shared_text(contents=name, kind=SharedTextKind.FILENAME)

    def callable(self, name: str = "Foo.barMethod") -> SharedText:
        return self.shared_text(contents=name, kind=SharedTextKind.CALLABLE)

    def message(self, name: str = "this is bad") -> SharedText:
        return self.shared_text(contents=name, kind=SharedTextKind.MESSAGE)

    def instance(
        self,
        message: str = "this is bad",
        filename: str = "/r/some/filename.py",
        callable: str = "Foo.barMethod",
        issue_id: Optional[DBID] = None,
        min_trace_length_to_sources: Optional[int] = None,
        min_trace_length_to_sinks: Optional[int] = None,
        purge_status: PurgeStatusForInstance = PurgeStatusForInstance.none,
        run_id: Optional[int] = None,
        archive_if_new_issue: bool = True,
    ) -> IssueInstance:
        issue_id = issue_id if issue_id is not None else DBID(1)
        filename_shared_text = self.filename(filename)
        message_shared_text = self.message(message)
        callable_shared_text = self.callable(callable)
        result = cast(
            IssueInstance,
            IssueInstance.Record(
                id=DBID(),
                location=SourceLocation(6, 7, 8),
                filename_id=filename_shared_text.id,
                message_id=message_shared_text.id,
                callable_id=callable_shared_text.id,
                run_id=run_id or self.run_id,
                issue_id=issue_id,
                min_trace_length_to_sources=min_trace_length_to_sources,
                min_trace_length_to_sinks=min_trace_length_to_sinks,
                purge_status=purge_status,
                archive_if_new_issue=archive_if_new_issue,
            ),
        )
        if self.graph:
            self.graph.add_issue_instance(result)
        else:
            self.saver.add(result)
        return result

    def fix_info(self) -> IssueInstanceFixInfo:
        result = IssueInstanceFixInfo.Record(id=DBID(), fix_info="fixthis")
        if self.graph:
            self.graph.add_issue_instance_fix_info(result.issue_instance, result)
        else:
            self.saver.add(result)
        return result

    def class_type_interval(
        self,
        class_name: str = "\\Foo",
        lower_bound: int = 0,
        upper_bound: int = 100,
        run_id: Optional[int] = None,
    ) -> ClassTypeInterval:
        interval = ClassTypeInterval.Record(
            id=DBID(),
            run_id=run_id or self.run_id,
            class_name=class_name,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        )
        if self.graph:
            self.graph.add_class_type_interval(interval)
        else:
            self.saver.add(interval)
        return interval
