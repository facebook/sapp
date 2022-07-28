#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-unsafe

import datetime
from typing import Any, Dict, Optional

from ..bulk_saver import BulkSaver
from ..models import (
    ClassTypeInterval,
    DBID,
    Feature,
    FrameReachability,
    Issue,
    IssueDBID,
    IssueInstance,
    IssueInstanceFixInfo,
    Run,
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

    def reinit(self, run_id) -> None:
        self.saver = BulkSaver()
        self.handle = 0
        self.source_name_id = 0
        self.sink_name_id = 0
        self.shared_text_name_id = 0
        self.run_id = run_id

    def save_all(self, db) -> None:
        if self.graph:
            self.graph.update_bulk_saver(self.saver)
        self.saver.save_all(db)
        self.saver = BulkSaver()

    def issue(
        self,
        callable: str = "Foo.barMethod",
        handle=None,
        code=None,
        status: str = "uncategorized",
    ):
        self.handle += 1
        now = datetime.datetime.now()
        callable = self.callable(callable)
        result = Issue.Record(
            id=IssueDBID(),
            handle=str(self.handle) if not handle else handle,
            code=code or (6015 + self.handle),
            callable_id=callable.id,
            status=status,
            detected_time=now.timestamp(),
        )
        if self.graph:
            # pyre-fixme[6]: For 1st param expected `Issue` but got `Munch`.
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
        location=(4, 5, 6),
        leaves=None,
        reachability=FrameReachability.UNREACHABLE,
        preserves_type_context: bool = False,
        type_interval_lower: int = 5,
        type_interval_upper: int = 7,
    ):
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
            titos=[],
            run_id=self.run_id,
            type_interval_lower=type_interval_lower,
            type_interval_upper=type_interval_upper,
            preserves_type_context=preserves_type_context,
            reachability=reachability,
        )
        if self.graph:
            self.graph.add_trace_frame(trace_frame)
            for (leaf, depth) in leaves:
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
        location=(4, 5, 6),
        leaves=None,
        preserves_type_context: bool = False,
        type_interval_lower: int = 5,
        type_interval_upper: int = 7,
    ):
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
            titos=[],
            run_id=self.run_id,
            type_interval_lower=type_interval_lower,
            type_interval_upper=type_interval_upper,
            preserves_type_context=preserves_type_context,
            reachability=FrameReachability.UNREACHABLE,
        )
        if self.graph:
            self.graph.add_trace_frame(trace_frame)
            for (leaf, depth) in leaves:
                # pyre-fixme[16]: `Optional` has no attribute
                #  `add_trace_frame_leaf_assoc`.
                self.graph.add_trace_frame_leaf_assoc(trace_frame, leaf, depth)
        else:
            self.saver.add(trace_frame)
        return trace_frame

    def shared_text(self, contents, kind):
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

    def run(self, differential_id=None, job_id=None, kind=None):
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

    def structured_feature(self, feature: Optional[Dict[str, Any]] = None):
        if feature is None:
            feature = {
                "always": True,
                "interval": ["-2147483648", "2147483647"],
                "op": "bound",
            }
        if self.graph:
            feature_obj = self.graph.get_feature(feature)
            if feature_obj is not None:
                return feature_obj

        feature_obj = Feature.Record(id=DBID(), data=feature)
        if self.graph:
            self.graph.add_feature(feature_obj)
        else:
            self.saver.add(feature_obj)
        return feature_obj

    def feature(self, name: str = "via:feature"):
        return self.shared_text(contents=name, kind=SharedTextKind.FEATURE)

    def source(self, name: str = "source"):
        return self.shared_text(contents=name, kind=SharedTextKind.SOURCE)

    def source_detail(self, name: str = "source_detail"):
        return self.shared_text(contents=name, kind=SharedTextKind.SOURCE_DETAIL)

    def sink(self, name: str = "sink"):
        return self.shared_text(contents=name, kind=SharedTextKind.SINK)

    def sink_detail(self, name: str = "sink_detail"):
        return self.shared_text(contents=name, kind=SharedTextKind.SINK_DETAIL)

    def filename(self, name: str = "/r/some/filename.py"):
        return self.shared_text(contents=name, kind=SharedTextKind.FILENAME)

    def callable(self, name: str = "Foo.barMethod"):
        return self.shared_text(contents=name, kind=SharedTextKind.CALLABLE)

    def message(self, name: str = "this is bad"):
        return self.shared_text(contents=name, kind=SharedTextKind.MESSAGE)

    def instance(
        self,
        message: str = "this is bad",
        filename: str = "/r/some/filename.py",
        callable: str = "Foo.barMethod",
        issue_id=None,
        min_trace_length_to_sources=None,
        min_trace_length_to_sinks=None,
    ):
        issue_id = issue_id if issue_id is not None else DBID(1)
        filename = self.filename(filename)
        message = self.message(message)
        callable = self.callable(callable)
        result = IssueInstance.Record(
            id=DBID(),
            location=SourceLocation(6, 7, 8),
            filename_id=filename.id,
            message_id=message.id,
            callable_id=callable.id,
            run_id=self.run_id,
            issue_id=issue_id,
            min_trace_length_to_sources=min_trace_length_to_sources,
            min_trace_length_to_sinks=min_trace_length_to_sinks,
        )
        if self.graph:
            # pyre-fixme[6]: For 1st param expected `IssueInstance` but got `Munch`.
            self.graph.add_issue_instance(result)
        else:
            self.saver.add(result)
        return result

    def fix_info(self):
        result = IssueInstanceFixInfo.Record(id=DBID(), fix_info="fixthis")
        if self.graph:
            self.graph.add_fix_info(result)
        else:
            self.saver.add(result)
        return result

    def class_type_interval(
        self, class_name: str = "\\Foo", lower_bound: int = 0, upper_bound: int = 100
    ) -> ClassTypeInterval:
        interval = ClassTypeInterval.Record(
            id=DBID(),
            run_id=self.run_id,
            class_name=class_name,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        )
        if self.graph:
            self.graph.add_class_type_interval(interval)
        else:
            self.saver.add(interval)
        return interval
