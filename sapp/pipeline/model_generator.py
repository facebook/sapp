# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import datetime
import json
import logging
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from pyre_extensions import none_throws

from ..metrics_logger import ScopedMetricsLogger
from ..models import (
    DBID,
    FrameReachability,
    Issue,
    IssueDBID,
    IssueInstance,
    IssueInstanceFixInfo,
    IssueStatus,
    MetaRunIssueInstanceIndex,
    PurgeStatus,
    Run,
    RunStatus,
    SharedText,
    SharedTextKind,
    SourceLocation,
    TraceFrame,
    TraceFrameAnnotation,
    TraceKind,
)
from ..pipeline import Frames
from ..trace_graph import LeafMapping, TraceGraph
from . import (
    IssuesAndFrames,
    meta_run_issue_duplicate_filter,
    ParseConditionTuple,
    ParseFeature,
    ParseIssueConditionTuple,
    ParseIssueTuple,
    ParseLeaf,
    ParseTraceAnnotation,
    ParseTraceAnnotationSubtrace,
    ParseTraceFeature,
    ParseTypeInterval,
    PipelineStep,
    Summary,
)

log: logging.Logger = logging.getLogger("sapp")


# pyre-fixme[2]: Really need Any here
def bound_int(i: Any, upper_limit: int) -> Optional[int]:
    if isinstance(i, int):
        if i < 0:
            return 0
        elif i > upper_limit:
            return upper_limit
        return i
    else:
        return None


MAX_TRACE_LENGTH: int = 1000


# pyre-fixme[2]: Really need Any here
def bound_trace_length(depth: Any) -> Optional[int]:
    # avoid writing bad trace_length to DB
    return bound_int(depth, MAX_TRACE_LENGTH)


MAX_TYPE_INTERVAL: int = (2**31) - 1


# pyre-fixme[2]: Really need Any here
def bound_type_interval_limit(i: Any) -> Optional[int]:
    # avoid writing bad interval numbers
    return bound_int(i, MAX_TYPE_INTERVAL)


class ModelGenerator(PipelineStep[IssuesAndFrames, TraceGraph]):
    def __init__(
        self,
        record_meta_run_issue_instances: bool = False,
        meta_run_identifier: Optional[int] = None,
        archive_issue_instances_of_new_issues: bool = True,
        skip_traces: bool = False,
    ) -> None:
        super().__init__()
        # pyre-fixme[13]: Attribute `summary` is never initialized.
        self.summary: Summary
        # pyre-fixme[13]: Attribute `graph` is never initialized.
        self.graph: TraceGraph
        self.visited_frames: Dict[int, Set[int]] = {}  # frame id -> leaf ids
        self.record_meta_run_issue_instances: bool = record_meta_run_issue_instances
        self.meta_run_identifier: Optional[int] = meta_run_identifier
        self.archive_issue_instances_of_new_issues = (
            archive_issue_instances_of_new_issues
        )
        self.skip_traces: bool = skip_traces
        self.trace_entries: Dict[TraceKind, Frames] = {}

    def run(
        self,
        input: IssuesAndFrames,
        summary: Summary,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> Tuple[TraceGraph, Summary]:
        result = self._run_inner(input, summary, scoped_metrics_logger)

        log.info("Freeing parsed issues and frames")
        input.issues = []
        input.preconditions.dispose()
        input.postconditions.dispose()
        log.info("Done freeing parsed issues and frames")

        return result

    def _run_inner(
        self,
        input: IssuesAndFrames,
        summary: Summary,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> Tuple[TraceGraph, Summary]:
        self.summary = summary

        self.trace_entries = {
            TraceKind.precondition: input.preconditions,
            TraceKind.postcondition: input.postconditions,
        }
        self.summary.missing_traces = defaultdict(
            set
        )  # Dict[TraceKind, Set[Tuple[str, str]]]
        self.summary.big_tito = set()  # Set[Tuple[str, str, int]]

        self.graph = TraceGraph()

        runs = self._create_empty_runs(status=RunStatus.incomplete)
        self.summary.runs = runs

        callables = self._compute_callables_count(input.issues)

        log.info("Generating issues and traces")
        for entry in input.issues:
            for run in runs:
                self._generate_issue(run, entry, callables)

        if self.summary.store_unused_models:
            for (
                trace_kind,
                traces,
            ) in self.trace_entries.items():
                for entry in traces.all_frames():
                    for run in runs:
                        self._generate_trace_frame(trace_kind, run, entry)

        return self.graph, self.summary

    def _compute_callables_count(
        self, issues: Iterable[ParseIssueTuple]
    ) -> Dict[str, int]:
        """Iterate over all issues and count the number of times each callable
        is seen."""
        count: Dict[str, int] = dict.fromkeys(
            [issue.callable for issue in issues], int(0)
        )
        for issue in issues:
            count[issue.callable] += 1

        return count

    def _create_empty_runs(
        self,
        status: RunStatus,
        status_description: Optional[str] = None,
    ) -> List[Run]:
        """setting boilerplate when creating a Run object"""
        run = Run(
            id=DBID(),
            job_id=self.summary.job_id,
            issue_instances=[],
            date=datetime.datetime.now(),
            status=status,
            status_description=status_description,
            repository=self.summary.repository,
            branch=self.summary.branch,
            commit_hash=self.summary.commit_hash,
            kind=self.summary.run_kind,
            purge_status=PurgeStatus.unpurged,
        )
        return [run]

    def _get_minimum_trace_length(
        self, entries: Iterable[ParseIssueConditionTuple]
    ) -> int:
        length = None
        for entry in entries:
            for _leaf, depth in entry.leaves:
                depth = bound_trace_length(depth)
                if length is None or (depth is not None and length > depth):
                    length = depth
        if length is not None:
            return length
        return 0

    def _generate_issue(
        self, run: Run, entry: ParseIssueTuple, callablesCount: Dict[str, int]
    ) -> None:
        """Insert the issue instance into a run. This includes creating (for
        new issues) or finding (for existing issues) Issue objects to associate
        with the instances.
        Also create sink entries and associate related issues"""

        trace_frames = []
        final_sink_kinds = set()
        initial_source_kinds = set()
        for p in entry.preconditions:
            tf, new_sink_ids = self._generate_issue_traces(
                TraceKind.precondition, run, entry, p
            )
            final_sink_kinds.update(new_sink_ids)
            trace_frames.append(tf)

        for p in entry.postconditions:
            tf, new_source_ids = self._generate_issue_traces(
                TraceKind.postcondition, run, entry, p
            )
            initial_source_kinds.update(new_source_ids)
            trace_frames.append(tf)

        callable = entry.callable

        source_details = {
            self._get_shared_text(SharedTextKind.source_detail, name)
            for (name, _kind, _depth) in entry.initial_sources
            if name
        }
        sink_details = {
            self._get_shared_text(SharedTextKind.sink_detail, name)
            for (name, _kind, _depth) in entry.final_sinks
            if name
        }

        callable_record = self._get_shared_text(SharedTextKind.callable, callable)

        # create id ahead so we can link the issue below. Note, issues are only saved if
        # first seen, i.e., their handle hasn't been seen before. So we can always set
        # first_instance_id, because it will only be saved when it is indeed new.
        instance_id = DBID()

        # pyre-fixme [9] Incompatible variable type: issue is declared to have type `Issue` but is used as type `munch.Munch`
        issue: Issue = Issue.Record(
            id=IssueDBID(),
            code=entry.code,
            handle=entry.handle,
            callable_id=callable_record.id,
            status=IssueStatus.uncategorized,
            detected_time=int(run.date.timestamp()),
            first_instance_id=instance_id,
            update_time=0,
            triage_duration=0,
        )

        self.graph.add_issue(issue)

        fix_info = None
        fix_info_id = None
        if entry.fix_info is not None:
            fix_info = IssueInstanceFixInfo.Record(
                id=DBID(),
                fix_info=json.dumps(entry.fix_info),
            )
            fix_info_id = fix_info.id

        message = self._get_shared_text(SharedTextKind.message, entry.message)
        filename_record = self._get_shared_text(SharedTextKind.filename, entry.filename)

        # pyre-fixme [9] Incompatible variable type: issue is declared to have type `Issue` but is used as type `munch.Munch`
        instance: IssueInstance = IssueInstance.Record(
            id=instance_id,
            issue_id=issue.id,
            location=self.get_location(entry),
            filename_id=filename_record.id,
            callable_id=callable_record.id,
            run_id=run.id,
            fix_info_id=fix_info_id,
            message_id=message.id,
            rank=0,
            min_trace_length_to_sources=self._get_minimum_trace_length(
                entry.postconditions
            ),
            min_trace_length_to_sinks=self._get_minimum_trace_length(
                entry.preconditions
            ),
            callable_count=callablesCount[callable],
            archive_if_new_issue=self.archive_issue_instances_of_new_issues,
        )

        for sink in final_sink_kinds:
            self.graph.add_issue_instance_shared_text_assoc_id(instance, sink)
        for detail in sink_details:
            self.graph.add_issue_instance_shared_text_assoc(instance, detail)
        for source in initial_source_kinds:
            self.graph.add_issue_instance_shared_text_assoc_id(instance, source)
        for detail in source_details:
            self.graph.add_issue_instance_shared_text_assoc(instance, detail)

        if fix_info is not None:
            self.graph.add_issue_instance_fix_info(instance, fix_info)

        for trace_frame in trace_frames:
            self.graph.add_issue_instance_trace_frame_assoc(instance, trace_frame)

        for feature in entry.features:
            feature = self._get_shared_text(SharedTextKind.feature, feature)
            self.graph.add_issue_instance_shared_text_assoc(instance, feature)

        self.graph.add_issue_instance(instance)

        meta_run_identifier = self.meta_run_identifier
        if self.record_meta_run_issue_instances and meta_run_identifier is not None:
            # Used to deduplicate issue instances across meta runs,
            # see `MetaRunIssueDuplicateFilter`.
            issue_instance_hash = (
                meta_run_issue_duplicate_filter.compute_issue_instance_hash(entry)
            )
            meta_run_issue_instance = MetaRunIssueInstanceIndex.Record(
                issue_instance_id=instance.id,
                meta_run_id=meta_run_identifier,
                issue_instance_hash=issue_instance_hash,
            )
            self.graph.add_meta_run_issue_instance(meta_run_issue_instance)

    # We need to thread filename explicitly since the entry might be a callinfo.
    def _generate_tito(
        self,
        filename: str,
        entry: Union[
            ParseConditionTuple, ParseIssueConditionTuple, ParseTraceAnnotation
        ],
        callable: str,
    ) -> List[SourceLocation]:
        titos = list(entry.titos)
        if len(titos) > 200:
            pre_key: Tuple[str, str, int] = (filename, callable, len(titos))
            big_tito = none_throws(self.summary.big_tito)
            if pre_key not in big_tito:
                log.info("Big Tito: %s", str(pre_key))
                big_tito.add(pre_key)
            titos = titos[:200]
        return titos

    def _generate_issue_traces(
        self,
        kind: TraceKind,
        run: Run,
        issue: ParseIssueTuple,
        callinfo: ParseIssueConditionTuple,
    ) -> Tuple[TraceFrame, Set[int]]:
        # Generates a synthetic trace frame from a forward or backward trace in callinfo
        # that represents a call edge from the issue callable to the start of a
        # a trace.
        # Generate all dependencies of this frame as well.
        caller = issue.callable
        titos = self._generate_tito(issue.filename, callinfo, caller)
        call_tf = self._generate_raw_trace_frame(
            kind,
            run=run,
            filename=issue.filename,
            caller=caller,
            caller_port=callinfo.root_port or "root",
            callee=callinfo.callee,
            callee_port=callinfo.port,
            callee_location=self._convert_to_source_location(callinfo.location),
            leaves=callinfo.leaves,
            type_interval=callinfo.type_interval,
            titos=titos,
            annotations=callinfo.annotations,
            features=callinfo.features,
        )
        caller_leaf_ids = set()
        callee_leaf_ids = set()
        for leaf_map in call_tf.leaf_mapping:
            caller_leaf_ids.add(leaf_map.caller_leaf)
            callee_leaf_ids.add(leaf_map.callee_leaf)
        self._generate_transitive_trace_frames(run, call_tf, callee_leaf_ids)
        return call_tf, caller_leaf_ids

    def _generate_transitive_trace_frames(
        self, run: Run, start_frame: TraceFrame, outgoing_leaf_ids: Set[int]
    ) -> List[TraceFrame]:
        """Generates all trace frames reachable from start_frame, provided they contain
        a leaf_id from the initial set of leaf_ids. Also applies tito transforms
        in reverse, meaning it strips off local transforms from leaf kinds when
        necessary.

        Returns the TraceFrames associated this starting frame (generated or found existing)
        """
        returned_frames = []
        if self.skip_traces:
            return returned_frames

        kind = start_frame.kind
        queue = [(start_frame, outgoing_leaf_ids)]
        while len(queue) > 0:
            frame, outgoing_leaves = queue.pop()
            if len(outgoing_leaves) == 0:
                continue

            returned_frames.append(frame)

            frame_id = frame.id.local_id
            if frame_id in self.visited_frames:
                outgoing_leaves = outgoing_leaves - self.visited_frames[frame_id]
                if len(outgoing_leaves) == 0:
                    continue
                else:
                    self.visited_frames[frame_id].update(outgoing_leaves)
            else:
                self.visited_frames[frame_id] = outgoing_leaves

            next_frames = self._get_or_populate_trace_frames(
                # pyre-fixme[6]: Expected `TraceKind` for 1st param but got `str`.
                kind,
                run,
                frame.callee_id,
                caller_port=frame.callee_port,
            )
            queue.extend(
                [
                    (
                        frame,
                        self.graph.compute_next_leaf_kinds(
                            outgoing_leaves, frame.leaf_mapping
                        ),
                    )
                    for frame in next_frames
                ]
            )
        return returned_frames

    def _get_or_populate_trace_frames(
        self, kind: TraceKind, run: Run, caller_id: DBID, caller_port: str
    ) -> List[TraceFrame]:
        if self.graph.has_trace_frames_with_caller(
            kind, caller_id, caller_port, run.id
        ):
            return self.graph.get_trace_frames_from_caller(
                kind, caller_id, caller_port, run.id
            )
        caller = self.graph.get_text(caller_id)
        key = (caller, caller_port)
        new = [
            self._generate_trace_frame(kind, run, e)
            for e in none_throws(self.trace_entries)[kind].frames_from_caller(
                caller, caller_port
            )
        ]
        if len(new) == 0 and not self.graph.is_leaf_port(key[1]):
            none_throws(self.summary.missing_traces)[kind].add(key)
        return new

    def _generate_trace_frame(
        self, kind: TraceKind, run: Run, entry: ParseConditionTuple
    ) -> TraceFrame:
        titos = self._generate_tito(entry.filename, entry, entry.caller)
        return self._generate_raw_trace_frame(
            kind,
            run=run,
            filename=entry.filename,
            caller=entry.caller,
            caller_port=entry.caller_port,
            callee=entry.callee,
            callee_port=entry.callee_port,
            callee_location=self._convert_to_source_location(entry.callee_location),
            titos=titos,
            leaves=entry.leaves,
            type_interval=entry.type_interval,
            annotations=entry.annotations,
            features=entry.features,
        )

    def _generate_raw_trace_frame(
        self,
        kind: TraceKind,
        run: Run,
        filename: str,
        caller: str,
        caller_port: str,
        callee: str,
        callee_port: str,
        callee_location: SourceLocation,
        titos: List[SourceLocation],
        leaves: Iterable[ParseLeaf],
        type_interval: Optional[ParseTypeInterval],
        annotations: Iterable[ParseTraceAnnotation],
        features: List[ParseTraceFeature],
    ) -> TraceFrame:
        leaf_kind = (
            SharedTextKind.source
            if kind is TraceKind.postcondition
            else SharedTextKind.sink
        )
        lb, ub, preserves_type_context = self._get_interval(type_interval)
        caller_record = self._get_shared_text(SharedTextKind.callable, caller)
        callee_record = self._get_shared_text(SharedTextKind.callable, callee)
        filename_record = self._get_shared_text(SharedTextKind.filename, filename)

        leaf_records = []
        leaf_mapping_ids: Set[LeafMapping] = set()
        for leaf, depth in leaves:
            # avoid writing bad trace_length to DB
            depth = bound_trace_length(depth)
            leaf_record = self._get_shared_text(leaf_kind, leaf)
            caller_leaf_id = self.graph.get_transform_normalized_caller_kind_id(
                leaf_record
            )
            callee_leaf_id = self.graph.get_transformed_callee_kind_id(leaf_record)
            leaf_mapping_ids.add(
                LeafMapping(
                    caller_leaf=caller_leaf_id,
                    callee_leaf=callee_leaf_id,
                    raw_kind=leaf_record.id.local_id,
                )
            )
            leaf_records.append((leaf_record, depth))

        trace_frame: TraceFrame = TraceFrame.Record(
            extra_fields=["leaf_mapping"],
            id=DBID(),
            kind=kind,
            caller_id=caller_record.id,
            caller_port=caller_port,
            callee_id=callee_record.id,
            callee_port=callee_port,
            callee_location=self._convert_to_source_location(callee_location),
            filename_id=filename_record.id,
            titos=[self._convert_to_source_location(t) for t in titos],
            run_id=run.id,
            preserves_type_context=preserves_type_context,
            type_interval_lower=lb,
            type_interval_upper=ub,
            leaf_mapping=leaf_mapping_ids,
            reachability=FrameReachability.unreachable,
        )

        for leaf_record, depth in leaf_records:
            self.graph.add_trace_frame_leaf_assoc(trace_frame, leaf_record, depth)

        # Note that the "graph._trace_frame_leaf_assoc" table is really associated with
        # the xdb table "trace_frame_message_assoc"
        # Putting the features into this assoc table is the correct thing to do, even though
        # the function to put it there is a bit odd.
        # Note that "graph._save_trace_frame_leaf_assoc" which is called by the bulk_saver
        # using "bulk_saver.add_trace_frame_leaf_assoc()" to drop into this table
        # as documented in models.py "class TraceFrameLeafAssoc(Base, PrepareMixin, RecordMixin)"
        for f in features:
            feature_record = self._get_shared_text(SharedTextKind.feature, f.name)
            self.graph.add_trace_frame_leaf_assoc(trace_frame, feature_record, 0)

            if f.locations:
                # To make the UI clearer, only annotate a single feature per line
                loc_dict = {}
                for loc in f.locations:
                    loc_dict[loc.line_no] = loc
                for loc in loc_dict.values():
                    self.graph.add_trace_annotation(
                        TraceFrameAnnotation.Record(
                            id=DBID(),
                            trace_frame_id=trace_frame.id,
                            location=self._convert_to_source_location(loc),
                            kind=None,
                            message=f.name,
                            leaf_id=None,
                            link=None,
                            trace_key=None,
                        )
                    )

        self.graph.add_trace_frame(trace_frame)
        self._generate_trace_annotations(
            trace_frame.id, filename, caller, annotations, run
        )
        return trace_frame

    def _convert_to_source_location(
        self, source_location: SourceLocation
    ) -> SourceLocation:
        if isinstance(source_location, SourceLocation):
            return source_location

        # Parsers may return duck types, so let's convert to
        # real SourceLocations so later pipeline steps can do hash/equality
        # checks on them like normal
        return SourceLocation(
            source_location.line_no,
            source_location.begin_column,
            source_location.end_column,
        )

    def _generate_issue_feature_contents(self, feature: ParseFeature) -> Set[str]:
        # Generates a synthetic feature from the extra/feature
        features = set()
        for key in feature:
            value = feature[key]
            if isinstance(value, str) and value:
                features.add(key + ":" + value)
            else:
                features.add(key)
        return features

    def _get_interval(
        self, ti: Optional[ParseTypeInterval]
    ) -> Tuple[Optional[int], Optional[int], bool]:
        if ti:
            lower = bound_type_interval_limit(ti.start)
            upper = bound_type_interval_limit(ti.finish)
            return (lower, upper, ti.preserves_type_context)
        else:
            return (None, None, False)

    def _generate_trace_annotations(
        self,
        parent_id: DBID,
        parent_filename: str,
        parent_caller: str,
        annotations: Iterable[ParseTraceAnnotation],
        run: Run,
    ) -> None:
        for annotation in annotations:
            location = annotation.location
            leaf_kind = annotation.leaf_kind
            kind = annotation.kind
            (trace_leaf_kind, trace_kind) = (
                (SharedTextKind.sink, TraceKind.precondition)
                if kind == "tito_transform" or kind == "sink"
                else (SharedTextKind.source, TraceKind.postcondition)
            )
            annotation_record = TraceFrameAnnotation.Record(
                id=DBID(),
                trace_frame_id=parent_id,
                location=self._convert_to_source_location(location),
                kind=kind,
                message=annotation.msg,
                leaf_id=(
                    None
                    if not leaf_kind
                    else self._get_shared_text(trace_leaf_kind, leaf_kind).id
                ),
                link=annotation.link,
                trace_key=annotation.trace_key,
            )
            self.graph.add_trace_annotation(annotation_record)

            for trace in annotation.subtraces:
                tf = self._generate_annotation_trace(
                    trace_kind, run, parent_filename, parent_caller, trace, annotation
                )
                self.graph.add_trace_frame_annotation_trace_frame_assoc(
                    annotation_record, tf
                )

    def _generate_annotation_trace(
        self,
        trace_kind: TraceKind,
        run: Run,
        parent_filename: str,
        parent_caller: str,
        trace: ParseTraceAnnotationSubtrace,
        annotation: ParseTraceAnnotation,
    ) -> TraceFrame:
        # Generates the first-hop trace frames from the annotation and
        # all dependencies of these sub traces. If this gets called, it is
        # assumed that the annotation leads to traces, and that the leaf kind
        # and depth are specified.
        callee = trace.callee
        callee_port = trace.port
        features = trace.features
        nested_annotations = trace.annotations
        position = trace.position
        titos = self._generate_tito(parent_filename, annotation, parent_caller)
        call_tf = self._generate_raw_trace_frame(
            trace_kind,
            run,
            parent_filename,
            parent_caller,
            "subtrace_root",
            callee,
            callee_port,
            position,
            titos,
            [(annotation.leaf_kind or "", annotation.leaf_depth)],
            annotation.type_interval,
            nested_annotations,
            features,
        )
        self._generate_transitive_trace_frames(
            run, call_tf, {leaf_map.callee_leaf for leaf_map in call_tf.leaf_mapping}
        )
        return call_tf

    def _get_shared_text(self, kind: SharedTextKind, name: str) -> SharedText:
        return self.graph.get_or_add_shared_text(kind, name)

    @staticmethod
    def get_location(
        entry: ParseIssueTuple, is_relative: bool = False
    ) -> SourceLocation:
        line = entry.line
        if is_relative and entry.callable_line:
            line -= entry.callable_line
        return SourceLocation(line, entry.start, entry.end)
