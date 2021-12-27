# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import logging
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple

from ..models import IssueInstance, SharedTextKind, TraceFrame, TraceKind
from ..trace_graph import TraceGraph
from . import PipelineStep, Summary

log: logging.Logger = logging.getLogger("sapp")


class PerSinkState:
    def __init__(self) -> None:
        self.shared_text_trace_lengths: Dict[int, int] = defaultdict(lambda: 999999)


FrameID = int
SinkToSharedTextMap = Dict[int, Set[int]]
SinkToState = Dict[int, PerSinkState]


class PropagateSharedTexts(PipelineStep[TraceGraph, TraceGraph]):  # pyre-fixme[13]
    """For all issues propagate source kinds and features to all reachable frames
    leading to sinks and propagate features to leaf sinks.
    """

    def __init__(self, propagate_sources: bool, propagate_features: bool) -> None:
        super().__init__()
        self.summary: Summary
        self.graph: TraceGraph
        self.propagate_sources = propagate_sources
        self.propagate_features = propagate_features
        # pyre-fixme[8]
        self.visited: Dict[FrameID, SinkToState] = defaultdict(
            lambda: defaultdict(lambda: PerSinkState())
        )

    def _subtract_kinds(
        self,
        trace_length: int,
        to_propagate: SinkToSharedTextMap,
        visited: SinkToState,
    ) -> SinkToSharedTextMap:
        """Prunes the search space by eliminating sources and features that have already
        been visited at a closer distance than our current trace length"""
        result = {}
        for sink_kind, shared_texts in to_propagate.items():
            if sink_kind in visited:
                shared_text_trace_lengths = visited[sink_kind].shared_text_trace_lengths
                shared_texts = {
                    to_propagate
                    for to_propagate in shared_texts
                    if trace_length < shared_text_trace_lengths.get(to_propagate, 99999)
                }
            if len(shared_texts) > 0:
                result[sink_kind] = shared_texts
        return result

    def _update_visited(
        self,
        frame_id: FrameID,
        trace_length: int,
        kind_map: SinkToSharedTextMap,
    ) -> None:
        visited_frame = self.visited[frame_id]
        for sink_kind, shared_texts in kind_map.items():
            for shared_text in shared_texts:
                trace_length_to_use = trace_length
                # Normally, when we decrease the distance of a source, we want to keep going
                # to decrease the distance on all subsequent frames.
                # But for features, we don't care about this.
                # Just set the depth low immediately when visited regardless of the
                # actual distance visited, so that
                # work is not wasted propagating such decreases.
                kind = self.graph.get_shared_text_by_local_id(shared_text).kind
                if kind is SharedTextKind.FEATURE:
                    trace_length_to_use = 0
                visited_frame[sink_kind].shared_text_trace_lengths[
                    shared_text
                ] = trace_length_to_use

    def _propagate_shared_texts(self, instance: IssueInstance) -> None:
        """Propagate the source kinds and features of this issue instance to all
        reachable sink traces."""
        graph = self.graph

        features = {
            text.id.local_id
            for text in graph.get_issue_instance_shared_texts(
                instance.id.local_id, SharedTextKind.FEATURE
            )
        }
        initial_frames = graph.get_issue_instance_trace_frames(instance)
        initial_source_frames = [
            frame for frame in initial_frames if frame.kind == TraceKind.POSTCONDITION
        ]
        initial_sink_frames = [
            frame for frame in initial_frames if frame.kind == TraceKind.PRECONDITION
        ]
        source_kind_list = [
            graph.get_caller_leaf_kinds_of_frame(frame)
            for frame in initial_source_frames
        ]

        shared_text_kinds = set.union(*source_kind_list).union(features)
        if len(shared_text_kinds) == 0:
            return
        initial_trace_length = instance.min_trace_length_to_sources or 0
        self._propagate_kinds_along_traces(
            initial_sink_frames, shared_text_kinds, initial_trace_length
        )

    def _propagate_kinds_along_traces(
        self,
        start_frames: List[TraceFrame],
        to_propagate: Set[int],
        initial_trace_length: int,
    ) -> None:
        graph = self.graph

        queue = deque(
            [
                (
                    start_frame,
                    {
                        sink_id: to_propagate
                        for sink_id in graph.get_caller_leaf_kinds_of_frame(start_frame)
                    },
                    initial_trace_length,
                )
                for start_frame in start_frames
            ]
        )
        while len(queue) > 0:
            frame, kind_map, trace_length = queue.popleft()
            if len(kind_map) == 0:
                continue

            frame_id = frame.id.local_id
            if frame_id in self.visited:
                kind_map = self._subtract_kinds(
                    trace_length, kind_map, self.visited[frame_id]
                )
                if len(kind_map) == 0:
                    continue

            self._update_visited(frame_id, trace_length, kind_map)

            next_frames = self.graph.get_trace_frames_from_caller(
                # pyre-fixme[6]: Expected `TraceKind` for 1st param but got `str`.
                frame.kind,
                frame.callee_id,
                frame.callee_port,
            )

            queue.extend(
                (
                    frame,
                    # account for transforms of sinks by this frame here
                    {
                        leaf_map.callee_leaf: kind_map[leaf_map.caller_leaf]
                        for leaf_map in frame.leaf_mapping
                        if leaf_map.caller_leaf in kind_map
                    },
                    trace_length + 1,
                )
                for frame in next_frames
            )

    def run(self, input: TraceGraph, summary: Summary) -> Tuple[TraceGraph, Summary]:
        if not (self.propagate_sources or self.propagate_features):
            return input, summary

        graph = input
        self.summary = summary
        self.graph = graph

        if self.propagate_sources:
            log.info("Propagating source kinds to sinks")

        if self.propagate_features:
            log.info("Propagating features to anchor sinks")

        for instance in graph.get_issue_instances():
            self._propagate_shared_texts(instance)

        # Create new assocs based on the visited results
        source_count = 0
        feature_count = 0
        trace_frame_count = 0
        for trace_frame_id, sink_to_state in self.visited.items():
            trace_frame_count += 1
            trace_frame = graph.get_trace_frame_from_id(trace_frame_id)
            is_anchor_port = trace_frame.callee_port.startswith("anchor:")
            for state in sink_to_state.values():
                for (
                    shared_text,
                    trace_length,
                ) in state.shared_text_trace_lengths.items():
                    shared_text_kind = graph.get_shared_text_by_local_id(
                        shared_text
                    ).kind
                    if (
                        self.propagate_sources
                        and shared_text_kind == SharedTextKind.SOURCE
                    ):
                        graph.add_trace_frame_leaf_by_local_id_assoc(
                            trace_frame, shared_text, trace_length
                        )
                        source_count += 1
                    if (
                        self.propagate_features
                        and is_anchor_port
                        and shared_text_kind == SharedTextKind.FEATURE
                    ):
                        graph.add_trace_frame_leaf_by_local_id_assoc(
                            trace_frame, shared_text, depth=None
                        )
                        feature_count += 1
        log.info(
            f"Added {source_count} source kinds and {feature_count} features to {trace_frame_count} trace frames"
        )

        return graph, summary
