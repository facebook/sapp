# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import functools
import logging
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple

from ..models import IssueInstance, SharedTextKind, TraceFrame, TraceKind
from ..trace_graph import TraceGraph
from . import PipelineStep, Summary

log: logging.Logger = logging.getLogger("sapp")


class PerTaintKindState:
    def __init__(self) -> None:
        self.shared_texts: Set[int] = set()


FrameID = int
TaintKindToFeaturesMap = Dict[int, Set[int]]
TaintKindToState = Dict[int, PerTaintKindState]


class PropagateContextToLeafFrames(PipelineStep[TraceGraph, TraceGraph]):
    """For all issues matching a certain code, propagate features matching a
    pattern to all reachable leaf frames for a particular frame_kind."""

    def __init__(
        self, issue_code: int, feature_pattern: str, frame_kind: TraceKind
    ) -> None:
        super().__init__()
        # pyre-fixme[13]: Attribute `summary` is never initialized.
        self.summary: Summary
        # pyre-fixme[13]: Attribute `graph` is never initialized.
        self.graph: TraceGraph
        self.feature_pattern = feature_pattern
        self.issue_code = issue_code
        self.frame_kind = frame_kind
        # pyre-fixme[8]: Expected `Dict[FrameID, TaintKindToState]` for 1st param but got `defaultdict`.
        self.visited: Dict[FrameID, TaintKindToState] = defaultdict(
            lambda: defaultdict(lambda: PerTaintKindState())
        )
        self.leaf_features_added = 0
        self.leaf_frames = 0

    def _subtract_kinds(
        self,
        to_propagate: TaintKindToFeaturesMap,
        visited: TaintKindToState,
    ) -> TaintKindToFeaturesMap:
        """Prunes the search space by eliminating features that have already
        been visited"""
        result = {}
        for taint_kind, shared_texts in to_propagate.items():
            if taint_kind in visited:
                shared_texts = shared_texts.difference(visited[taint_kind].shared_texts)
            if len(shared_texts) > 0:
                result[taint_kind] = shared_texts
        return result

    def _update_visited(
        self,
        frame_id: FrameID,
        taint_kind_map: TaintKindToFeaturesMap,
    ) -> None:
        visited_frame = self.visited[frame_id]
        for taint_kind, shared_texts in taint_kind_map.items():
            visited_frame_kind_state = visited_frame[taint_kind]
            visited_frame_kind_state.shared_texts = shared_texts.union(
                visited_frame_kind_state.shared_texts
            )

    def _feature_matches(self, text: str) -> bool:
        return self.feature_pattern in text

    def _propagate_shared_texts(self, instance: IssueInstance) -> None:
        """Propagate the features to leaf frames"""
        graph = self.graph

        features = {
            text.id.local_id
            for text in graph.get_issue_instance_shared_texts(
                instance.id.local_id, SharedTextKind.FEATURE
            )
            if self._feature_matches(text.contents)
        }
        if len(features) <= 0:
            return

        initial_frames = [
            frame
            for frame in graph.get_issue_instance_trace_frames(instance)
            if frame.kind == self.frame_kind
        ]
        self._propagate_features_by_kinds_along_traces(
            initial_frames,
            features,
        )

    def _propagate_features_by_kinds_along_traces(
        self,
        start_frames: List[TraceFrame],
        features_to_propagate: Set[int],
    ) -> None:
        graph = self.graph

        queue = deque(
            [
                (
                    start_frame,
                    {
                        taint_kind_id: features_to_propagate
                        for taint_kind_id in graph.get_caller_leaf_kinds_of_frame(
                            start_frame
                        )
                    },
                )
                for start_frame in start_frames
            ]
        )
        while len(queue) > 0:
            frame, kind_map = queue.popleft()
            if len(kind_map) == 0:
                continue

            frame_id = frame.id.local_id
            if frame_id in self.visited:
                kind_map = self._subtract_kinds(kind_map, self.visited[frame_id])
                if len(kind_map) == 0:
                    continue

            self._update_visited(frame_id, kind_map)

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
                )
                for frame in next_frames
            )

    def _final_feature_text(self, original_feature: str) -> str:
        # strip always- and add context-
        return "context-" + original_feature.removeprefix("always-")

    def _add_contextual_features_to_frame(
        self, trace_frame: TraceFrame, features: Set[int]
    ) -> None:
        for feature_id in features:
            feature_text = self.graph.get_shared_text_by_local_id(feature_id)
            feature_to_add = self._final_feature_text(feature_text.contents)
            shared_text_to_add = self.graph.get_or_add_shared_text(
                SharedTextKind.FEATURE,
                feature_to_add,
            )
            self.graph.add_trace_frame_leaf_by_local_id_assoc(
                trace_frame, shared_text_to_add.id.local_id, depth=None
            )
            self.leaf_features_added += 1

    def _is_root_port(self, port: str) -> bool:
        return port == "root" or port.startswith("port:")

    def _add_contextual_features_to_neighbor_frames(
        self, trace_frame: TraceFrame, features: Set[int]
    ) -> None:
        """Root frames will not be shared among the context providing and context
        needing flows. We need to propagate onto root frames at same call site. If
        the context providing frame is a root frame, we may also need to propagate
        onto non-root frames.
        """
        candidates = self.graph.get_all_trace_frames_from_caller(
            # pyre-fixme[6]: Expected `TraceKind` for 1st param but got `str`.
            trace_frame.kind,
            trace_frame.caller_id,
        )
        is_root = self._is_root_port(trace_frame.caller_port)
        for candidate in candidates:
            if (
                candidate.callee_location != trace_frame.callee_location
                or candidate.callee_port != trace_frame.callee_port
                or candidate.callee_id.local_id != trace_frame.callee_id.local_id
            ):
                continue

            if self._is_root_port(candidate.caller_port) or is_root:
                self._add_contextual_features_to_frame(candidate, features)

    def run(self, input: TraceGraph, summary: Summary) -> Tuple[TraceGraph, Summary]:
        graph = input
        self.summary = summary
        self.graph = graph

        log.info(
            f"Propagating feature {self.feature_pattern} in issues {self.issue_code} to {self.frame_kind} leaves"
        )

        for instance in graph.get_issue_instances():
            if self.issue_code == graph.get_issue(instance.issue_id).code:
                self._propagate_shared_texts(instance)

        # Create new assocs based on the visited leaf frames.
        for trace_frame_id, taint_kind_to_state in self.visited.items():
            trace_frame = graph.get_trace_frame_from_id(trace_frame_id)
            if self.graph.is_leaf_port(trace_frame.callee_port):
                # union propagated features (now independent of kind)
                features = functools.reduce(
                    lambda a, b: a.union(b.shared_texts),
                    taint_kind_to_state.values(),
                    set(),
                )
                self.leaf_frames += 1
                self._add_contextual_features_to_frame(trace_frame, features)
                self._add_contextual_features_to_neighbor_frames(trace_frame, features)
        log.info(
            f"Added {self.leaf_features_added} features to {self.leaf_frames} trace frames"
        )

        return graph, summary
