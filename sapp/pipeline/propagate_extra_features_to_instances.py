# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import logging
from collections import defaultdict, deque
from typing import Dict, Set, Tuple

from ..metrics_logger import ScopedMetricsLogger
from ..models import SharedTextKind, TraceFrame
from ..trace_graph import TraceGraph
from . import PipelineStep, Summary

log: logging.Logger = logging.getLogger("sapp")

FrameID = int
FeatureID = int
KindID = int
InstanceID = int


class PerTaintKindState:
    def __init__(self) -> None:
        self.shared_texts: Set[FeatureID] = set()


TaintKindToFeaturesMap = Dict[KindID, Set[FeatureID]]
TaintKindToState = Dict[KindID, PerTaintKindState]


class PropagateExtraFeaturesToInstances(PipelineStep[TraceGraph, TraceGraph]):
    """Propagates extra features added by previous pipeline steps to certain frames
    upwards towards instances so they can be filtered on after processing.
    The propagation must
    - take into account kinds and transforms (in future intervals)
    - deal with features on subtraces and propagate them onto main traces
    """

    def __init__(
        self,
    ) -> None:
        super().__init__()
        # pyre-fixme[13]: Attribute `summary` is never initialized.
        self.summary: Summary
        # pyre-fixme[13]: Attribute `graph` is never initialized.
        self.graph: TraceGraph
        # pyre-fixme[8]: Expected `Dict[FrameID, TaintKindToState]` for param 1
        self.visited: Dict[FrameID, TaintKindToState] = defaultdict(
            lambda: defaultdict(lambda: PerTaintKindState())
        )
        self.instance_features: Dict[InstanceID, Set[FeatureID]] = defaultdict(
            lambda: set()
        )
        # Intermediate points where subtraces connect to parent traces. We need to
        # inline the breadcrumbs here to until we perform search generally on all
        # subtraces.
        self.parent_frame_features: Dict[FrameID, Set[FeatureID]] = defaultdict(
            lambda: set()
        )
        self.instance_features_added: int = 0
        self.instances: int = 0
        self.parent_frames: int = 0
        self.parent_frame_features_added: int = 0

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

    def _propagate_features_by_kinds_along_traces(
        self,
        start_frame: TraceFrame,
        features_to_propagate: Set[FeatureID],
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

            # check if this frame is a root frame and record features on instance
            if self._is_root_port(frame.caller_port):
                instance_ids = self.graph.get_issue_instances_for_root_frame(
                    frame.id.local_id
                )
                acceptable_incoming_kinds = graph.get_caller_leaf_kinds_of_frame(frame)
                features = set()
                for kind, extra_features in kind_map.items():
                    if kind in acceptable_incoming_kinds:
                        features.update(extra_features)

                for instance_id in instance_ids:
                    self.instance_features[instance_id].update(features)

            elif self._is_subtrace_root_port(frame.caller_port):
                annotations = self.graph._trace_frame_trace_frame_annotation_assoc[
                    frame_id
                ]
                # Grab all features independent of kind from subtrace to push towards
                # main trace.  as we don't know how to map kinds from subtrace to main
                # trace
                parent_features = set()
                for _, extra_features in kind_map.items():
                    parent_features.update(extra_features)
                for annotation_id in annotations:
                    annotation = self.graph.get_trace_annotation(annotation_id)
                    parent_frame_id = annotation.trace_frame_id
                    parent_frame = self.graph.get_trace_frame_from_id(
                        parent_frame_id.local_id
                    )
                    # Record inlining features onto parent frame until we search
                    # subtraces in general from UI/scripts, etc
                    self.parent_frame_features[parent_frame_id.local_id].update(
                        parent_features
                    )
                    queue.append(
                        (
                            parent_frame,
                            {
                                leaf_map.caller_leaf: parent_features
                                for leaf_map in parent_frame.leaf_mapping
                            },
                        )
                    )
            else:
                # Otherwise find previous frames
                prev_frames = self.graph.get_trace_frames_from_callee(
                    # pyre-fixme[6]: Expected `TraceKind` for 1st param but got `str`.
                    frame.kind,
                    frame.caller_id,
                    frame.caller_port,
                )

                queue.extend(
                    (
                        frame,
                        # account for transforms by this frame here
                        {
                            leaf_map.caller_leaf: kind_map[leaf_map.callee_leaf]
                            for leaf_map in frame.leaf_mapping
                            if leaf_map.callee_leaf in kind_map
                        },
                    )
                    for frame in prev_frames
                )

    def _is_root_port(self, port: str) -> bool:
        return port == "root" or port.startswith("root:")

    def _is_subtrace_root_port(self, port: str) -> bool:
        return port == "subtrace_root" or port.startswith("subtrace_root:")

    def run(
        self,
        input: TraceGraph,
        summary: Summary,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> Tuple[TraceGraph, Summary]:
        graph = input
        self.summary = summary
        self.graph = graph

        log.info("Propagating extra features from previous steps towards issues")

        marker_feature = graph.get_or_add_shared_text(
            SharedTextKind.feature, "sapp-upward-propagated-breadcrumbs"
        )
        for frame_id, features in graph.get_extra_features_to_propagate_up().items():
            frame = graph.get_trace_frame_from_id(frame_id)
            self._propagate_features_by_kinds_along_traces(frame, features)

        # Add breadcrumbs to parent_frames
        for parent_frame_id, features in self.parent_frame_features.items():
            self.parent_frames += 1
            for feature_id in features:
                self.graph.add_trace_frame_id_leaf_by_local_id_assoc(
                    parent_frame_id, feature_id, 0
                )
                self.parent_frame_features_added += 1

        # Add breadcrumbs to instances
        for instance_id, features in self.instance_features.items():
            self.instances += 1
            self.graph.add_issue_instance_id_shared_text_assoc_id(
                instance_id, marker_feature.id.local_id
            )
            for feature_id in features:
                self.graph.add_issue_instance_id_shared_text_assoc_id(
                    instance_id, feature_id
                )
                self.instance_features_added += 1

        log.info(
            f"Added {self.instance_features_added} features to {self.instances}"
            + f" instances, and {self.parent_frame_features_added}"
            + f" features to {self.parent_frames}"
        )

        return graph, summary
