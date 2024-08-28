# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import logging
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable

from ..analysis_output import PartialFlowToMark

from ..models import IssueInstance, SharedTextKind, TraceFrame, TraceKind
from ..trace_graph import TraceGraph
from . import PipelineStep, SourceLocation, Summary

log: logging.Logger = logging.getLogger("sapp")


class PerTaintKindState:
    def __init__(self) -> None:
        self.shared_texts: set[int] = set()


# A frame key is an issue-code-agnostic identifier for frames we're looking
# to associate between a longer flow and a partial flow.
# The dataclass is frozen to ensure we can use these as dict keys.
@dataclass(eq=True, frozen=True)
class FrameKey:
    caller_id: int
    # callee_id is unnecessary because callee_location is sufficiently unique.
    callee_location: SourceLocation

    @classmethod
    def from_frame(cls, frame: TraceFrame) -> "FrameKey":
        return cls(
            caller_id=frame.caller_id.local_id,
            callee_location=frame.callee_location,
        )


# A full flow context is a set of frame keys, i.e. places where we've seen relevant
# transforms happen in the full flows. This is used to add breadcrumbs at matching
# spots for partial flows.
FullFlowContext = set[FrameKey]


# Returns a tuple of (local_transforms, global_transforms) for a given frame.
def _get_all_transforms(
    graph: TraceGraph, frame: TraceFrame
) -> tuple[set[str], set[str]]:
    leaf_mappings = frame.leaf_mapping
    if leaf_mappings is None:
        return set(), set()
    all_local_transforms, all_global_transforms = set(), set()

    for leaf_mapping in leaf_mappings:
        unparsed = graph.get_shared_text_by_local_id(leaf_mapping.transform).contents
        if "@" in unparsed:
            split_by_local = unparsed.split("@")
            local_transforms = split_by_local[0].split(":")
            all_local_transforms.update(local_transforms)
            global_transforms = split_by_local[1].split(":")[:-1]
            all_global_transforms.update(global_transforms)
        else:
            all_global_transforms.update(unparsed.split(":")[:-1])
    return all_local_transforms, all_global_transforms


def _get_local_transform_frame_key(
    graph: TraceGraph, frame: TraceFrame, desired_transform: str
) -> FrameKey | None:
    """
    Returns the local transforms for a trace frame by parsing the
    transform's text. In general, the kind is specified as `T1:T2@T3:T4:S`,
    where the transforms happening locally on the frame are colon-separated
    before the `@`.

    The output is represented as a map from local transform name to frame keys, where
    we return the frame keys each local transform happens in.
    """
    local_transforms, _ = _get_all_transforms(graph, frame)
    if desired_transform in local_transforms:
        return FrameKey.from_frame(frame)
    return None


class MarkPartialFlows(PipelineStep[TraceGraph, TraceGraph]):
    """Given a list of (full flow rule, partial flow rule) pairs, mark all frames in
    the partial flows that have a corresponding full flow with a breadcrumb."""

    def __init__(
        self,
        partial_flows_to_mark: list[PartialFlowToMark],
    ) -> None:
        super().__init__()

        self.partial_flows_to_mark = partial_flows_to_mark
        self.partial_flow_features_added = 0
        self.partial_flow_frames = 0

    def _mark_partial_flows(
        self,
        graph: TraceGraph,
        instances: Iterable[IssueInstance],
        feature_name: str,
        context: FullFlowContext,
    ) -> None:
        """
        Goes through the trace subgraphs of each issue instance that's passed
        in, looking for frame matches using `context`. If a match is found,
        the `"{feature_name}"` breadcrumb will be added for each matching
        issue instance.
        """

        feature_to_add = graph.get_or_add_shared_text(
            SharedTextKind.FEATURE, f"{feature_name}"
        )
        for instance in instances:
            issue_instance_frames = list(
                graph.get_issue_instance_trace_frames(instance)
            )
            queue = deque(issue_instance_frames)
            added_breadcrumb = False
            visited = set()
            while len(queue) > 0:
                frame = queue.popleft()
                frame_id = frame.id.local_id
                if frame_id in visited:
                    continue
                visited.add(frame_id)
                # Queue next frames.
                next_frames = graph.get_trace_frames_from_caller(
                    # pyre-fixme[6]: Expected `TraceKind` for 1st param but got `str`.
                    frame.kind,
                    frame.callee_id,
                    frame.callee_port,
                )
                key = FrameKey.from_frame(frame)
                if key in context:
                    graph.add_trace_frame_leaf_by_local_id_assoc(
                        frame, feature_to_add.id.local_id, depth=None
                    )
                    self.partial_flow_frames += 1
                    self.partial_flow_features_added += 1
                    added_breadcrumb = True

                queue.extend((frame for frame in next_frames))

            if added_breadcrumb:
                graph.add_issue_instance_shared_text_assoc_id(
                    instance, feature_to_add.id.local_id
                )

    def _build_flow_context_by_searching_graph(
        self,
        graph: TraceGraph,
        issue_instance_frames: list[TraceFrame],
        context: FullFlowContext,
        instance: IssueInstance,
        visited: set[int],
        transform: str,
    ) -> None:
        """
        Does a BFS iteration through the subgraph induced by the initial frames.
        The `initial_frames_to_mark` variable controls what happens
        if we find a relevant transform in the full issue. If it's None, that means that
        we should mark the local frame where the transform happened. Otherwise, we mark
        the passed-in frames. See the `PartialFlowToMark` class' comments for more detail.
        """
        queue = deque(issue_instance_frames)
        while len(queue) > 0:
            frame = queue.popleft()
            frame_id = frame.id.local_id
            if frame_id in visited:
                continue
            visited.add(frame_id)
            # Queue next frames.
            next_frames = graph.get_trace_frames_from_caller(
                # pyre-fixme[6]: Expected `TraceKind` for 1st param but got `str`.
                frame.kind,
                frame.callee_id,
                frame.callee_port,
            )
            queue.extend((frame for frame in next_frames))

            frame_key = _get_local_transform_frame_key(graph, frame, transform)
            if frame_key is not None:
                context.add(frame_key)

    def _build_candidates_to_transform_from_larger_issue(
        self,
        graph: TraceGraph,
        full_instance: IssueInstance,
        context: FullFlowContext,
        partial_flow_to_mark: PartialFlowToMark,
        visited: set[int],
    ) -> None:
        """
        Iterates through an issue, updating `context` in-place.
        """
        # Go through postcondition half of trace.
        initial_postcondition_frames = [
            frame
            for frame in graph.get_issue_instance_trace_frames(full_instance)
            if frame.kind == TraceKind.POSTCONDITION
        ]
        initial_precondition_frames = [
            frame
            for frame in graph.get_issue_instance_trace_frames(full_instance)
            if frame.kind == TraceKind.PRECONDITION
        ]
        if partial_flow_to_mark.is_prefix_flow:
            # In the prefix flow case, a transform in any precondition frame would
            # cause the root frame to be marked, so avoid traversal and consider all
            # transforms.
            for frame in initial_precondition_frames:
                local_transforms, global_transforms = _get_all_transforms(graph, frame)
                if (
                    partial_flow_to_mark.full_issue_transform in local_transforms
                    or partial_flow_to_mark.full_issue_transform in global_transforms
                ):
                    for frame in initial_postcondition_frames:
                        context.add(FrameKey.from_frame(frame))
                    break
                    # context.add(FrameKey.from_frame(frame))
            # Search preconditions for the transform. If we find the transform here
            # for a prefix flow, the initial postcondition frame must be marked instead.
            self._build_flow_context_by_searching_graph(
                graph,
                initial_postcondition_frames,
                context,
                full_instance,
                visited,
                transform=partial_flow_to_mark.full_issue_transform,
            )
        else:
            for frame in initial_postcondition_frames:
                local_transforms, global_transforms = _get_all_transforms(graph, frame)
                if (
                    partial_flow_to_mark.full_issue_transform in local_transforms
                    or partial_flow_to_mark.full_issue_transform in global_transforms
                ):
                    for frame in initial_precondition_frames:
                        context.add(FrameKey.from_frame(frame))
                    break
            self._build_flow_context_by_searching_graph(
                graph,
                initial_precondition_frames,
                context,
                full_instance,
                visited,
                transform=partial_flow_to_mark.full_issue_transform,
            )

    def _build_full_flow_context(
        self,
        graph: TraceGraph,
        issues: Iterable[IssueInstance],
        partial_flow_to_mark: PartialFlowToMark,
    ) -> FullFlowContext:
        visited = set()
        context = set()
        for issue in issues:
            self._build_candidates_to_transform_from_larger_issue(
                graph, issue, context, partial_flow_to_mark, visited
            )
        return context

    def run(self, input: TraceGraph, summary: Summary) -> tuple[TraceGraph, Summary]:
        if len(self.partial_flows_to_mark) == 0:
            return (input, summary)

        graph = input

        for partial_flow_to_mark in self.partial_flows_to_mark:
            full_issues: list[IssueInstance] = []
            partial_issues: list[IssueInstance] = []
            for instance in graph.get_issue_instances():
                issue = graph.get_issue(instance.issue_id)
                if issue.code == partial_flow_to_mark.full_issue_code:
                    full_issues.append(instance)
                elif issue.code == partial_flow_to_mark.partial_issue_code:
                    partial_issues.append(instance)
            # This is a naive implementation that repeats work. If we end up
            # having lots of # partial flows, it would be more efficient to
            # first collect all full # flow categories and then apply the
            # context to each partial category.
            context = self._build_full_flow_context(
                graph, full_issues, partial_flow_to_mark
            )
            self._mark_partial_flows(
                graph, partial_issues, partial_flow_to_mark.feature, context
            )
            log.info(
                f"Added {self.partial_flow_features_added} partial flow features to {self.partial_flow_frames} frames."
            )
        return graph, summary
