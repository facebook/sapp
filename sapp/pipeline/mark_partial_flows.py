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
from ..models import IssueInstance, SharedText, SharedTextKind, TraceFrame, TraceKind
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


# A full flow context is a map from a partial issue code to a set of frame keys,
# i.e. places where we've seen relevant # transforms happen in the full flows.
# This is used to add breadcrumbs at matching spots for partial flows.
FullFlowContext = dict[int, set[FrameKey]]


# Returns a set of transforms for the given frame. `local_only` controls whether non-local
# transforms are also included in the returned set.
def _get_transforms(
    graph: TraceGraph, frame: TraceFrame, *, local_only: bool
) -> set[str]:
    leaf_mappings = frame.leaf_mapping
    if leaf_mappings is None:
        return set()
    transforms = set()
    for leaf_mapping in leaf_mappings:
        unparsed = graph.get_shared_text_by_local_id(leaf_mapping.transform).contents
        if "@" in unparsed:
            split_by_local = unparsed.split("@")
            local_transforms = split_by_local[0].split(":")
            transforms.update(local_transforms)
            if not local_only:
                global_transforms = split_by_local[1].split(":")[:-1]
                transforms.update(global_transforms)
        elif not local_only:
            transforms.update(unparsed.split(":")[:-1])
    return transforms


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
    local_transforms = _get_transforms(graph, frame, local_only=True)
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
        self.partial_flow_frames = 0

    def _dfs_mark_partial_flows_for_frame_memoized(
        self,
        graph: TraceGraph,
        frame: TraceFrame,
        feature_to_add: SharedText,
        context: set[FrameKey],
        visited: dict[int, bool],
    ) -> bool:
        """
        Evaluates to whether we added a partial flow anywhere reachable from `frame`.

        After evaluation, this function will mutate `visited` for `frame`
        with the information of whether anything transitively reachable from
        `frame` was marked with a partial flow, keyed by the frame's local id.
        """

        # We use an explicit stack to avoid Python's recursion limits (Python
        # stack frames are quite expensive).
        # The gist of the algorithm is that we add every frame to the stack twice,
        # the first time to mark the children for DFS, and the second time in order
        # to set the final result for the frame.
        # If true, the bool parameter indicates that all children are already
        # processed, and that we can trust the visited[frame_id] value for all
        # children as being final.
        stack: list[tuple[TraceFrame, bool]] = [(frame, False)]
        while stack:
            frame, children_processed = stack.pop()
            frame_id = frame.id.local_id
            if not children_processed:
                # This is the first time we're visiting the node, push ourselves
                # and all children to the stack and continue. The second
                # pass will be responsible for ensuring the value of
                # `visited[frame_id]` is correct.
                if frame_id in visited:
                    continue
                # Add a dummy value to visited to avoid re-queueing this frame.
                visited[frame_id] = False
                # We add the current frame with True first so that it gets processed
                # after all children are done.
                stack.append((frame, True))
                next_frames = graph.get_trace_frames_from_caller(
                    # pyre-fixme[6]: Expected `TraceKind` for 1st param but got `str`.
                    frame.kind,
                    frame.callee_id,
                    frame.callee_port,
                )
                for next_frame in next_frames:
                    stack.append((next_frame, False))
            else:
                # This is the second time we're seeing the node, we need to populate
                # `visited` for this frame id with the final result.
                key = FrameKey.from_frame(frame)
                added_breadcrumb = False
                if key in context:
                    graph.add_trace_frame_leaf_by_local_id_assoc(
                        frame, feature_to_add.id.local_id, depth=None
                    )
                    self.partial_flow_frames += 1
                    added_breadcrumb = True
                next_frames = graph.get_trace_frames_from_caller(
                    # pyre-fixme[6]: Expected `TraceKind` for 1st param but got `str`.
                    frame.kind,
                    frame.callee_id,
                    frame.callee_port,
                )
                for next_frame in next_frames:
                    added_breadcrumb = (
                        added_breadcrumb or visited[next_frame.id.local_id]
                    )
                visited[frame_id] = added_breadcrumb
        return visited[frame.id.local_id]

    def _mark_partial_flows_for_code(
        self,
        graph: TraceGraph,
        instances: Iterable[IssueInstance],
        feature_name: str,
        context: set[FrameKey],
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
        visited = {}
        for instance in instances:
            issue_instance_frames = list(
                graph.get_issue_instance_trace_frames(instance)
            )
            added_breadcrumb = False
            for frame in issue_instance_frames:
                added_breadcrumb = (
                    added_breadcrumb
                    or self._dfs_mark_partial_flows_for_frame_memoized(
                        graph, frame, feature_to_add, context, visited
                    )
                )

            if added_breadcrumb:
                graph.add_issue_instance_shared_text_assoc_id(
                    instance, feature_to_add.id.local_id
                )

    def _mark_partial_flows(
        self,
        graph: TraceGraph,
        issues: dict[int, list[IssueInstance]],
        context: FullFlowContext,
    ) -> None:
        visited_partial_issue_codes = set()
        for partial_flow_to_mark in self.partial_flows_to_mark:
            if partial_flow_to_mark.partial_issue_code in visited_partial_issue_codes:
                continue
            visited_partial_issue_codes.add(partial_flow_to_mark.partial_issue_code)
            self._mark_partial_flows_for_code(
                graph,
                issues[partial_flow_to_mark.partial_issue_code],
                partial_flow_to_mark.feature,
                context[partial_flow_to_mark.partial_issue_code],
            )
        pass

    def _build_flow_context_by_searching_graph(
        self,
        graph: TraceGraph,
        issue_instance_frames: list[TraceFrame],
        context: set[FrameKey],
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
        context: set[FrameKey],
        is_prefix_flow: bool,
        full_issue_transform: str,
        visited: set[int],
    ) -> None:
        """
        Iterates through an issue, updating `context` in-place.
        """
        # Go through postcondition half of trace.
        initial_postcondition_frames, initial_precondition_frames = [], []
        for frame in graph.get_issue_instance_trace_frames(full_instance):
            if frame.kind == TraceKind.POSTCONDITION:
                initial_postcondition_frames.append(frame)
            else:
                initial_precondition_frames.append(frame)
        if is_prefix_flow:
            # In the prefix flow case, a transform in any precondition frame would
            # cause the root frame to be marked, so avoid traversal and consider all
            # transforms.
            for frame in initial_precondition_frames:
                transforms = _get_transforms(graph, frame, local_only=False)
                if full_issue_transform in transforms:
                    for frame in initial_postcondition_frames:
                        context.add(FrameKey.from_frame(frame))
                    break
            # Search preconditions for the transform. If we find the transform here
            # for a prefix flow, the initial postcondition frame must be marked instead.
            self._build_flow_context_by_searching_graph(
                graph,
                initial_postcondition_frames,
                context,
                full_instance,
                visited,
                transform=full_issue_transform,
            )
        else:
            for frame in initial_postcondition_frames:
                transforms = _get_transforms(graph, frame, local_only=False)
                if full_issue_transform in transforms:
                    for frame in initial_precondition_frames:
                        context.add(FrameKey.from_frame(frame))
                    break
            self._build_flow_context_by_searching_graph(
                graph,
                initial_precondition_frames,
                context,
                full_instance,
                visited,
                transform=full_issue_transform,
            )

    def _build_full_flow_context(
        self,
        graph: TraceGraph,
        issues: dict[int, list[IssueInstance]],
    ) -> FullFlowContext:
        visited = set()
        # The full flow context is a mapping from partial issue code -> frames to mark. Each issue
        # will mark frames for the corresponding set of frames to mark.
        context: FullFlowContext = defaultdict(set)
        for partial_flow in self.partial_flows_to_mark:
            for issue in issues[partial_flow.full_issue_code]:
                self._build_candidates_to_transform_from_larger_issue(
                    graph,
                    issue,
                    context[partial_flow.partial_issue_code],
                    partial_flow.is_prefix_flow,
                    partial_flow.full_issue_transform,
                    visited,
                )
        return context

    def run(self, input: TraceGraph, summary: Summary) -> tuple[TraceGraph, Summary]:
        if len(self.partial_flows_to_mark) == 0:
            return (input, summary)

        log.info("Marking partial flows...")
        graph = input
        full_issue_codes: set[int] = set()
        partial_issue_codes: set[int] = set()
        issues: dict[int, list[IssueInstance]] = defaultdict(list)

        for partial_flow_to_mark in self.partial_flows_to_mark:
            full_issue_codes.add(partial_flow_to_mark.full_issue_code)
            partial_issue_codes.add(partial_flow_to_mark.partial_issue_code)

        for instance in graph.get_issue_instances():
            issue = graph.get_issue(instance.issue_id)
            if issue.code in full_issue_codes or issue.code in partial_issue_codes:
                issues[issue.code].append(instance)

        context = self._build_full_flow_context(graph, issues)
        log.info("Built full flow context.")
        self._mark_partial_flows(graph, issues, context)
        log.info(f"Added partial flow features to {self.partial_flow_frames} frames.")
        return graph, summary
