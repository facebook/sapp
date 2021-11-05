# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import logging
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

from .models import DBID, SharedTextKind, TraceFrame, TraceFrameAnnotation, TraceKind
from .trace_graph import TraceGraph

log: logging.Logger = logging.getLogger("sapp")


# Union for queue to recompute trace lengths
@dataclass(frozen=True)
class SearchAction:
    frame: TraceFrame
    remaining_length: int
    leaves: Set[int]


@dataclass(frozen=True)
class ComputeMinAction:
    frame: TraceFrame
    leaves: Set[int]


Action = Union[SearchAction, ComputeMinAction]

# frame_id -> leaf_id -> distance
# Represents that we visited the frame_id looking for leaf kind leaf before.
# There are two cases:
#   distance >= 0 -> we found the leaf within distance hops
#   distance < 0 -> we didn't find the leaf within -distance hops
#
# NOTE: storing the "negative" distance caputres that we did search for leaf
# before and couldn't find it within that many hops. This means that a future
# search with a distance remaining that is less or equal to the previously
# failed distance will also fail. We only revisit if the new visit has more
# "remaining" hops left.
#
# IMPORTANT: The leaf kinds are always the normalized transform kinds, i.e. with
# '@' replaced by ':'. This means we have to be careful at actual leaf-frames to
# compare with the normalized kinds, as well as when updating a frame's trace
# lengths.
Visited = Dict[int, Dict[int, int]]


class TrimmedTraceGraph(TraceGraph):
    """Represents a trimmed graph that is constructed from a bigger TraceGraph
    based on issues that have traces involving a set of affected files or
    directories.
    """

    def __init__(
        self, affected_files: List[str], affected_issues_only: bool = False
    ) -> None:
        """Creates an empty TrimmedTraceGraph."""
        super().__init__()
        self._affected_files = affected_files
        self._affected_issues_only = affected_issues_only
        self._visited_trace_frame_ids: Set[int] = set()

    def populate_from_trace_graph(self, graph: TraceGraph) -> None:
        """Populates this graph from the given one based on affected_files"""
        # Track which trace frames have been visited as we populate the full
        # traces of the graph.
        self._visited_trace_frame_ids: Set[int] = set()

        self._populate_affected_issues(graph)

        if not self._affected_issues_only:
            # Finds issues from the conditions and saves them.
            # Also saves traces that have been trimmed to the affected
            # conditions.
            self._populate_issues_from_affected_trace_frames(graph)

            # Traces populated above may be missing all traces because
            # _populate_issues_from_affected_trace_frames only populates
            # traces that reach the affected conditions in one direction. We
            # may need to populate traces in other directions too.
            #
            # For example:
            #
            # Issue_x reaches affected_file_x via postcondition_x (forward
            # trace, i.e. trace leading to source). None of its backward
            # traces (leading to sinks) reach the affected files.
            #
            # _populate_issues_from_affected_trace_frames would have copied its
            # forward traces and trimmed it to those reaching postcondition_x.
            # We cannot blindly populate all forward traces in this case as
            # branches not leading to postcondition_x are unnecessary.
            #
            # However, in this specific example, all backward traces are needed
            # to give a complete picture of which sinks the issue reaches.
            # The following ensures that.
            for instance_id in self._issue_instances.keys():
                first_hop_ids = self._issue_instance_trace_frame_assoc[instance_id]
                fwd_trace_ids = {
                    tf_id
                    for tf_id in first_hop_ids
                    if self._trace_frames[tf_id].kind == TraceKind.POSTCONDITION
                }
                bwd_trace_ids = {
                    tf_id
                    for tf_id in first_hop_ids
                    if self._trace_frames[tf_id].kind == TraceKind.PRECONDITION
                }
                if len(fwd_trace_ids) == 0:
                    self._populate_issue_trace(
                        graph, instance_id, TraceKind.POSTCONDITION
                    )

                if len(bwd_trace_ids) == 0:
                    self._populate_issue_trace(
                        graph, instance_id, TraceKind.PRECONDITION
                    )

        self._recompute_instance_properties(graph)

    # pyre-fixme[3]: Return type must be annotated.
    def _recompute_instance_properties(self, graph: TraceGraph):
        """Some properties of issue instances will be affected after trimming
        such as min trace length to leaves. This should be called after the
        trimming to re-compute these values.
        """
        callables_histo = Counter(
            inst.callable_id.local_id for inst in self._issue_instances.values()
        )

        # frame_id -> leaf_id -> min_trace
        # where min_trace is negative k, if we didn't reach the leaf in k hops
        visited: Visited = {}

        for inst in self._issue_instances.values():
            # log.info(
            #     "recomputing props for %d",
            #     inst.id.local_id,
            # )

            inst.min_trace_length_to_sources = self._get_min_depth_to_sources(
                visited,
                inst.id.local_id,
                inst.min_trace_length_to_sources,
            )
            inst.min_trace_length_to_sinks = self._get_min_depth_to_sinks(
                visited,
                inst.id.local_id,
                inst.min_trace_length_to_sinks,
            )
            inst.callable_count = callables_histo[inst.callable_id.local_id]

    def _get_min_depth_to_sources(
        self, visited: Visited, instance_id: int, prior: Optional[int]
    ) -> Optional[int]:
        """Returns shortest depth to source from the issue instance. Instances
        have a pre-computed min_trace_length_to_source, but this can change
        after traces get trimmed from the graph. This re-computes it and
        returns the min.
        """
        if prior is None:
            return None

        first_hop_tf_ids = {
            tf_id
            for tf_id in self._issue_instance_trace_frame_assoc[instance_id]
            if self.get_trace_frame_from_id(tf_id).kind == TraceKind.POSTCONDITION
        }
        return self._recompute_trace_length_association(
            visited, first_hop_tf_ids, SharedTextKind.source
        )

    def _get_min_depth_to_sinks(
        self, visited: Visited, instance_id: int, prior: Optional[int]
    ) -> Optional[int]:
        """See get_min_depths_to_sources."""
        if prior is None:
            return None

        first_hop_tf_ids = {
            tf_id
            for tf_id in self._issue_instance_trace_frame_assoc[instance_id]
            if self.get_trace_frame_from_id(tf_id).kind == TraceKind.PRECONDITION
        }
        return self._recompute_trace_length_association(
            visited, first_hop_tf_ids, SharedTextKind.sink
        )

    def _map_info(self, v: Dict[int, int]) -> str:
        return ", ".join(
            [f"{self._get_local_text(key)} -> {d}" for key, d in v.items()]
        )

    def _remaining_leaves(
        self,
        remaining_length: int,
        leaves: Set[int],
        visited: Visited,
        frame_id: int,
    ) -> Set[int]:
        """Given a visit to frame_id with remaining_length and looking for the given
        leaves, compute whether we already have visited this frame under some of
        these leaves. Returns the remaining leaves that will need to be visited
        for the children. There are multiple cases:

        1. we have visited the frame_id before and found a distance to the leaf,
        remove the leaf.

        2. we have visited the frame_id before but didn't finish the visit
        because it didn't lead to the leaf before we ran out of trace length (or
        we are recursively visiting it). In that case, the negative number
        stored is the length we looked for. If we have more remaining_length
        left now, we revisit the leaf, otherwise we don't.

        For the leaves we will search in children, we update the visited state
        to indicate that this is on the stack by adding -remaining_length to the
        visited state.

        """
        assert remaining_length > 0
        if frame_id in visited:
            visited_leaves = visited[frame_id]
            # figure out what needs to be visited still
            # log.info("    old visited: %s", self._map_info(visited_leaves))
            visit_leaves = {
                leaf_id: -remaining_length
                for leaf_id in leaves
                if leaf_id not in visited_leaves
                or visited_leaves[leaf_id] < 0
                and -visited_leaves[leaf_id] < remaining_length
            }
            visited[frame_id].update(visit_leaves)
            # log.info("    new visited: %s", self._map_info(visited[frame_id]))
            return set(visit_leaves.keys())
        else:
            # first time. Put remaining trace lengths (pending)
            visited[frame_id] = {leaf_id: -remaining_length for leaf_id in leaves}
            # log.info("    first visit: %s", self._map_info(visited[frame_id]))
            return leaves

    def _get_text(self, id: DBID) -> str:
        return self.get_shared_text_by_local_id(id.local_id).contents

    def _get_local_text(self, id: int) -> str:
        return self.get_shared_text_by_local_id(id).contents

    def _frame_info(self, frame: TraceFrame) -> str:
        return (
            f"frame_id:{frame.id.local_id} "
            f"caller:{self._get_text(frame.caller_id)} "
            f"caller_port:{frame.caller_port} "
            f"callee:{self._get_text(frame.callee_id)} "
            f"callee_port:{frame.callee_port} "
            f"interval:[{frame.type_interval_lower},{frame.type_interval_upper}]"
        )

    def _recompute_trace_length_association(
        self, visited: Visited, initial_frames: Set[int], leaf_kind: SharedTextKind
    ) -> int:

        """Walks the traces starting at the initial frames with the initial
        corresponding kinds to recompute and store the minimum trace length from each
        reachable frame to the corresponding leaf."""

        max_trace_length = 100
        infinite_trace_length = 9999
        stack: List[Action] = [
            SearchAction(
                frame=self.get_trace_frame_from_id(frame_id),
                remaining_length=max_trace_length,
                leaves=self.get_caller_leaf_kinds_of_frame(
                    self.get_trace_frame_from_id(frame_id)
                ),
            )
            for frame_id in initial_frames
        ]

        while len(stack) > 0:
            todo = stack.pop()
            if isinstance(todo, SearchAction):
                # log.info(
                #     "  search %s, remaining %d leaves: %s",
                #     self._frame_info(todo.frame),
                #     todo.remaining_length,
                #     " ".join(
                #         [self._get_local_text(leaf_id) for leaf_id in todo.leaves]
                #     ),
                # )
                frame_id = todo.frame.id.local_id
                leaves = self._remaining_leaves(
                    todo.remaining_length, todo.leaves, visited, frame_id
                )
                if len(leaves) == 0 or todo.remaining_length <= 1:
                    continue

                # log.info(
                #     "    remaining leaves: %s",
                #     " ".join([self._get_local_text(leaf_id) for leaf_id in leaves]),
                # )

                if self.is_leaf_port(todo.frame.callee_port):
                    actual_leaves = {}
                    for leaf_id in self.get_trace_frame_leaf_ids_by_kind(
                        todo.frame, leaf_kind
                    ):
                        leaf = self.get_shared_text_by_local_id(leaf_id)
                        leaf_id = self.get_transform_normalized_kind_id(leaf)
                        actual_leaves[leaf_id] = 0
                    visited[frame_id].update(actual_leaves)
                    # log.info(
                    #     "    leaf result %s",
                    #     self._map_info(actual_leaves),
                    # )
                    continue

                successors = []
                (successor_frames, succ_leaf_kinds) = self._get_successor_frames(
                    self,
                    leaves,
                    todo.frame,
                )
                if len(succ_leaf_kinds) > 0:
                    for next_frame in successor_frames:
                        successors.append(
                            SearchAction(
                                frame=next_frame,
                                remaining_length=todo.remaining_length - 1,
                                leaves=succ_leaf_kinds,
                            )
                        )
                # Note: list append/pop both work from the tail, so we have to
                # append the ComputeMin first before the search on the children.
                stack.append(
                    ComputeMinAction(
                        todo.frame,
                        leaves,
                    )
                )
                stack.extend(successors)

            elif isinstance(todo, ComputeMinAction):
                visit_result = visited[todo.frame.id.local_id]
                # log.info(
                #     "  compute min %s, leaves: %s",
                #     self._frame_info(todo.frame),
                #     " ".join(
                #         [f"{self._get_local_text(leaf_id)}" for leaf_id in todo.leaves]
                #     ),
                # )
                for leaf_id in todo.leaves:
                    # log.info("    looking for %s", self._get_local_text(leaf_id))
                    (successors, succ_leaves) = self._get_successor_frames(
                        self,
                        {leaf_id},
                        todo.frame,
                    )
                    if len(succ_leaves) > 0:
                        # log.info(
                        #     "      succ_leaves %s",
                        #     ", ".join([self._get_local_text(id) for id in succ_leaves]),
                        # )
                        for succ in successors:
                            for succ_leaf_id, length in visited[
                                succ.id.local_id
                            ].items():
                                if succ_leaf_id in succ_leaves:
                                    if length >= 0 and (
                                        length + 1 < visit_result[leaf_id]
                                        or visit_result[leaf_id] < 0
                                    ):
                                        visit_result[leaf_id] = length + 1
                                    elif (
                                        length < 0
                                        and length - 1 > visit_result[leaf_id]
                                    ):
                                        visit_result[leaf_id] = length - 1
                frame_result = {}
                frame_leaves = self.get_trace_frame_leaf_ids_with_depths(todo.frame)
                for frame_leaf_id in frame_leaves:
                    frame_leaf = self.get_shared_text_by_local_id(frame_leaf_id)
                    if (
                        frame_leaf.kind != SharedTextKind.source
                        and frame_leaf.kind != SharedTextKind.sink
                    ):
                        continue
                    normalized_frame_leaf_id = self.get_transform_normalized_kind_id(
                        frame_leaf
                    )
                    if normalized_frame_leaf_id in todo.leaves:
                        if visit_result[normalized_frame_leaf_id] < 0:
                            frame_result[frame_leaf_id] = infinite_trace_length
                        else:
                            frame_result[frame_leaf_id] = visit_result[
                                normalized_frame_leaf_id
                            ]

                # log.info(
                #     "    frame_result: %s",
                #     self._map_info(frame_result),
                # )
                # log.info(
                #     "    visit_result: %s",
                #     self._map_info(visit_result),
                # )
                visited[todo.frame.id.local_id].update(visit_result)
                self.get_trace_frame_leaf_ids_with_depths(todo.frame).update(
                    frame_result
                )

        # compute minimum over all initial frames/leaves
        result = infinite_trace_length
        for frame_id in initial_frames:
            for _, length in visited[frame_id].items():
                if length >= 0 and length < result:
                    result = length
        return result

    def _populate_affected_issues(self, graph: TraceGraph) -> None:
        """Populates the trimmed graph with issues whose locations are in
        affected_files based on data in the input graph. Since these issues
        exist in the affected files, all traces are copied as well.
        """
        affected_instance_ids = [
            instance.id.local_id
            for instance in graph._issue_instances.values()
            if self._is_filename_prefixed_with(
                graph.get_text(instance.filename_id), self._affected_files
            )
        ]

        for instance_id in affected_instance_ids:
            if instance_id in self._issue_instances:
                continue
            self._populate_issue_and_traces(graph, instance_id)

    def _get_sink_kinds(self, graph: TraceGraph, instance_id: int) -> Set[int]:
        kind: SharedTextKind = SharedTextKind.SINK
        sinks = graph.get_issue_instance_shared_texts(instance_id, kind)
        return {sink.id.local_id for sink in sinks}

    def _get_source_kinds(self, graph: TraceGraph, instance_id: int) -> Set[int]:
        kind: SharedTextKind = SharedTextKind.SOURCE
        sources = graph.get_issue_instance_shared_texts(instance_id, kind)
        return {source.id.local_id for source in sources}

    def _get_instance_leaf_ids(self, graph: TraceGraph, instance_id: int) -> Set[int]:
        return self._get_source_kinds(graph, instance_id).union(
            self._get_sink_kinds(graph, instance_id)
        )

    def _populate_issues_from_affected_trace_frames(self, graph: TraceGraph) -> None:
        """TraceFrames found in affected_files should be reachable via some
        issue instance. Follow traces of graph to find them and
        populate this TrimmedGraph with it.
        """

        initial_trace_frames = [
            trace_frame
            for trace_frame in graph._trace_frames.values()
            if self._is_filename_prefixed_with(
                graph.get_text(trace_frame.filename_id), self._affected_files
            )
        ]

        self._populate_issues_from_affected_conditions(
            initial_trace_frames,
            graph,
        )

    def _get_issue_instances_from_frame_id(
        self, graph: TraceGraph, trace_frame_id: int
    ) -> Set[int]:
        return graph._trace_frame_issue_instance_assoc[trace_frame_id]

    def _get_predecessor_frames(
        self, graph: TraceGraph, leaves: Set[int], trace_frame: TraceFrame
    ) -> List[Tuple[TraceFrame, Set[int]]]:
        """Returns predecessor frames paired with leaf kinds to follow for those frames"""
        result = []
        # pyre-fixme[6]: Enums and str are the same but Pyre doesn't think so.
        for trace_frame_id in graph._trace_frames_rev_map[trace_frame.kind][
            (trace_frame.caller_id.local_id, trace_frame.caller_port)
        ]:
            predecessor = graph._trace_frames[trace_frame_id]
            assert predecessor.leaf_mapping is not None
            pred_kinds = graph.compute_prev_leaf_kinds(leaves, predecessor.leaf_mapping)
            result.append((predecessor, pred_kinds))
        return result

    def _get_successor_frames(
        self, graph: TraceGraph, leaves: Set[int], trace_frame: TraceFrame
    ) -> Tuple[List[TraceFrame], Set[int]]:
        """Returns successor frames and successor leaf_kind pair"""
        result = []
        assert trace_frame.leaf_mapping is not None
        succ_kinds = graph.compute_next_leaf_kinds(leaves, trace_frame.leaf_mapping)
        # pyre-fixme[6]: Enums and str are the same but Pyre doesn't think so.
        for trace_frame_id in graph._trace_frames_map[trace_frame.kind][
            (trace_frame.callee_id.local_id, trace_frame.callee_port)
        ]:
            successor = graph._trace_frames[trace_frame_id]
            result.append(successor)
        return (result, succ_kinds)

    def _populate_issues_from_affected_conditions(
        self,
        # pyre-fixme[2]: Parameter must be annotated.
        initial_conditions,
        graph: TraceGraph,
    ) -> None:
        """Helper for populating reachable issue instances from the initial
        pre/postconditions. Also populates conditions/traces reachable from
        these instances. Traces are populated only in the direction this is
        called from: i.e. if initial_conditions are preconditions, only the
        backward trace is populated.

        Params:
        initial_conditions: The initial collection of pre/postconditions to
        start searching for issues from.

        graph: The trace graph to search for issues. Nodes/edges in this graph
        will be copied over to the local state
        """
        visited: Dict[int, Set[int]] = {}
        stack = [
            # We will be using these leaf kinds to look for matching callers. So
            # we need the caller view of the kinds.
            (frame, graph.get_caller_leaf_kinds_of_frame(frame))
            for frame in initial_conditions
        ]

        # Note that parent conditions may not transitively lead to the leaves
        # that its descendents lead to due to special-cased leaf filtering at
        # analysis time. When visiting each condition, we need to track the
        # leaves that we are visiting it from and only visit parent traces that
        # share common leaves along the path.
        while len(stack) > 0:
            condition, leaves = stack.pop()
            cond_id = condition.id.local_id

            if cond_id in visited:
                leaves = leaves - visited[cond_id]
                if len(leaves) == 0:
                    continue
                else:
                    visited[cond_id].update(leaves)
            else:
                visited[cond_id] = leaves

            # Found instance(s) related to the current condition. Yay.
            # This instance may have been found before, but process it again
            # anyway because we need to add the assoc with this condition.
            for instance_id in self._get_issue_instances_from_frame_id(graph, cond_id):
                # Check if the leaves (sources/sinks) of the issue reach
                # the same leaves as the ones relevant to this condition.
                instance = graph._issue_instances[instance_id]
                issue_leaves = set(
                    self._get_instance_leaf_ids(graph, instance.id.local_id)
                )
                common_leaves = issue_leaves.intersection(leaves)
                if len(common_leaves) > 0:
                    if instance_id not in self._issue_instances:
                        self._populate_issue(graph, instance_id)
                    self.add_issue_instance_trace_frame_assoc(instance, condition)

            # Conditions that call this may have originated from other issues,
            # keep searching for parent conditions leading to this one.
            for (next_frame, frame_leaves) in self._get_predecessor_frames(
                graph, leaves, condition
            ):
                if len(frame_leaves) > 0:
                    stack.append((next_frame, frame_leaves))

        # Add traces leading out from initial_conditions, and all visited
        # conditions leading back towards the issues.
        initial_condition_ids = [
            condition.id.local_id for condition in initial_conditions
        ]
        self._populate_trace(graph, initial_condition_ids)
        for frame_id in visited:
            self._add_trace_frame(graph, graph._trace_frames[frame_id])

    def _populate_issue_and_traces(self, graph: TraceGraph, instance_id: int) -> None:
        """Copies an issue over from the given trace graph, including all its
        traces and assocs.
        """
        self._populate_issue(graph, instance_id)
        self._populate_issue_trace(graph, instance_id)

    def _populate_issue_trace(
        self, graph: TraceGraph, instance_id: int, kind: Optional[TraceKind] = None
    ) -> None:
        trace_frame_ids = list(graph._issue_instance_trace_frame_assoc[instance_id])
        instance = graph._issue_instances[instance_id]
        filtered_ids = []
        for trace_frame_id in trace_frame_ids:
            frame = graph._trace_frames[trace_frame_id]
            if kind is None or kind == frame.kind:
                self.add_issue_instance_trace_frame_assoc(instance, frame)
                filtered_ids.append(trace_frame_id)
        self._populate_trace(graph, filtered_ids)

    def _populate_issue(self, graph: TraceGraph, instance_id: int) -> None:
        """Adds an issue to the trace graph along with relevant information
        pertaining to the issue (e.g. instance, fix_info, sources/sinks)
        The issue is identified by its corresponding instance's ID in the input
        trace graph.
        """
        instance = graph._issue_instances[instance_id]
        issue = graph._issues[instance.issue_id.local_id]
        self._populate_shared_text(graph, instance.message_id)
        self._populate_shared_text(graph, instance.filename_id)
        self._populate_shared_text(graph, instance.callable_id)

        self.add_issue_instance(instance)
        self.add_issue(issue)

        if instance_id in graph._issue_instance_fix_info:
            issue_fix_info = graph._issue_instance_fix_info[instance_id]
            self.add_issue_instance_fix_info(instance, issue_fix_info)

        for shared_text_id in graph._issue_instance_shared_text_assoc[instance_id]:
            shared_text = graph._shared_texts[shared_text_id]
            if shared_text_id not in self._shared_texts:
                self.add_shared_text(shared_text)
            self.add_issue_instance_shared_text_assoc(instance, shared_text)

    def _populate_trace(self, graph: TraceGraph, trace_frame_ids: List[int]) -> None:
        """Populates (from the given trace graph) the forward and backward
        traces reachable from the given traces (including input trace frames).
        Make sure to respect trace kind in successors
        """
        while len(trace_frame_ids) > 0:
            trace_frame_id = trace_frame_ids.pop()
            if trace_frame_id in self._visited_trace_frame_ids:
                continue

            trace_frame = graph._trace_frames[trace_frame_id]
            self._add_trace_frame(graph, trace_frame)
            self._visited_trace_frame_ids.add(trace_frame_id)

            trace_frame_ids.extend(
                [
                    next_frame.id.local_id
                    for next_frame in graph.get_next_trace_frames(trace_frame)
                    if next_frame.id.local_id not in self._visited_trace_frame_ids
                ]
            )

    def _add_trace_frame(self, graph: TraceGraph, trace_frame: TraceFrame) -> None:
        """Copies the trace frame from 'graph' to this (self) graph.
        Also copies all the trace_frame-leaf assocs since we don't
        know which ones are needed until we know the issue that reaches it
        """
        trace_frame_id = trace_frame.id.local_id
        self.add_trace_frame(trace_frame)

        annotations = graph.get_condition_annotations(trace_frame_id)
        for annotation in annotations:
            self._add_trace_annotation(graph, annotation)

        self._populate_shared_text(graph, trace_frame.filename_id)
        self._populate_shared_text(graph, trace_frame.caller_id)
        self._populate_shared_text(graph, trace_frame.callee_id)
        for (leaf_id, depth) in graph._trace_frame_leaf_assoc[trace_frame_id].items():
            leaf = graph._shared_texts[leaf_id]
            if leaf_id not in self._shared_texts:
                self.add_shared_text(leaf)
            self.add_trace_frame_leaf_assoc(trace_frame, leaf, depth)

    @staticmethod
    def _is_filename_prefixed_with(filename: str, prefixes: Iterable[str]) -> bool:
        return any(filename.startswith(p) for p in prefixes)

    # pyre-fixme[2]: Parameter must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    def _populate_shared_text(self, graph, id) -> None:
        text = graph._shared_texts[id.local_id]
        if text.id.local_id not in self._shared_texts:
            self.add_shared_text(text)

    def _add_trace_annotation(
        self, graph: TraceGraph, annotation: TraceFrameAnnotation
    ) -> None:
        """Copies the annotation from 'graph' to this (self) graph.
        Also copies children TraceFrames of the annotation (if any). The
        parent TraceFrame of the annotation is NOT copied.
        """
        self.add_trace_annotation(annotation)
        children = graph.get_annotation_trace_frames(annotation.id.local_id)
        child_ids = [child.id.local_id for child in children]
        for child in children:
            self.add_trace_frame_annotation_trace_frame_assoc(annotation, child)
        self._populate_trace(graph, child_ids)
