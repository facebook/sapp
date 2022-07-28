# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import logging
from collections import deque
from typing import Set, Tuple

from ..models import DBID, SharedText, SharedTextKind
from ..trace_graph import LeafMapping, TraceGraph
from . import PipelineStep, Summary

# pyre-fixme[5]: Global expression must be annotated.
log = logging.getLogger("sapp")


class AddReverseTraces(PipelineStep[TraceGraph, TraceGraph]):
    """For all issues with a given code and given leaf kind, adds the given new leaf
    name along all reachable reverse traces. The depth increases as the trace
    frames get further away (in the caller->callee direction) from the issue
    frame. Useful for queries in the callee->caller direction.
    """

    def __init__(
        self,
        code: int,
        orig_leaf_name: str,
        orig_leaf_kind: SharedTextKind,
        new_leaf_name: str,
        new_leaf_kind: SharedTextKind,
    ) -> None:
        super().__init__()
        self.code = code
        self.orig_leaf_name = orig_leaf_name
        self.orig_leaf_kind = orig_leaf_kind
        self.new_leaf_name = new_leaf_name
        self.new_leaf_kind = new_leaf_kind

    def run(self, input: TraceGraph, summary: Summary) -> Tuple[TraceGraph, Summary]:
        graph = input

        orig_leaf = graph.get_shared_text(self.orig_leaf_kind, self.orig_leaf_name)
        if orig_leaf is None:
            # nothing todo
            return graph, summary

        # Get all the issue instances within this category
        instances = [
            instance
            for instance in graph.get_issue_instances()
            if self.code == graph.get_issue(instance.issue_id).code
        ]

        # Add all the trace frame ids for all the issue instances
        trace_frames = []
        for instance in instances:
            trace_frames.extend(graph.get_issue_instance_trace_frames(instance))

        # Explore forward (caller -> callee; issue -> leaf)
        queue = deque(
            [
                (frame, 0)
                for frame in trace_frames
                if orig_leaf.id.local_id in graph.get_trace_frame_leaf_ids(frame)
            ]
        )
        depth_by_frame_id = {}
        while len(queue) > 0:
            trace_frame, depth = queue.popleft()
            trace_frame_id = trace_frame.id.local_id

            # Skip repeat frames unless we arrived at them by a shorter path.
            if (
                trace_frame_id in depth_by_frame_id
                and depth >= depth_by_frame_id[trace_frame_id]
            ):
                continue
            else:
                # Record the minimum depth.
                depth_by_frame_id[trace_frame_id] = depth

            # Iterate forward
            queue.extend(
                (next_frame, depth + 1)
                for next_frame in graph.get_next_trace_frames(trace_frame)
                if orig_leaf.id.local_id in graph.get_trace_frame_leaf_ids(next_frame)
            )

        # Create new leaves based on these depths
        leaf = graph.get_shared_text(self.new_leaf_kind, self.new_leaf_name)
        if leaf is None:
            leaf = SharedText.Record(
                id=DBID(),
                contents=self.new_leaf_name,
                kind=self.new_leaf_kind,
            )
            graph.add_shared_text(leaf)

        # Add the assoc to the leaf
        log.info(
            'Adding %d "%s" leaves from issues with code %d...',
            len(depth_by_frame_id),
            self.new_leaf_name,
            self.code,
        )
        for trace_frame_id, depth in depth_by_frame_id.items():
            trace_frame = graph.get_trace_frame_from_id(trace_frame_id)
            leaf_mapping: Set[LeafMapping] = trace_frame.leaf_mapping
            if leaf.kind == SharedTextKind.source or leaf.kind == SharedTextKind.sink:
                leaf_mapping.add(
                    LeafMapping(leaf.id.local_id, leaf.id.local_id, leaf.id.local_id)
                )
            graph.add_trace_frame_leaf_assoc(trace_frame, leaf, depth)

        return graph, summary
