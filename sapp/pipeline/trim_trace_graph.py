# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import logging
from typing import List, Tuple

from ..metrics_logger import ScopedMetricsLogger

from ..trace_graph import TraceGraph
from ..trimmed_trace_graph import TrimmedTraceGraph
from . import PipelineStep, Summary

log: logging.Logger = logging.getLogger("sapp")


class TrimTraceGraph(PipelineStep[TraceGraph, List[TraceGraph]]):
    def run(
        self,
        input: TraceGraph,
        summary: Summary,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> Tuple[List[TraceGraph], Summary]:
        if not summary["affected_file_sets"]:
            return [input], summary

        trimmed_graphs = []
        for run, affected_files in zip(
            summary["runs"], summary["affected_file_sets"], strict=True
        ):
            if affected_files is None:
                trimmed_graphs.append(input)
            else:
                log.info("Trimming graph to affected files.")
                trimmed_graph = TrimmedTraceGraph(
                    affected_files,
                    summary.get("affected_issues_only", False),
                    run.id,
                )
                trimmed_graph.populate_from_trace_graph(input)
                trimmed_graphs.append(trimmed_graph)
        return trimmed_graphs, summary
