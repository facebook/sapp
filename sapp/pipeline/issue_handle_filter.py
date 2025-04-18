# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from typing import Set, Tuple

from ..metrics_logger import ScopedMetricsLogger

from . import DictEntries, ParseIssueTuple, PipelineStep, Summary


class IssueHandleFilter(PipelineStep[DictEntries, DictEntries]):
    def __init__(
        self,
        handles_to_keep: Set[str],
    ) -> None:
        self.handles_to_keep = handles_to_keep

    def _should_keep_issue(self, issue: ParseIssueTuple) -> bool:
        return issue.handle in self.handles_to_keep

    def run(
        self,
        input: DictEntries,
        summary: Summary,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> Tuple[DictEntries, Summary]:
        input["issues"] = [
            issue for issue in input["issues"] if self._should_keep_issue(issue)
        ]
        return input, summary
