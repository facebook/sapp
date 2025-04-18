# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from typing import Set, Tuple

from ..metrics_logger import ScopedMetricsLogger

from . import DictEntries, ParseIssueTuple, PipelineStep, Summary


class WarningCodeFilter(PipelineStep[DictEntries, DictEntries]):
    def __init__(self, codes_to_keep: Set[int]) -> None:
        self.codes_to_keep: Set[int] = codes_to_keep

    def _should_skip_issue(self, issue: ParseIssueTuple) -> bool:
        return issue.code not in self.codes_to_keep

    def run(
        self,
        input: DictEntries,
        summary: Summary,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> Tuple[DictEntries, Summary]:
        filtered_issues = []
        for issue in input["issues"]:
            if self._should_skip_issue(issue):
                continue
            filtered_issues.append(issue)

        input["issues"] = filtered_issues

        return input, summary
