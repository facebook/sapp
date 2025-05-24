# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import logging
from typing import List, Optional, Set, Tuple

from ..metrics_logger import ScopedMetricsLogger
from . import IssuesAndFrames, PipelineStep, Summary

log: logging.Logger = logging.getLogger("sapp")


class AddFeatures(PipelineStep[IssuesAndFrames, IssuesAndFrames]):
    """Optional pipeline that attaches given features to all issues.
    If the features list is empty, the input is simply passed without
    change as the output"""

    def __init__(self, features: Optional[List[str]]) -> None:
        super().__init__()
        self.features: Set[str] = set(features or [])

    def run(
        self,
        input: IssuesAndFrames,
        summary: Summary,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> Tuple[IssuesAndFrames, Summary]:
        if len(self.features) > 0:
            log.info("Attaching provided features")
            input.issues = [
                issue.with_added_features(self.features) for issue in input.issues
            ]
        return input, summary
