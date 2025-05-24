# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import logging
from typing import Tuple

from ..db import DB
from ..metrics_logger import ScopedMetricsLogger
from ..models import create as create_models
from . import IssuesAndFrames, PipelineStep, Summary

log: logging.Logger = logging.getLogger("sapp")


class CreateDatabase(PipelineStep[IssuesAndFrames, IssuesAndFrames]):
    def __init__(self, database: DB) -> None:
        super().__init__()
        self.database = database

    def run(
        self,
        input: IssuesAndFrames,
        summary: Summary,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> Tuple[IssuesAndFrames, Summary]:
        create_models(self.database)
        return input, summary
