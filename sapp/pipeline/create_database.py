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
from . import DictEntries, PipelineStep, Summary

log: logging.Logger = logging.getLogger("sapp")


class CreateDatabase(PipelineStep[DictEntries, DictEntries]):
    def __init__(self, database: DB) -> None:
        super().__init__()
        self.database = database

    def run(
        self,
        input: DictEntries,
        summary: Summary,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> Tuple[DictEntries, Summary]:
        create_models(self.database)
        return input, summary
