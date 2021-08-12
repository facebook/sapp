# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import logging
from typing import List, Optional, Set, Tuple

from . import DictEntries, PipelineStep, Summary

log: logging.Logger = logging.getLogger("sapp")


class AddFeatures(PipelineStep[DictEntries, DictEntries]):
    """Optional pipeline that attaches given features to all issues.
    If the features list is empty, the input is simply passed without
    change as the output"""

    def __init__(self, features: Optional[List[str]]) -> None:
        super().__init__()
        self.features: Set[str] = set(features or [])

    def run(self, input: DictEntries, summary: Summary) -> Tuple[DictEntries, Summary]:
        if len(self.features) > 0:
            log.info("Attaching provided features")
            input["issues"] = [
                issue._replace(features=list(set(issue.features) | self.features))
                for issue in input["issues"]
            ]
        return input, summary
