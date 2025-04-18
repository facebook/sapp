# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict
from abc import ABC, abstractmethod
from typing import Mapping, Optional


class MetricsLogger(ABC):
    """
    Extend this class to log timing metrics to a backend of your choice
    """

    @abstractmethod
    def log_timing(
        self,
        key: str,
        start_perf_counter: float,
        extra_data: Optional[Mapping[str, str]] = None,
    ) -> None:
        pass
