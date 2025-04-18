# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict
from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Iterator


class MetricsLogger(ABC):
    """
    Extend this class to log timing metrics to a backend of your choice
    """

    @abstractmethod
    @contextmanager
    def log_timing(
        self,
        key: str,
    ) -> Iterator[ScopedMetricsLogger]:
        """
        A context manager that logs the time it takes to between entering and exiting

        The caller can append extra logging data to the ScopedMetricsLogger
        """
        pass


class ScopedMetricsLogger(ABC):
    """
    Used to add supplimentary data that will be logged
    when the enclosing scope finishes (ex: when the timer metric is logged)
    """

    def __init__(self, logger: MetricsLogger) -> None:
        self.logger = logger

    def get_logger(self) -> MetricsLogger:
        return self.logger

    @abstractmethod
    def add_data(self, key: str, value: str) -> None:
        pass


class NoOpMetricsLogger(MetricsLogger):
    """
    A MetricsLogger that does nothing
    """

    @contextmanager
    def log_timing(
        self,
        key: str,
    ) -> Iterator[ScopedMetricsLogger]:
        yield NoOpScopedMetricsLogger(self)


class NoOpScopedMetricsLogger(ScopedMetricsLogger):
    """
    A ScopedMetricsLogger that does nothing
    """

    def add_data(
        self,
        key: str,
        value: str,
    ) -> None:
        pass
