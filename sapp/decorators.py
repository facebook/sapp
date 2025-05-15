# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import datetime
import logging
import sys
import time
from contextlib import contextmanager
from functools import wraps
from typing import Callable, Generator, List, Optional, ParamSpec, Type, TypeVar

log: logging.Logger = logging.getLogger("sapp")

P = ParamSpec("P")
R = TypeVar("R")


class retryable:
    def __init__(
        self, num_tries: int = 1, retryable_exs: Optional[List[Type[Exception]]] = None
    ) -> None:
        self.num_tries = num_tries
        self.retryable_exs = retryable_exs

    def __call__(self, func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def new_func(*args: P.args, **kwargs: P.kwargs) -> R:
            try_num = 1
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if self.retryable_exs and type(e) not in self.retryable_exs:
                        raise
                    try_num += 1
                    if try_num > self.num_tries:
                        raise

        new_func.__wrapped__ = func
        return new_func


def log_time(func: Callable[P, R]) -> Callable[P, R]:
    """Log the time it takes to run a function. It's sort of like timeit, but
    prettier.
    """

    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        start_time = time.time()
        log.info("%s starting...", func.__name__.title())
        ret = func(*args, **kwargs)
        log.info(
            "%s finished (%s)",
            func.__name__.title(),
            datetime.timedelta(seconds=int(time.time() - start_time)),
        )
        return ret

    return wrapper


class UserError(Exception):
    pass


@contextmanager
def catch_user_error() -> Generator[None, None, None]:
    try:
        yield
    except UserError as error:
        print(str(error), file=sys.stderr)


@contextmanager
def catch_keyboard_interrupt() -> Generator[None, None, None]:
    try:
        yield
    except KeyboardInterrupt:
        print("\nOperation aborted.", file=sys.stderr)
