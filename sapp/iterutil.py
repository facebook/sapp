# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import itertools
from typing import Iterable, Iterator, List, TypeVar

T = TypeVar("T")


def split_every(n: int, iterable: Iterable[T]) -> Iterator[List[T]]:
    """Yields batches of size 'n' from an iterable:

    list(split_every(2, range(10))) => [[0, 1], [2, 3], [4, 5], [6, 7], [8, 9]]
    """
    i = iter(iterable)
    piece = list(itertools.islice(i, n))
    while piece:
        yield piece
        piece = list(itertools.islice(i, n))
