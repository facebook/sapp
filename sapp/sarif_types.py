# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from enum import Enum
from typing import Dict, Union, List

from typing_extensions import TypeAlias


class SARIFSeverityLevel(Enum):
    WARNING = "warning"
    ERROR = "error"
    NOTE = "note"
    NONE = "none"

    def __str__(self) -> str:
        return self.value


SARIFResult: TypeAlias = Dict[
    str,
    Union[
        Dict[str, str],
        List[Dict[str, Dict[str, Union[Dict[str, int], Dict[str, str]]]]],
        str,
    ],
]
