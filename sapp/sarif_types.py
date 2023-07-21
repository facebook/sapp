# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import sys
from enum import Enum
from typing import Dict, List, Optional, TypedDict, Union


if sys.version_info >= (3, 10):
    from typing import TypeAlias
else:
    from typing_extensions import TypeAlias


class SARIFSeverityLevel(Enum):
    WARNING = "warning"
    ERROR = "error"
    NOTE = "note"
    NONE = "none"

    def __str__(self) -> str:
        return self.value


class SARIFRegionObject(TypedDict, total=False):
    startLine: int
    startColumn: int
    endColumn: int


class SARIFMessageObject(TypedDict):
    text: str


class SARIFArtifactLocationObject(TypedDict, total=False):
    uri: Optional[str]
    uriBaseId: str


class SARIFPhyicalLocationObject(TypedDict):
    artifactLocation: SARIFArtifactLocationObject
    region: Union[SARIFRegionObject, Dict[None, None]]


class SARIFCodeflowLocationInnerObject(TypedDict, total=False):
    physicalLocation: SARIFPhyicalLocationObject
    message: SARIFMessageObject


class SARIFCodeflowLocationObject(TypedDict):
    location: SARIFCodeflowLocationInnerObject
    nestingLevel: int


class SARIFThreadFlowObject(TypedDict):
    locations: List[SARIFCodeflowLocationObject]


class SARIFCodeflowObject(TypedDict):
    threadFlows: List[SARIFThreadFlowObject]


SARIFCodeflowsObject: TypeAlias = List[SARIFCodeflowObject]


class SARIFResult(TypedDict):
    ruleId: str
    level: str
    message: SARIFMessageObject
    locations: List[SARIFCodeflowLocationInnerObject]
    codeFlows: SARIFCodeflowsObject
