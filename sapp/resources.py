# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from typing import Dict

from .constant import Constant

STRING_CONSTANTS: Dict[Constant, str] = {
    Constant.GRAPHQL_PACKAGE: "<unknown>",
    Constant.STRUCTURED_LOGGER_PACKAGE: "<unknown>",
}


def get_string(constant: Constant) -> str:
    resource = STRING_CONSTANTS.get(constant)
    if resource is not None:
        return resource

    raise NotImplementedError(f"Unknown string constant `{constant}`")
