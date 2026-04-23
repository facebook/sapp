# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

TYPECHECK_ERROR = 102


class AIException(Exception):
    pass


class AIRecoverableException(AIException):
    pass


class AIProcessException(AIRecoverableException):
    # pyre-fixme[2]: Parameter must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    def __init__(self, message, error_code) -> None:
        super().__init__(message)
        self.error_code = error_code


class ParseTypeException(Exception):
    pass
