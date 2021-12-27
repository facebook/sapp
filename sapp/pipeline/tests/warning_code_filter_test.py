# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from unittest import TestCase

from .. import ParseIssueTuple, Pipeline
from ..warning_code_filter import WarningCodeFilter


class TestWarningCodeFilter(TestCase):
    def setUp(self) -> None:
        self.warning_code_filter = WarningCodeFilter({6000})

    @staticmethod
    def make_fake_issue(code: int) -> ParseIssueTuple:
        return ParseIssueTuple(
            code,
            "",
            "",
            "",
            "",
            0,
            0,
            0,
            [],
            [],
            [],
            [],
            [],
            0,
            {},
        )

    def test_filter_codes(self) -> None:
        dict_entries = {
            "issues": list(
                map(TestWarningCodeFilter.make_fake_issue, [6000, 6001, 6002])
            )
        }
        output, _ = Pipeline([self.warning_code_filter]).run(dict_entries)

        self.assertEqual(len(output["issues"]), 1)
        self.assertEqual(output["issues"][0].code, 6000)
