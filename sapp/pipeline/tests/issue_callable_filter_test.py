# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from unittest import TestCase

from .. import ParseIssueTuple, Pipeline
from ..issue_callable_filter import IssueCallableFilter


class TestIssueCallableFilter(TestCase):
    def setUp(self) -> None:
        self.issue_callable_filter = IssueCallableFilter(
            issue_callable_allowlist={"a", "b", "c"}
        )

    def make_fake_issue(self, callable: str) -> ParseIssueTuple:
        issue = ParseIssueTuple(
            0,
            "",
            callable,
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
        self.assertEqual(issue.callable, callable)
        return issue

    def test_filter_callables(self) -> None:
        dict_entries = {
            "issues": list(map(self.make_fake_issue, ["alpaca", "b", "llama", "a"]))
        }
        output, _ = Pipeline([self.issue_callable_filter]).run(dict_entries)

        self.assertEqual(len(output["issues"]), 2)
        self.assertEqual(output["issues"][0].callable, "b")
        self.assertEqual(output["issues"][1].callable, "a")
