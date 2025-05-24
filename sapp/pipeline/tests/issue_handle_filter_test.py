# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from unittest import TestCase

from .. import Frames, IssuesAndFrames, ParseIssueTuple, Pipeline
from ..issue_handle_filter import IssueHandleFilter


class TestIssueHandleFilter(TestCase):
    def setUp(self) -> None:
        self.warning_code_filter = IssueHandleFilter(handles_to_keep={"a", "b", "c"})

    def make_fake_issue(self, handle: str) -> ParseIssueTuple:
        issue = ParseIssueTuple(
            0,
            "",
            "",
            handle,
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
        self.assertEqual(issue.handle, handle)
        return issue

    def test_filter_handles(self) -> None:
        dict_entries = IssuesAndFrames(
            issues=list(map(self.make_fake_issue, ["alpaca", "b", "llama", "a"])),
            preconditions=Frames({}),
            postconditions=Frames({}),
        )
        output, _ = Pipeline([self.warning_code_filter]).run(dict_entries)

        self.assertEqual(len(output.issues), 2)
        self.assertEqual(output.issues[0].handle, "b")
        self.assertEqual(output.issues[1].handle, "a")
