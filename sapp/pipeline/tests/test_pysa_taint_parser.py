# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import io
import unittest
from typing import Iterable, Union

from ...analysis_output import AnalysisOutput, Metadata
from .. import (
    ParseConditionTuple,
    ParseIssueConditionTuple,
    ParseIssueTuple,
    SourceLocation,
)
from ..base_parser import ParseType
from ..pysa_taint_parser import Parser


class TestParser(unittest.TestCase):
    def assertParsed(
        self,
        input: str,
        expected: Iterable[Union[ParseConditionTuple, ParseIssueTuple]],
    ) -> None:
        input = "".join(input.split("\n"))  # Flatten json-line.
        input = '{"file_version":2}\n' + input  # Add version header.
        parser = Parser()
        analysis_output = AnalysisOutput(
            directory="/output/directory",
            filename_specs=["taint-output.json"],
            file_handle=io.StringIO(input),
            metadata=Metadata(
                analysis_root="/analysis/root",
                rules={1: {"name": "TestRule", "description": "Test Rule Description"}},
            ),
        )

        def sort_entry(e: Union[ParseConditionTuple, ParseIssueTuple]) -> str:
            if isinstance(e, ParseConditionTuple):
                return e.caller
            else:
                return e.callable

        self.assertEqual(
            sorted(parser.parse(analysis_output), key=sort_entry),
            expected,
        )

    def testEmptyModel(self) -> None:
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {}
            }
            """,
            [],
        )

    def testIssue(self) -> None:
        # Indirect source to indirect sink.
        self.assertParsed(
            """
            {
              "kind": "issue",
              "data": {
                "callable": "foo.bar",
                "callable_line": 10,
                "code": 1,
                "line": 11,
                "start": 12,
                "end": 13,
                "filename": "foo.py",
                "message": "[UserControlled] to [RCE]",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 14,
                            "start": 15,
                            "end": 16
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result",
                          "length": 1
                        },
                        "tito": [ { "line": 17, "start": 18, "end": 19 } ],
                        "leaves": [
                          {
                            "kind": "UserControlled",
                            "name": "_user_controlled"
                          }
                        ],
                        "features": [ { "always-via": "source-feature" } ]
                      }
                    ]
                  },
                  {
                    "name": "backward",
                    "roots": [
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 20,
                            "start": 21,
                            "end": 22
                          },
                          "resolves_to": [
                            "foo.sink"
                          ],
                          "port": "formal(x)[parameter]",
                          "length": 2
                        },
                        "tito": [ { "line": 23, "start": 24, "end": 25 } ],
                        "leaves": [
                          {
                            "kind": "RCE",
                            "name": "_remote_code_execution"
                          }
                        ],
                        "features": [ { "always-via": "sink-feature" } ]
                      }
                    ]
                  }
                ],
                "features": [
                  { "always-via": "foo" },
                  { "via": "bar" }
                ]
              }
            }
            """,
            [
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=12,
                    end=13,
                    postconditions=[
                        ParseIssueConditionTuple(
                            callee="foo.source",
                            port="result",
                            location=SourceLocation(
                                line_no=14,
                                begin_column=16,
                                end_column=16,
                            ),
                            leaves=[("UserControlled", 1)],
                            titos=[
                                SourceLocation(
                                    line_no=17, begin_column=19, end_column=19
                                ),
                            ],
                            features=["always-via:source-feature"],
                            type_interval=None,
                            annotations=[],
                        )
                    ],
                    preconditions=[
                        ParseIssueConditionTuple(
                            callee="foo.sink",
                            port="formal(x)[parameter]",
                            location=SourceLocation(
                                line_no=20,
                                begin_column=22,
                                end_column=22,
                            ),
                            leaves=[("RCE", 2)],
                            titos=[
                                SourceLocation(
                                    line_no=23, begin_column=25, end_column=25
                                )
                            ],
                            features=["always-via:sink-feature"],
                            type_interval=None,
                            annotations=[],
                        )
                    ],
                    initial_sources={("_user_controlled", "UserControlled", 1)},
                    final_sinks={("_remote_code_execution", "RCE", 2)},
                    features=["always-via:foo", "via:bar"],
                    fix_info=None,
                )
            ],
        )
        # Direct source + indirect source to direct sink + indirect sink.
        self.assertParsed(
            """
            {
              "kind": "issue",
              "data": {
                "callable": "foo.bar",
                "callable_line": 10,
                "code": 1,
                "line": 11,
                "start": 12,
                "end": 13,
                "filename": "foo.py",
                "message": "[UserControlled] to [RCE]",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 100,
                          "start": 101,
                          "end": 102
                        },
                        "tito": [
                          { "line": 110, "start": 111, "end": 112 },
                          { "line": 113, "start": 114, "end": 115 }
                        ],
                        "leaves": [
                          {
                            "kind": "UserControlled",
                            "name": "_user_controlled"
                          }
                        ],
                        "features": [ { "via": "source-direct" } ]
                      },
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 120,
                            "start": 121,
                            "end": 122
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result",
                          "length": 2
                        },
                        "leaves": [
                          {
                            "kind": "UserControlled",
                            "name": "_other_user_controlled"
                          }
                        ],
                        "features": [ { "always-via": "source-indirect" } ]
                      }
                    ]
                  },
                  {
                    "name": "backward",
                    "roots": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 200,
                          "start": 201,
                          "end": 202
                        },
                        "tito": [ { "line": 210, "start": 211, "end": 212 } ],
                        "leaves": [
                          {
                            "kind": "RCE",
                            "name": "_other_remote_code_execution"
                          }
                        ],
                        "features": [ { "always-via": "sink-direct" } ]
                      },
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 220,
                            "start": 221,
                            "end": 222
                          },
                          "resolves_to": [
                            "foo.sink"
                          ],
                          "port": "formal(y)",
                          "length": 5
                        },
                        "leaves": [
                          {
                            "kind": "RCE",
                            "name": "_remote_code_execution"
                          }
                        ],
                        "features": [ { "via": "sink-indirect" } ]
                      }
                    ]
                  }
                ],
                "features": [
                  { "always-via": "foo" },
                  { "via": "bar" }
                ]
              }
            }
            """,
            [
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=12,
                    end=13,
                    postconditions=[
                        ParseIssueConditionTuple(
                            callee="_user_controlled",
                            port="source",
                            location=SourceLocation(
                                line_no=100,
                                begin_column=102,
                                end_column=102,
                            ),
                            leaves=[("UserControlled", 0)],
                            titos=[
                                SourceLocation(
                                    line_no=110, begin_column=112, end_column=112
                                ),
                                SourceLocation(
                                    line_no=113, begin_column=115, end_column=115
                                ),
                            ],
                            features=["via:source-direct"],
                            type_interval=None,
                            annotations=[],
                        ),
                        ParseIssueConditionTuple(
                            callee="foo.source",
                            port="result",
                            location=SourceLocation(
                                line_no=120,
                                begin_column=122,
                                end_column=122,
                            ),
                            leaves=[("UserControlled", 2)],
                            titos=[],
                            features=["always-via:source-indirect"],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    preconditions=[
                        ParseIssueConditionTuple(
                            callee="_other_remote_code_execution",
                            port="sink",
                            location=SourceLocation(
                                line_no=200,
                                begin_column=202,
                                end_column=202,
                            ),
                            leaves=[("RCE", 0)],
                            titos=[
                                SourceLocation(
                                    line_no=210, begin_column=212, end_column=212
                                )
                            ],
                            features=["always-via:sink-direct"],
                            type_interval=None,
                            annotations=[],
                        ),
                        ParseIssueConditionTuple(
                            callee="foo.sink",
                            port="formal(y)",
                            location=SourceLocation(
                                line_no=220,
                                begin_column=222,
                                end_column=222,
                            ),
                            leaves=[("RCE", 5)],
                            titos=[],
                            features=["via:sink-indirect"],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    initial_sources={
                        ("_user_controlled", "UserControlled", 0),
                        ("_other_user_controlled", "UserControlled", 2),
                    },
                    final_sinks={
                        ("_other_remote_code_execution", "RCE", 0),
                        ("_remote_code_execution", "RCE", 5),
                    },
                    features=["always-via:foo", "via:bar"],
                    fix_info=None,
                )
            ],
        )
        # direct source with multiple leaves to direct sinks with multiple leaves.
        self.assertParsed(
            """
            {
              "kind": "issue",
              "data": {
                "callable": "foo.bar",
                "callable_line": 10,
                "code": 1,
                "line": 11,
                "start": 12,
                "end": 13,
                "filename": "foo.py",
                "message": "[UserControlled] to [RCE]",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 100,
                          "start": 101,
                          "end": 102
                        },
                        "tito": [ { "line": 110, "start": 111, "end": 112 } ],
                        "leaves": [
                          {
                            "kind": "UserControlled",
                            "name": "_user_controlled"
                          },
                          {
                            "kind": "UserControlled",
                            "name": "_other_user_controlled"
                          }
                        ],
                        "features": [ { "via": "source-direct" } ]
                      }
                    ]
                  },
                  {
                    "name": "backward",
                    "roots": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 200,
                          "start": 201,
                          "end": 202
                        },
                        "tito": [ { "line": 210, "start": 211, "end": 212 } ],
                        "leaves": [
                          {
                            "kind": "RCE",
                            "name": "_remote_code_execution"
                          },
                          {
                            "kind": "RCE",
                            "name": "_other_remote_code_execution"
                          }
                        ],
                        "features": [ { "always-via": "sink-direct" } ]
                      }
                    ]
                  }
                ],
                "features": [
                  { "always-via": "foo" },
                  { "via": "bar" }
                ]
              }
            }
            """,
            [
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=12,
                    end=13,
                    postconditions=[
                        ParseIssueConditionTuple(
                            callee="_user_controlled",
                            port="source",
                            location=SourceLocation(
                                line_no=100,
                                begin_column=102,
                                end_column=102,
                            ),
                            leaves=[("UserControlled", 0)],
                            titos=[
                                SourceLocation(
                                    line_no=110, begin_column=112, end_column=112
                                ),
                            ],
                            features=["via:source-direct"],
                            type_interval=None,
                            annotations=[],
                        ),
                        ParseIssueConditionTuple(
                            callee="_other_user_controlled",
                            port="source",
                            location=SourceLocation(
                                line_no=100,
                                begin_column=102,
                                end_column=102,
                            ),
                            leaves=[("UserControlled", 0)],
                            titos=[
                                SourceLocation(
                                    line_no=110, begin_column=112, end_column=112
                                ),
                            ],
                            features=["via:source-direct"],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    preconditions=[
                        ParseIssueConditionTuple(
                            callee="_remote_code_execution",
                            port="sink",
                            location=SourceLocation(
                                line_no=200,
                                begin_column=202,
                                end_column=202,
                            ),
                            leaves=[("RCE", 0)],
                            titos=[
                                SourceLocation(
                                    line_no=210, begin_column=212, end_column=212
                                )
                            ],
                            features=["always-via:sink-direct"],
                            type_interval=None,
                            annotations=[],
                        ),
                        ParseIssueConditionTuple(
                            callee="_other_remote_code_execution",
                            port="sink",
                            location=SourceLocation(
                                line_no=200,
                                begin_column=202,
                                end_column=202,
                            ),
                            leaves=[("RCE", 0)],
                            titos=[
                                SourceLocation(
                                    line_no=210, begin_column=212, end_column=212
                                )
                            ],
                            features=["always-via:sink-direct"],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    initial_sources={
                        ("_user_controlled", "UserControlled", 0),
                        ("_other_user_controlled", "UserControlled", 0),
                    },
                    final_sinks={
                        ("_other_remote_code_execution", "RCE", 0),
                        ("_remote_code_execution", "RCE", 0),
                    },
                    features=["always-via:foo", "via:bar"],
                    fix_info=None,
                )
            ],
        )
        # Indirect source with multiple callees to indirect sinks with multiple callees.
        self.assertParsed(
            """
            {
              "kind": "issue",
              "data": {
                "callable": "foo.bar",
                "callable_line": 10,
                "code": 1,
                "line": 11,
                "start": 12,
                "end": 13,
                "filename": "foo.py",
                "message": "[UserControlled] to [RCE]",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 14,
                            "start": 15,
                            "end": 16
                          },
                          "resolves_to": [
                            "foo.source",
                            "foo.other_source"
                          ],
                          "port": "result",
                          "length": 1
                        },
                        "tito": [ { "line": 17, "start": 18, "end": 19 } ],
                        "leaves": [
                          {
                            "kind": "UserControlled",
                            "name": "_user_controlled"
                          }
                        ],
                        "features": [ { "always-via": "source-feature" } ]
                      }
                    ]
                  },
                  {
                    "name": "backward",
                    "roots": [
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 20,
                            "start": 21,
                            "end": 22
                          },
                          "resolves_to": [
                            "foo.sink",
                            "foo.other_sink"
                          ],
                          "port": "formal(x)[parameter]",
                          "length": 2
                        },
                        "tito": [ { "line": 23, "start": 24, "end": 25 } ],
                        "leaves": [
                          {
                            "kind": "RCE",
                            "name": "_remote_code_execution"
                          }
                        ],
                        "features": [ { "always-via": "sink-feature" } ]
                      }
                    ]
                  }
                ],
                "features": [
                  { "always-via": "foo" },
                  { "via": "bar" }
                ]
              }
            }
            """,
            [
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=12,
                    end=13,
                    postconditions=[
                        ParseIssueConditionTuple(
                            callee="foo.source",
                            port="result",
                            location=SourceLocation(
                                line_no=14,
                                begin_column=16,
                                end_column=16,
                            ),
                            leaves=[("UserControlled", 1)],
                            titos=[
                                SourceLocation(
                                    line_no=17, begin_column=19, end_column=19
                                ),
                            ],
                            features=["always-via:source-feature"],
                            type_interval=None,
                            annotations=[],
                        ),
                        ParseIssueConditionTuple(
                            callee="foo.other_source",
                            port="result",
                            location=SourceLocation(
                                line_no=14,
                                begin_column=16,
                                end_column=16,
                            ),
                            leaves=[("UserControlled", 1)],
                            titos=[
                                SourceLocation(
                                    line_no=17, begin_column=19, end_column=19
                                ),
                            ],
                            features=["always-via:source-feature"],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    preconditions=[
                        ParseIssueConditionTuple(
                            callee="foo.sink",
                            port="formal(x)[parameter]",
                            location=SourceLocation(
                                line_no=20,
                                begin_column=22,
                                end_column=22,
                            ),
                            leaves=[("RCE", 2)],
                            titos=[
                                SourceLocation(
                                    line_no=23, begin_column=25, end_column=25
                                )
                            ],
                            features=["always-via:sink-feature"],
                            type_interval=None,
                            annotations=[],
                        ),
                        ParseIssueConditionTuple(
                            callee="foo.other_sink",
                            port="formal(x)[parameter]",
                            location=SourceLocation(
                                line_no=20,
                                begin_column=22,
                                end_column=22,
                            ),
                            leaves=[("RCE", 2)],
                            titos=[
                                SourceLocation(
                                    line_no=23, begin_column=25, end_column=25
                                )
                            ],
                            features=["always-via:sink-feature"],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    initial_sources={("_user_controlled", "UserControlled", 1)},
                    final_sinks={("_remote_code_execution", "RCE", 2)},
                    features=["always-via:foo", "via:bar"],
                    fix_info=None,
                )
            ],
        )

    def testSourceModel(self) -> None:
        # User-declared source.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "decl": null,
                        "leaves": [ { "kind": "UserControlled" } ],
                        "features": [ { "always-via": "user-declared" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [],
        )
        # Direct source.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          { "kind": "UserControlled", "name": "_user_controlled" },
                          { "kind": "Header", "name": "_user_controlled" }
                        ],
                        "features": [ { "always-via": "direct-source" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="_user_controlled",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("UserControlled", 0), ("Header", 0)],
                    caller_port="result",
                    callee_port="source",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )
        # Direct source with multiple leaves.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sources": [
                  {
                    "port": "result[attribute]",
                    "taint": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          { "kind": "UserControlled", "name": "_user_controlled" },
                          { "kind": "UserControlled", "name": "_other_user_controlled" }
                        ],
                        "features": [ { "always-via": "direct-source" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="_user_controlled",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("UserControlled", 0)],
                    caller_port="result[attribute]",
                    callee_port="source",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="_other_user_controlled",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("UserControlled", 0)],
                    caller_port="result[attribute]",
                    callee_port="source",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )
        # Direct source with ports on leaves (e.g, cross-repo),
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          {
                            "kind": "UserControlled",
                            "name": "_user_controlled"
                          },
                          {
                            "kind": "UserControlled",
                            "name": "_cross_repo",
                            "port": "producer:1:result"
                          },
                          {
                            "kind": "Header",
                            "name": "_cross_repo",
                            "port": "producer:1:result"
                          },
                          {
                            "kind": "UserControlled",
                            "name": "_cross_repo_other",
                            "port": "producer:1:result"
                          },
                          {
                            "kind": "UserControlled",
                            "name": "_cross_repo",
                            "port": "producer:2:result"
                          }
                        ],
                        "features": [ { "always-via": "direct-source" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="_user_controlled",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("UserControlled", 0)],
                    caller_port="result",
                    callee_port="source",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="_cross_repo",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("UserControlled", 0), ("Header", 0)],
                    caller_port="result",
                    callee_port="producer:1:result",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="_cross_repo_other",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("UserControlled", 0)],
                    caller_port="result",
                    callee_port="producer:1:result",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="_cross_repo",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("UserControlled", 0)],
                    caller_port="result",
                    callee_port="producer:2:result",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )
        # Indirect source.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sources": [
                  {
                    "port": "result[field]",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result[attribute]",
                          "length": 2
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          { "kind": "UserControlled", "name": "_user_controlled" },
                          { "kind": "Header", "name": "_user_controlled" }
                        ],
                        "features": [ { "always-via": "direct-source" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="foo.source",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("UserControlled", 2), ("Header", 2)],
                    caller_port="result[field]",
                    callee_port="result[attribute]",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )
        # Indirect source with multiple callees.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.source",
                            "foo.other_source"
                          ],
                          "port": "result[attribute]",
                          "length": 2
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          { "kind": "UserControlled", "name": "_user_controlled" }
                        ],
                        "features": [ { "always-via": "direct-source" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="foo.source",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("UserControlled", 2)],
                    caller_port="result",
                    callee_port="result[attribute]",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="foo.other_source",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("UserControlled", 2)],
                    caller_port="result",
                    callee_port="result[attribute]",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )
        # Mix of direct and indirect sources.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          { "kind": "UserControlled", "name": "_user_controlled" }
                        ],
                        "features": [ { "always-via": "direct-source" } ]
                      },
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 100,
                            "start": 101,
                            "end": 102
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result[attribute]",
                          "length": 2
                        },
                        "tito": [
                          { "line": 110, "start": 111, "end": 112 },
                          { "line": 113, "start": 114, "end": 115 }
                        ],
                        "leaves": [
                          { "kind": "UserControlled", "name": "_user_controlled" }
                        ],
                        "features": [ { "always-via": "direct-source" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="_user_controlled",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("UserControlled", 0)],
                    caller_port="result",
                    callee_port="source",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="foo.source",
                    callee_location=SourceLocation(
                        line_no=100,
                        begin_column=102,
                        end_column=102,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=110, begin_column=112, end_column=112),
                        SourceLocation(line_no=113, begin_column=115, end_column=115),
                    ],
                    leaves=[("UserControlled", 2)],
                    caller_port="result",
                    callee_port="result[attribute]",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )
        # User-declared parameter source.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sources": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "decl": null,
                        "leaves": [ { "kind": "UserControlled" } ],
                        "features": [ { "always-via": "user-declared" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [],
        )

    def testSinkModel(self) -> None:
        # User-declared sink.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "decl": null,
                        "leaves": [ { "kind": "RCE" } ],
                        "features": [ { "always-via": "user-declared" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [],
        )
        # Direct sink.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          { "kind": "SQL", "name": "_sql" },
                          { "kind": "RCE", "name": "_sql" }
                        ],
                        "features": [ { "always-via": "direct-sink" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="_sql",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("SQL", 0), ("RCE", 0)],
                    caller_port="formal(x)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )
        # Direct sink with multiple leaves.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          { "kind": "RCE", "name": "_remote_code_execution" },
                          { "kind": "RCE", "name": "_other_remote_code_execution" }
                        ],
                        "features": [ { "always-via": "direct-sink" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="_remote_code_execution",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("RCE", 0)],
                    caller_port="formal(x)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="_other_remote_code_execution",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("RCE", 0)],
                    caller_port="formal(x)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )
        # Direct sink with ports on leaves (e.g, cross-repo),
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sinks": [
                  {
                    "port": "formal(y)[attribute]",
                    "taint": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          {
                            "kind": "RCE",
                            "name": "_remote_code_execution"
                          },
                          {
                            "kind": "RCE",
                            "name": "_cross_repo",
                            "port": "producer:1:formal(x)"
                          },
                          {
                            "kind": "SQL",
                            "name": "_cross_repo",
                            "port": "producer:1:formal(x)"
                          },
                          {
                            "kind": "RCE",
                            "name": "_cross_repo_other",
                            "port": "producer:1:formal(x)"
                          },
                          {
                            "kind": "RCE",
                            "name": "_cross_repo",
                            "port": "producer:2:formal(x)"
                          }
                        ],
                        "features": [ { "always-via": "direct-sink" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="_remote_code_execution",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("RCE", 0)],
                    caller_port="formal(y)[attribute]",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="_cross_repo",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("RCE", 0), ("SQL", 0)],
                    caller_port="formal(y)[attribute]",
                    callee_port="producer:1:formal(x)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="_cross_repo_other",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("RCE", 0)],
                    caller_port="formal(y)[attribute]",
                    callee_port="producer:1:formal(x)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="_cross_repo",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("RCE", 0)],
                    caller_port="formal(y)[attribute]",
                    callee_port="producer:2:formal(x)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )
        # Indirect sink.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.sink"
                          ],
                          "port": "formal(y)[attribute]",
                          "length": 2
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          { "kind": "RCE", "name": "_sink_leaf" },
                          { "kind": "SQL", "name": "_sink_leaf" }
                        ],
                        "features": [ { "always-via": "direct-sink" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="foo.sink",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("RCE", 2), ("SQL", 2)],
                    caller_port="formal(x)",
                    callee_port="formal(y)[attribute]",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )
        # Indirect sink with multiple callees.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.sink",
                            "foo.other_sink"
                          ],
                          "port": "formal(y)[attribute]",
                          "length": 2
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          { "kind": "RCE", "name": "_sink_leaf" },
                          { "kind": "SQL", "name": "_sink_leaf" }
                        ],
                        "features": [ { "always-via": "direct-sink" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="foo.sink",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("RCE", 2), ("SQL", 2)],
                    caller_port="formal(x)",
                    callee_port="formal(y)[attribute]",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="foo.other_sink",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("RCE", 2), ("SQL", 2)],
                    caller_port="formal(x)",
                    callee_port="formal(y)[attribute]",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )
        # Mix of direct and indirect sinks.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "leaves": [
                          { "kind": "RCE", "name": "_remote_code_execution" }
                        ],
                        "features": [ { "always-via": "direct-sink" } ]
                      },
                      {
                        "call": {
                          "position": {
                            "filename": "foo.py",
                            "line": 100,
                            "start": 101,
                            "end": 102
                          },
                          "resolves_to": [
                            "foo.sink"
                          ],
                          "port": "formal(y)[attribute]",
                          "length": 2
                        },
                        "tito": [
                          { "line": 110, "start": 111, "end": 112 },
                          { "line": 113, "start": 114, "end": 115 }
                        ],
                        "leaves": [
                          { "kind": "RCE", "name": "_remote_code_execution" }
                        ],
                        "features": [ { "always-via": "direct-sink" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="_remote_code_execution",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=10, begin_column=12, end_column=12),
                        SourceLocation(line_no=13, begin_column=15, end_column=15),
                    ],
                    leaves=[("RCE", 0)],
                    caller_port="formal(x)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="foo.sink",
                    callee_location=SourceLocation(
                        line_no=100,
                        begin_column=102,
                        end_column=102,
                    ),
                    filename="foo.py",
                    titos=[
                        SourceLocation(line_no=110, begin_column=112, end_column=112),
                        SourceLocation(line_no=113, begin_column=115, end_column=115),
                    ],
                    leaves=[("RCE", 2)],
                    caller_port="formal(x)",
                    callee_port="formal(y)[attribute]",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )
        # User-declared return sink.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "sinks": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "decl": null,
                        "leaves": [ { "kind": "RCE" } ],
                        "features": [ { "always-via": "user-declared" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [],
        )

    def testIgnoreModels(self) -> None:
        # Ignore modes.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "modes": [ "Obscure" ]
              }
            }
            """,
            [],
        )
        # Ignore sanitizers.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "global_sanitizer": { "sources": "All" }
              }
            }
            """,
            [],
        )
        # Ignore tito.
        self.assertParsed(
            """
            {
              "kind": "model",
              "data": {
                "tito": [
                  {
                    "port": "formal(value)",
                    "taint": [
                      {
                        "decl": null,
                        "leaves": [
                          { "kind": "LocalReturn", "name": "[instance]", "depth": 0 },
                          { "kind": "LocalReturn", "name": "[attribute]", "depth": 0 }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            [],
        )
