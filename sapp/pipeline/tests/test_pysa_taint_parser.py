# Copyright (c) Meta Platforms, Inc. and affiliates.
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
    ParseTraceFeature,
)
from ..base_parser import ParseType
from ..pysa_taint_parser import Parser


class TestParser(unittest.TestCase):
    def assertParsed(
        self,
        version: int,
        input: str,
        expected: Iterable[Union[ParseConditionTuple, ParseIssueTuple]],
    ) -> None:
        input = "".join(input.split("\n"))  # Flatten json-line.
        input = '{"file_version":%d}\n%s' % (version, input)  # Add version header.
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

    def testEmptyModelV2(self) -> None:
        self.assertParsed(
            version=2,
            input="""
            {
              "kind": "model",
              "data": {}
            }
            """,
            expected=[],
        )

    def testEmptyModelV3(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {}
            }
            """,
            expected=[],
        )

    def testIssueV2(self) -> None:
        # Indirect source to indirect sink.
        self.assertParsed(
            version=2,
            input="""
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
            expected=[
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=13,
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
                            features=[],
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
                            features=[],
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
            version=2,
            input="""
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
            expected=[
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=13,
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
            version=2,
            input="""
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
            expected=[
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=13,
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
            version=2,
            input="""
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
            expected=[
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=13,
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
        # Indirect source into a return sink.
        self.assertParsed(
            version=2,
            input="""
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
                          "line": 20,
                          "start": 21,
                          "end": 22
                        },
                        "tito": [ { "line": 30, "start": 31, "end": 32 } ],
                        "leaves": [
                          {
                            "kind": "UserControlled",
                            "name": "_user_controlled"
                          }
                        ],
                        "features": [
                          { "has": "first-index" },
                          { "first-index": "payload" },
                          { "always-via": "tito" }
                        ]
                      }
                    ]
                  },
                  {
                    "name": "backward",
                    "roots": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 100,
                          "start": 101,
                          "end": 102
                        },
                        "leaves": [ { "kind": "RCE" } ]
                      }
                    ]
                  }
                ],
                "features": [
                  { "has": "first-index" },
                  { "first-index": "payload" },
                  { "always-via": "tito" }
                ]
              }
            }
            """,
            expected=[
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=13,
                    end=13,
                    postconditions=[
                        ParseIssueConditionTuple(
                            callee="_user_controlled",
                            port="source",
                            location=SourceLocation(
                                line_no=20,
                                begin_column=22,
                                end_column=22,
                            ),
                            leaves=[("UserControlled", 0)],
                            titos=[
                                SourceLocation(
                                    line_no=30, begin_column=32, end_column=32
                                ),
                            ],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    preconditions=[
                        ParseIssueConditionTuple(
                            callee="leaf",
                            port="sink",
                            location=SourceLocation(
                                line_no=100,
                                begin_column=102,
                                end_column=102,
                            ),
                            leaves=[("RCE", 0)],
                            titos=[],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    initial_sources={("_user_controlled", "UserControlled", 0)},
                    # pyre-fixme[6]: Expected `str` but got `None`
                    final_sinks={(None, "RCE", 0)},
                    features=[
                        "has:first-index",
                        "first-index:payload",
                        "always-via:tito",
                    ],
                    fix_info=None,
                )
            ],
        )

    def testIssueV3(self) -> None:
        # Indirect source to indirect sink.
        self.assertParsed(
            version=3,
            input="""
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
                          "port": "result"
                        },
                        "tito": [ { "line": 17, "start": 18, "end": 19 } ],
                        "local_features": [ { "always-via": "source-local" } ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "source-feature" } ]
                          }
                        ]
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
                          "port": "formal(x)[parameter]"
                        },
                        "tito": [ { "line": 23, "start": 24, "end": 25 } ],
                        "local_features": [ { "always-via": "sink-local" } ],
                        "kinds": [
                          {
                            "kind": "RCE",
                            "length": 2,
                            "leaves": [ { "name": "_remote_code_execution" } ],
                            "features": [ { "always-via": "sink-feature" } ]
                          }
                        ]
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
            expected=[
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=13,
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
                            features=[ParseTraceFeature("always-via:source-local", [])],
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
                            features=[ParseTraceFeature("always-via:sink-local", [])],
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
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "via": "source-direct" } ]
                          }
                        ]
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
                          "port": "result"
                        },
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 2,
                            "leaves": [ { "name": "_other_user_controlled" } ],
                            "features": [ { "always-via": "source-indirect" } ]
                          }
                        ]
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
                        "kinds": [
                          {
                            "kind": "RCE",
                            "leaves": [ { "name": "_other_remote_code_execution" } ],
                            "features": [ { "always-via": "sink-direct" } ]
                          }
                        ]
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
                          "port": "formal(y)"
                        },
                        "kinds": [
                          {
                            "kind": "RCE",
                            "length": 5,
                            "leaves": [ { "name": "_remote_code_execution" } ],
                            "features": [ { "via": "sink-indirect" } ]
                          }
                        ]
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
            expected=[
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=13,
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "leaves": [
                              { "name": "_user_controlled" },
                              { "name": "_other_user_controlled" }
                            ],
                            "features": [ { "via": "source-direct" } ]
                          }
                        ]
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
                        "kinds": [
                          {
                            "kind": "RCE",
                            "leaves": [
                              { "name": "_remote_code_execution" },
                              { "name": "_other_remote_code_execution" }
                            ],
                            "features": [ { "always-via": "sink-direct" } ]
                          }
                        ]
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
            expected=[
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=13,
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
            version=3,
            input="""
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
                          "port": "result"
                        },
                        "tito": [ { "line": 17, "start": 18, "end": 19 } ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "source-feature" } ]
                          }
                        ]
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
                          "port": "formal(x)[parameter]"
                        },
                        "tito": [ { "line": 23, "start": 24, "end": 25 } ],
                        "kinds": [
                          {
                            "kind": "RCE",
                            "length": 2,
                            "leaves": [ { "name": "_remote_code_execution" } ],
                            "features": [ { "always-via": "sink-feature" } ]
                          }
                        ]
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
            expected=[
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=13,
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
                            features=[],
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
        # Indirect source with multiple kinds to indirect sinks with multiple kinds.
        self.assertParsed(
            version=3,
            input="""
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
                "message": "[UserControlled, Header] to [RCE, SQL]",
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
                          "resolves_to": ["foo.source"],
                          "port": "result"
                        },
                        "tito": [ { "line": 17, "start": 18, "end": 19 } ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "source-feature" } ]
                          },
                          {
                            "kind": "Header",
                            "length": 2,
                            "leaves": [ { "name": "_header" } ],
                            "features": [ { "always-via": "source-other-feature" } ]
                          }
                        ]
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
                          "resolves_to": ["foo.sink"],
                          "port": "formal(x)[parameter]"
                        },
                        "tito": [ { "line": 23, "start": 24, "end": 25 } ],
                        "kinds": [
                          {
                            "kind": "RCE",
                            "length": 3,
                            "leaves": [ { "name": "_remote_code_execution" } ],
                            "features": [ { "always-via": "sink-feature" } ]
                          },
                          {
                            "kind": "SQL",
                            "length": 2,
                            "leaves": [ { "name": "_sql" } ],
                            "features": [ { "always-via": "sink-other-feature" } ]
                          }
                        ]
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
            expected=[
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled, Header] to [RCE, SQL]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=13,
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
                            leaves=[("UserControlled", 1), ("Header", 2)],
                            titos=[
                                SourceLocation(
                                    line_no=17, begin_column=19, end_column=19
                                ),
                            ],
                            features=[],
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
                            leaves=[("RCE", 3), ("SQL", 2)],
                            titos=[
                                SourceLocation(
                                    line_no=23, begin_column=25, end_column=25
                                )
                            ],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    initial_sources={
                        ("_user_controlled", "UserControlled", 1),
                        ("_header", "Header", 2),
                    },
                    final_sinks={
                        ("_remote_code_execution", "RCE", 3),
                        ("_sql", "SQL", 2),
                    },
                    features=["always-via:foo", "via:bar"],
                    fix_info=None,
                )
            ],
        )
        # Indirect source into a return sink.
        self.assertParsed(
            version=3,
            input="""
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
                          "line": 20,
                          "start": 21,
                          "end": 22
                        },
                        "tito": [ { "line": 30, "start": 31, "end": 32 } ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [
                              { "has": "first-index" },
                              { "first-index": "payload" },
                              { "always-via": "tito" }
                            ]
                          }
                        ]
                      }
                    ]
                  },
                  {
                    "name": "backward",
                    "roots": [
                      {
                        "root": {
                          "filename": "foo.py",
                          "line": 100,
                          "start": 101,
                          "end": 102
                        },
                        "kinds": [ { "kind": "RCE" } ]
                      }
                    ]
                  }
                ],
                "features": [
                  { "has": "first-index" },
                  { "first-index": "payload" },
                  { "always-via": "tito" }
                ]
              }
            }
            """,
            expected=[
                ParseIssueTuple(
                    code=1,
                    message="[UserControlled] to [RCE]",
                    callable="foo.bar",
                    handle="foo.bar:1|12|13:1:4f2c49226090f13a",
                    filename="foo.py",
                    callable_line=10,
                    line=11,
                    start=13,
                    end=13,
                    postconditions=[
                        ParseIssueConditionTuple(
                            callee="_user_controlled",
                            port="source",
                            location=SourceLocation(
                                line_no=20,
                                begin_column=22,
                                end_column=22,
                            ),
                            leaves=[("UserControlled", 0)],
                            titos=[
                                SourceLocation(
                                    line_no=30, begin_column=32, end_column=32
                                ),
                            ],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    preconditions=[
                        ParseIssueConditionTuple(
                            callee="leaf",
                            port="sink",
                            location=SourceLocation(
                                line_no=100,
                                begin_column=102,
                                end_column=102,
                            ),
                            leaves=[("RCE", 0)],
                            titos=[],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    initial_sources={("_user_controlled", "UserControlled", 0)},
                    # pyre-fixme[6]: Expected `str` but got `None`
                    final_sinks={(None, "RCE", 0)},
                    features=[
                        "has:first-index",
                        "first-index:payload",
                        "always-via:tito",
                    ],
                    fix_info=None,
                )
            ],
        )

    def testSourceModelV2(self) -> None:
        # User-declared source.
        self.assertParsed(
            version=2,
            input="""
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
            expected=[],
        )
        # Direct source.
        self.assertParsed(
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[],
        )
        # Implicit source.
        self.assertParsed(
            version=2,
            input="""
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
                        "leaves": [ { "kind": "UserControlled" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[],
                    leaves=[("UserControlled", 0)],
                    caller_port="result",
                    callee_port="source",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSourceModelV3(self) -> None:
        # User-declared source.
        self.assertParsed(
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "features": [ { "always-via": "user-declared" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[],
        )
        # Direct source.
        self.assertParsed(
            version=3,
            input="""
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
                        "local_features": [ { "always-via": "source-local" } ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "direct-source" } ]
                          },
                          {
                            "kind": "Header",
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "other-direct-source" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
                    features=[ParseTraceFeature("always-via:source-local", [])],
                    annotations=[],
                )
            ],
        )
        # Direct source with multiple leaves.
        self.assertParsed(
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "leaves": [
                              { "name": "_user_controlled" },
                              { "name": "_other_user_controlled" }
                            ],
                            "features": [ { "always-via": "direct-source" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "leaves": [
                              {
                                "name": "_user_controlled"
                              },
                              {
                                "name": "_cross_repo",
                                "port": "producer:1:result"
                              },
                              {
                                "name": "_cross_repo_other",
                                "port": "producer:1:result"
                              },
                              {
                                "name": "_cross_repo",
                                "port": "producer:2:result"
                              }
                            ],
                            "features": [ { "always-via": "direct-source" } ]
                          },
                          {
                            "kind": "Header",
                            "leaves": [
                              {
                                "kind": "Header",
                                "name": "_cross_repo",
                                "port": "producer:1:result"
                              }
                            ],
                            "features": [ { "always-via": "direct-source" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
            version=3,
            input="""
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
                          "port": "result[attribute]"
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 2,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "direct-source" } ]
                          },
                          {
                            "kind": "Header",
                            "length": 3,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "direct-source" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
                    leaves=[("UserControlled", 2), ("Header", 3)],
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
            version=3,
            input="""
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
                          "port": "result[attribute]"
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 2,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "direct-source" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "direct-source" } ]
                          }
                        ]
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
                          "port": "result[attribute]"
                        },
                        "tito": [
                          { "line": 110, "start": 111, "end": 112 },
                          { "line": 113, "start": 114, "end": 115 }
                        ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 2,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "direct-source" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "features": [ { "always-via": "user-declared" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[],
        )
        # Implicit source.
        self.assertParsed(
            version=3,
            input="""
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
                        "kinds": [ { "kind": "UserControlled" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="foo.bar",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[],
                    leaves=[("UserControlled", 0)],
                    caller_port="result",
                    callee_port="source",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSinkModelV2(self) -> None:
        # User-declared sink.
        self.assertParsed(
            version=2,
            input="""
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
            expected=[],
        )
        # Direct sink.
        self.assertParsed(
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[
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
            version=2,
            input="""
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
            expected=[],
        )
        # Implicit sink.
        self.assertParsed(
            version=2,
            input="""
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
                        "leaves": [ { "kind": "RCE" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[],
                    leaves=[("RCE", 0)],
                    caller_port="formal(x)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSinkModelV3(self) -> None:
        # User-declared sink.
        self.assertParsed(
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "RCE",
                            "features": [ { "always-via": "user-declared" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[],
        )
        # Direct sink.
        self.assertParsed(
            version=3,
            input="""
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
                        "local_features": [ { "always-via": "local-sink" } ],
                        "kinds": [
                          {
                            "kind": "SQL",
                            "leaves": [ { "name": "_sql" } ],
                            "features": [ { "always-via": "direct-sink" } ]
                          },
                          {
                            "kind": "RCE",
                            "leaves": [ { "name": "_sql" } ],
                            "features": [ { "always-via": "other-direct-sink" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
                    features=[ParseTraceFeature("always-via:local-sink", [])],
                    annotations=[],
                )
            ],
        )
        # Direct sink with multiple leaves.
        self.assertParsed(
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "RCE",
                            "leaves": [
                              { "name": "_remote_code_execution" },
                              { "name": "_other_remote_code_execution" }
                            ],
                            "features": [ { "always-via": "direct-sink" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "RCE",
                            "leaves": [
                              {
                                "name": "_remote_code_execution"
                              },
                              {
                                "name": "_cross_repo",
                                "port": "producer:1:formal(x)"
                              },
                              {
                                "name": "_cross_repo_other",
                                "port": "producer:1:formal(x)"
                              },
                              {
                                "name": "_cross_repo",
                                "port": "producer:2:formal(x)"
                              }
                            ],
                            "features": [ { "always-via": "direct-sink" } ]
                          },
                          {
                            "kind": "SQL",
                            "leaves": [
                              {
                                "name": "_cross_repo",
                                "port": "producer:1:formal(x)"
                              }
                            ],
                            "features": [ { "always-via": "direct-sink" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
            version=3,
            input="""
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
                          "port": "formal(y)[attribute]"
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "RCE",
                            "length": 2,
                            "leaves": [ { "name": "_sink_leaf" } ],
                            "features": [ { "always-via": "direct-sink" } ]
                          },
                          {
                            "kind": "SQL",
                            "length": 3,
                            "leaves": [ { "name": "_sink_leaf" } ],
                            "features": [ { "always-via": "direct-sink" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
                    leaves=[("RCE", 2), ("SQL", 3)],
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
            version=3,
            input="""
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
                          "port": "formal(y)[attribute]"
                        },
                        "tito": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "RCE",
                            "length": 2,
                            "leaves": [ { "name": "_sink_leaf" } ],
                            "features": [ { "always-via": "direct-sink" } ]
                          },
                          {
                            "kind": "SQL",
                            "length": 3,
                            "leaves": [ { "name": "_sink_leaf" } ],
                            "features": [ { "always-via": "direct-sink" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
                    leaves=[("RCE", 2), ("SQL", 3)],
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
                    leaves=[("RCE", 2), ("SQL", 3)],
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
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "RCE",
                            "leaves": [ { "name": "_remote_code_execution" } ],
                            "features": [ { "always-via": "direct-sink" } ]
                          }
                        ]
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
                          "port": "formal(y)[attribute]"
                        },
                        "tito": [
                          { "line": 110, "start": 111, "end": 112 },
                          { "line": 113, "start": 114, "end": 115 }
                        ],
                        "kinds": [
                          {
                            "kind": "RCE",
                            "length": 2,
                            "leaves": [ { "name": "_remote_code_execution" } ],
                            "features": [ { "always-via": "direct-sink" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
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
            version=3,
            input="""
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
                        "kinds": [
                          {
                            "kind": "RCE",
                            "features": [ { "always-via": "user-declared" } ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[],
        )
        # Implicit sink.
        self.assertParsed(
            version=3,
            input="""
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
                        "kinds": [ { "kind": "RCE" } ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="foo.bar",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=3,
                        end_column=3,
                    ),
                    filename="foo.py",
                    titos=[],
                    leaves=[("RCE", 0)],
                    caller_port="formal(x)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testIgnoreModelsV2(self) -> None:
        # Ignore modes.
        self.assertParsed(
            version=2,
            input="""
            {
              "kind": "model",
              "data": {
                "modes": [ "Obscure" ]
              }
            }
            """,
            expected=[],
        )
        # Ignore sanitizers.
        self.assertParsed(
            version=2,
            input="""
            {
              "kind": "model",
              "data": {
                "global_sanitizer": { "sources": "All" }
              }
            }
            """,
            expected=[],
        )
        # Ignore tito.
        self.assertParsed(
            version=2,
            input="""
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
            expected=[],
        )

    def testIgnoreModelsV3(self) -> None:
        # Ignore modes.
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "modes": [ "Obscure" ]
              }
            }
            """,
            expected=[],
        )
        # Ignore sanitizers.
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "global_sanitizer": { "sources": "All" }
              }
            }
            """,
            expected=[],
        )
        # Ignore tito.
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "tito": [
                  {
                    "port": "formal(value)",
                    "taint": [
                      {
                        "decl": null,
                        "kinds": [
                          {
                            "kind": "LocalReturn",
                            "return_paths": ["[instance]", "[attribute]"]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
            """,
            expected=[],
        )
