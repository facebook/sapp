# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import io
import sys
import unittest
from typing import Iterable, Union

from ...analysis_output import AnalysisOutput, Metadata, Rule
from .. import (
    ParseConditionTuple,
    ParseIssueConditionTuple,
    ParseIssueTuple,
    ParseTraceAnnotation,
    ParseTraceAnnotationSubtrace,
    ParseTraceFeature,
    ParseTypeInterval,
    SourceLocation,
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
                repo_roots={"/analysis/root"},
                rules={1: Rule(name="TestRule", description="Test Rule Description")},
            ),
        )

        def sort_entry(e: Union[ParseConditionTuple, ParseIssueTuple]) -> str:
            if isinstance(e, ParseConditionTuple):
                return e.caller
            else:
                return e.callable

        issues_and_frames = parser.parse_analysis_output(analysis_output)
        entries = (
            issues_and_frames.issues
            + list(issues_and_frames.preconditions.all_frames())
            + list(issues_and_frames.postconditions.all_frames())
        )
        self.assertEqual(
            sorted(entries, key=sort_entry),
            expected,
        )

    def testEmptyModelV3(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar"
              }
            }
            """,
            expected=[],
        )

    def testIssueV3_indirectSourceToIndirectSink(self) -> None:
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
                "sink_handle": {
                  "kind": "Call",
                  "callee": "foo.sink",
                  "index": 0,
                  "parameter": "formal(x)"
                },
                "master_handle": "foo.bar:1:0:Call|foo.sink|0|formal(x)",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "receiver_interval": [{ "lower": 23, "upper": 24 }],
                        "is_self_call": false,
                        "call": {
                          "position": {
                            "line": 14,
                            "start": 15,
                            "end": 16
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result"
                        },
                        "tito_positions": [ { "line": 17, "start": 18, "end": 19 } ],
                        "local_features": [ { "always-via": "source-local" } ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "source-feature" } ],
                            "extra_traces": [
                              {
                                "call": {
                                  "position": {
                                    "line": 117,
                                    "start": 22,
                                    "end": 24
                                  },
                                  "resolves_to": [
                                    "extra_trace.transform_yz"
                                  ],
                                  "port": "formal(arg)"
                                },
                                "kind": "TransformY:TransformZ:ExtraTraceSink"
                              }
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
                        "caller_interval": [{
                          "lower": 10,
                          "upper": 11
                        }],
                        "is_self_call": true,
                        "call": {
                          "position": {
                            "line": 20,
                            "start": 21,
                            "end": 22
                          },
                          "resolves_to": [
                            "foo.sink"
                          ],
                          "port": "formal(x)[parameter]"
                        },
                        "tito_positions": [ { "line": 23, "start": 24, "end": 25 } ],
                        "local_features": [ { "always-via": "sink-local" } ],
                        "kinds": [
                          {
                            "kind": "RCE",
                            "length": 2,
                            "leaves": [ { "name": "_remote_code_execution" } ],
                            "features": [ { "always-via": "sink-feature" } ],
                            "extra_traces": [
                              {
                                "call": {
                                  "position": {
                                    "line": 117,
                                    "start": 22,
                                    "end": 24
                                  },
                                  "resolves_to": [
                                    "extra_trace.transform_yz"
                                  ],
                                  "port": "formal(arg)"
                                },
                                "leaf_kind": "TransformY:TransformZ:ExtraTraceSink",
                                "trace_kind": "sink"
                              }
                            ]
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
                    handle="foo.bar:1:0:Call|foo.sink|0|formal(x)",
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
                            type_interval=ParseTypeInterval(
                                start=23,
                                finish=24,
                                preserves_type_context=False,
                            ),
                            annotations=[
                                ParseTraceAnnotation(
                                    location=SourceLocation(
                                        line_no=117, begin_column=23, end_column=24
                                    ),
                                    kind="tito_transform",
                                    msg="",
                                    leaf_kind="TransformY:TransformZ:ExtraTraceSink",
                                    leaf_depth=0,
                                    type_interval=None,
                                    link=None,
                                    trace_key=None,
                                    titos=[],
                                    subtraces=[
                                        ParseTraceAnnotationSubtrace(
                                            callee="extra_trace.transform_yz",
                                            port="formal(arg)",
                                            position=SourceLocation(
                                                line_no=117,
                                                begin_column=23,
                                                end_column=24,
                                            ),
                                        )
                                    ],
                                )
                            ],
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
                            type_interval=ParseTypeInterval(
                                start=0, finish=sys.maxsize, preserves_type_context=True
                            ),
                            annotations=[
                                ParseTraceAnnotation(
                                    location=SourceLocation(
                                        line_no=117, begin_column=23, end_column=24
                                    ),
                                    kind="sink",
                                    msg="",
                                    leaf_kind="TransformY:TransformZ:ExtraTraceSink",
                                    leaf_depth=0,
                                    type_interval=None,
                                    link=None,
                                    trace_key=None,
                                    titos=[],
                                    subtraces=[
                                        ParseTraceAnnotationSubtrace(
                                            callee="extra_trace.transform_yz",
                                            port="formal(arg)",
                                            position=SourceLocation(
                                                line_no=117,
                                                begin_column=23,
                                                end_column=24,
                                            ),
                                        )
                                    ],
                                )
                            ],
                        )
                    ],
                    initial_sources={("_user_controlled", "UserControlled", 1)},
                    final_sinks={("_remote_code_execution", "RCE", 2)},
                    features=["always-via:foo", "via:bar"],
                    fix_info=None,
                )
            ],
        )

    def testIssueV3_directAndIndirectSourceToDirectAndIndirectSink(self) -> None:
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
                "sink_handle": {
                  "kind": "Call",
                  "callee": "foo.sink",
                  "index": 0,
                  "parameter": "formal(x)"
                },
                "master_handle": "foo.bar:1:0:Call|foo.sink|0|formal(x)",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "receiver_interval": [
                          { "lower": 20, "upper": 21 },
                          { "lower": 30, "upper": 41 }
                        ],
                        "origin": {
                          "line": 100,
                          "start": 101,
                          "end": 102
                        },
                        "tito_positions": [
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
                        "receiver_interval": [{ "lower": 22, "upper": 23 }],
                        "call": {
                          "position": {
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
                        "receiver_interval": [{ "lower": 30, "upper": 31 }],
                        "origin": {
                          "line": 200,
                          "start": 201,
                          "end": 202
                        },
                        "tito_positions": [ { "line": 210, "start": 211, "end": 212 } ],
                        "kinds": [
                          {
                            "kind": "RCE",
                            "leaves": [ { "name": "_other_remote_code_execution" } ],
                            "features": [ { "always-via": "sink-direct" } ]
                          }
                        ]
                      },
                      {
                        "receiver_interval": [{ "lower": 32, "upper": 33 }],
                        "call": {
                          "position": {
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
                    handle="foo.bar:1:0:Call|foo.sink|0|formal(x)",
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
                            type_interval=ParseTypeInterval(
                                start=20,
                                finish=41,
                                preserves_type_context=False,
                            ),
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
                            type_interval=ParseTypeInterval(
                                start=22,
                                finish=23,
                                preserves_type_context=False,
                            ),
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
                            type_interval=ParseTypeInterval(
                                start=30,
                                finish=31,
                                preserves_type_context=False,
                            ),
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
                            type_interval=ParseTypeInterval(
                                start=32,
                                finish=33,
                                preserves_type_context=False,
                            ),
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

    def testIssueV3_directWithMultipleLeaves(self) -> None:
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
                "sink_handle": {
                  "kind": "Call",
                  "callee": "foo.sink",
                  "index": 0,
                  "parameter": "formal(x)"
                },
                "master_handle": "foo.bar:1:0:Call|foo.sink|0|formal(x)",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "origin": {
                          "line": 100,
                          "start": 101,
                          "end": 102
                        },
                        "tito_positions": [ { "line": 110, "start": 111, "end": 112 } ],
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
                        "origin": {
                          "line": 200,
                          "start": 201,
                          "end": 202
                        },
                        "tito_positions": [ { "line": 210, "start": 211, "end": 212 } ],
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
                    handle="foo.bar:1:0:Call|foo.sink|0|formal(x)",
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
                            type_interval=ParseTypeInterval(
                                start=0,
                                finish=sys.maxsize,
                                preserves_type_context=False,
                            ),
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
                            type_interval=ParseTypeInterval(
                                start=0,
                                finish=sys.maxsize,
                                preserves_type_context=False,
                            ),
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
                            type_interval=ParseTypeInterval(
                                start=0,
                                finish=sys.maxsize,
                                preserves_type_context=False,
                            ),
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
                            type_interval=ParseTypeInterval(
                                start=0,
                                finish=sys.maxsize,
                                preserves_type_context=False,
                            ),
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

    def testIssueV3_indirectWithMultipleCallees(self) -> None:
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
                "sink_handle": {
                  "kind": "Call",
                  "callee": "foo.sink",
                  "index": 0,
                  "parameter": "formal(x)"
                },
                "master_handle": "foo.bar:1:0:Call|foo.sink|0|formal(x)",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "receiver_interval": [
                          { "lower": 40, "upper": 41 },
                          { "lower": 50, "upper": 61 }
                        ],
                        "call": {
                          "position": {
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
                        "tito_positions": [ { "line": 17, "start": 18, "end": 19 } ],
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
                        "receiver_interval": [{ "lower": 42, "upper": 43 }],
                        "call": {
                          "position": {
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
                        "tito_positions": [ { "line": 23, "start": 24, "end": 25 } ],
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
                    handle="foo.bar:1:0:Call|foo.sink|0|formal(x)",
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
                            type_interval=ParseTypeInterval(
                                start=40,
                                finish=61,
                                preserves_type_context=False,
                            ),
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
                            type_interval=ParseTypeInterval(
                                start=40,
                                finish=61,
                                preserves_type_context=False,
                            ),
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
                            type_interval=ParseTypeInterval(
                                start=42,
                                finish=43,
                                preserves_type_context=False,
                            ),
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
                            type_interval=ParseTypeInterval(
                                start=42,
                                finish=43,
                                preserves_type_context=False,
                            ),
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

    def testIssueV3_indirectWithMultipleKinds(self) -> None:
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
                "sink_handle": {
                  "kind": "Call",
                  "callee": "foo.sink",
                  "index": 0,
                  "parameter": "formal(x)"
                },
                "master_handle": "foo.bar:1:0:Call|foo.sink|0|formal(x)",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "receiver_interval": [
                          { "lower": 50, "upper": 51 },
                          { "lower": 60, "upper": 71 }
                        ],
                        "call": {
                          "position": {
                            "line": 14,
                            "start": 15,
                            "end": 16
                          },
                          "resolves_to": ["foo.source"],
                          "port": "result"
                        },
                        "tito_positions": [ { "line": 17, "start": 18, "end": 19 } ],
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
                            "line": 20,
                            "start": 21,
                            "end": 22
                          },
                          "resolves_to": ["foo.sink"],
                          "port": "formal(x)[parameter]"
                        },
                        "tito_positions": [ { "line": 23, "start": 24, "end": 25 } ],
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
                    handle="foo.bar:1:0:Call|foo.sink|0|formal(x)",
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
                            leaves=[
                                ("Header", 2),
                                ("UserControlled", 1),
                            ],
                            titos=[
                                SourceLocation(
                                    line_no=17, begin_column=19, end_column=19
                                ),
                            ],
                            features=[],
                            type_interval=ParseTypeInterval(
                                start=50,
                                finish=71,
                                preserves_type_context=False,
                            ),
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
                            leaves=[
                                ("RCE", 3),
                                ("SQL", 2),
                            ],
                            titos=[
                                SourceLocation(
                                    line_no=23, begin_column=25, end_column=25
                                )
                            ],
                            features=[],
                            type_interval=ParseTypeInterval(
                                start=0,
                                finish=sys.maxsize,
                                preserves_type_context=False,
                            ),
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

    def testIssueV3_indirectSourceToReturnSink(self) -> None:
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
                "sink_handle": {
                  "kind": "Call",
                  "callee": "foo.sink",
                  "index": 0,
                  "parameter": "formal(x)"
                },
                "master_handle": "foo.bar:1:0:Call|foo.sink|0|formal(x)",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "origin": {
                          "line": 20,
                          "start": 21,
                          "end": 22
                        },
                        "tito_positions": [ { "line": 30, "start": 31, "end": 32 } ],
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
                        "origin": {
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
                    handle="foo.bar:1:0:Call|foo.sink|0|formal(x)",
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
                            type_interval=ParseTypeInterval(
                                start=0,
                                finish=sys.maxsize,
                                preserves_type_context=False,
                            ),
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
                            type_interval=ParseTypeInterval(
                                start=0,
                                finish=sys.maxsize,
                                preserves_type_context=False,
                            ),
                            annotations=[],
                        ),
                    ],
                    initial_sources={("_user_controlled", "UserControlled", 0)},
                    final_sinks={(None, "RCE", 0)},
                    features=[
                        "always-via:tito",
                        "first-index:payload",
                        "has:first-index",
                    ],
                    fix_info=None,
                )
            ],
        )

    def testIssueV3_duplicateLeaves(self) -> None:
        # Duplicate leaves with the same (port, kind) should be merged and sorted
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
                "sink_handle": {
                  "kind": "Call",
                  "callee": "foo.sink",
                  "index": 0,
                  "parameter": "formal(x)"
                },
                "master_handle": "foo.bar:1:0:Call|foo.sink|0|formal(x)",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "receiver_interval": [
                          { "lower": 50, "upper": 51 },
                          { "lower": 60, "upper": 71 }
                        ],
                        "call": {
                          "position": {
                            "line": 14,
                            "start": 15,
                            "end": 16
                          },
                          "resolves_to": ["foo.source"],
                          "port": "result"
                        },
                        "tito_positions": [ { "line": 17, "start": 18, "end": 19 } ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled_a" } ],
                            "features": [ { "always-via": "source-feature" } ]
                          },
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled_b" } ],
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
                            "line": 20,
                            "start": 21,
                            "end": 22
                          },
                          "resolves_to": ["foo.sink"],
                          "port": "formal(x)[parameter]"
                        },
                        "tito_positions": [ { "line": 23, "start": 24, "end": 25 } ],
                        "kinds": [
                          {
                            "kind": "SQL",
                            "length": 2,
                            "leaves": [ { "name": "_sql" } ],
                            "features": [ { "always-via": "sink-other-feature" } ]
                          },
                          {
                            "kind": "RCE",
                            "length": 1,
                            "leaves": [ { "name": "_remote_code_execution_a" } ],
                            "features": [ { "always-via": "sink-feature" } ]
                          },
                          {
                            "kind": "RCE",
                            "length": 1,
                            "leaves": [ { "name": "_remote_code_execution_b" } ],
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
                    message="[UserControlled, Header] to [RCE, SQL]",
                    callable="foo.bar",
                    handle="foo.bar:1:0:Call|foo.sink|0|formal(x)",
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
                            leaves=[
                                ("Header", 2),
                                ("UserControlled", 1),
                            ],
                            titos=[
                                SourceLocation(
                                    line_no=17, begin_column=19, end_column=19
                                ),
                            ],
                            features=[],
                            type_interval=ParseTypeInterval(
                                start=50,
                                finish=71,
                                preserves_type_context=False,
                            ),
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
                            leaves=[
                                ("RCE", 1),
                                ("SQL", 2),
                            ],
                            titos=[
                                SourceLocation(
                                    line_no=23, begin_column=25, end_column=25
                                )
                            ],
                            features=[],
                            type_interval=ParseTypeInterval(
                                start=0,
                                finish=sys.maxsize,
                                preserves_type_context=False,
                            ),
                            annotations=[],
                        ),
                    ],
                    initial_sources={
                        ("_user_controlled_a", "UserControlled", 1),
                        ("_user_controlled_b", "UserControlled", 1),
                        ("_header", "Header", 2),
                    },
                    final_sinks={
                        ("_remote_code_execution_a", "RCE", 1),
                        ("_remote_code_execution_b", "RCE", 1),
                        ("_sql", "SQL", 2),
                    },
                    features=["always-via:foo", "via:bar"],
                    fix_info=None,
                )
            ],
        )

    def testIssueV3_duplicateTitos(self) -> None:
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
                "sink_handle": {
                  "kind": "Call",
                  "callee": "foo.sink",
                  "index": 0,
                  "parameter": "formal(x)"
                },
                "master_handle": "foo.bar:1:0:Call|foo.sink|0|formal(x)",
                "traces": [
                  {
                    "name": "forward",
                    "roots": [
                      {
                        "receiver_interval": [{ "lower": 23, "upper": 24 }],
                        "is_self_call": false,
                        "call": {
                          "position": {
                            "line": 14,
                            "start": 15,
                            "end": 16
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result"
                        },
                        "tito_positions": [
                          { "line": 17, "start": 18, "end": 19 },
                          { "line": 17, "start": 18, "end": 19 }
                        ],
                        "local_features": [ { "always-via": "source-local" } ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "source-feature" } ],
                            "extra_traces": [
                              {
                                "call": {
                                  "position": {
                                    "line": 117,
                                    "start": 22,
                                    "end": 24
                                  },
                                  "resolves_to": [
                                    "extra_trace.transform_yz"
                                  ],
                                  "port": "formal(arg)"
                                },
                                "kind": "TransformY:TransformZ:ExtraTraceSink"
                              }
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
                        "caller_interval": [{
                          "lower": 10,
                          "upper": 11
                        }],
                        "is_self_call": true,
                        "call": {
                          "position": {
                            "line": 20,
                            "start": 21,
                            "end": 22
                          },
                          "resolves_to": [
                            "foo.sink"
                          ],
                          "port": "formal(x)[parameter]"
                        },
                        "tito_positions": [
                          { "line": 23, "start": 24, "end": 25 },
                          { "line": 23, "start": 24, "end": 25 }
                        ],
                        "local_features": [ { "always-via": "sink-local" } ],
                        "kinds": [
                          {
                            "kind": "RCE",
                            "length": 2,
                            "leaves": [ { "name": "_remote_code_execution" } ],
                            "features": [ { "always-via": "sink-feature" } ],
                            "extra_traces": [
                              {
                                "call": {
                                  "position": {
                                    "line": 117,
                                    "start": 22,
                                    "end": 24
                                  },
                                  "resolves_to": [
                                    "extra_trace.transform_yz"
                                  ],
                                  "port": "formal(arg)"
                                },
                                "leaf_kind": "TransformY:TransformZ:ExtraTraceSink",
                                "trace_kind": "sink"
                              }
                            ]
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
                    handle="foo.bar:1:0:Call|foo.sink|0|formal(x)",
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
                            type_interval=ParseTypeInterval(
                                start=23,
                                finish=24,
                                preserves_type_context=False,
                            ),
                            annotations=[
                                ParseTraceAnnotation(
                                    location=SourceLocation(
                                        line_no=117, begin_column=23, end_column=24
                                    ),
                                    kind="tito_transform",
                                    msg="",
                                    leaf_kind="TransformY:TransformZ:ExtraTraceSink",
                                    leaf_depth=0,
                                    type_interval=None,
                                    link=None,
                                    trace_key=None,
                                    titos=[],
                                    subtraces=[
                                        ParseTraceAnnotationSubtrace(
                                            callee="extra_trace.transform_yz",
                                            port="formal(arg)",
                                            position=SourceLocation(
                                                line_no=117,
                                                begin_column=23,
                                                end_column=24,
                                            ),
                                        )
                                    ],
                                )
                            ],
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
                            type_interval=ParseTypeInterval(
                                start=0, finish=sys.maxsize, preserves_type_context=True
                            ),
                            annotations=[
                                ParseTraceAnnotation(
                                    location=SourceLocation(
                                        line_no=117, begin_column=23, end_column=24
                                    ),
                                    kind="sink",
                                    msg="",
                                    leaf_kind="TransformY:TransformZ:ExtraTraceSink",
                                    leaf_depth=0,
                                    type_interval=None,
                                    link=None,
                                    trace_key=None,
                                    titos=[],
                                    subtraces=[
                                        ParseTraceAnnotationSubtrace(
                                            callee="extra_trace.transform_yz",
                                            port="formal(arg)",
                                            position=SourceLocation(
                                                line_no=117,
                                                begin_column=23,
                                                end_column=24,
                                            ),
                                        )
                                    ],
                                )
                            ],
                        )
                    ],
                    initial_sources={("_user_controlled", "UserControlled", 1)},
                    final_sinks={("_remote_code_execution", "RCE", 2)},
                    features=["always-via:foo", "via:bar"],
                    fix_info=None,
                )
            ],
        )

    def testSourceModelV3_userDeclared(self) -> None:
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
                        "declaration": null,
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

    def testSourceModelV3_direct(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito_positions": [
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
                        ],
                        "caller_interval": [{
                          "lower": 10,
                          "upper": 11
                        }],
                        "receiver_interval": [
                          { "lower": 25, "upper": 30 },
                          { "lower": 35, "upper": 40 }
                        ],
                        "is_self_call": false
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
                    leaves=[
                        ("Header", 0),
                        ("UserControlled", 0),
                    ],
                    caller_port="result",
                    callee_port="source",
                    type_interval=ParseTypeInterval(
                        start=25, finish=40, preserves_type_context=False
                    ),
                    features=[ParseTraceFeature("always-via:source-local", [])],
                    annotations=[],
                )
            ],
        )

    def testSourceModelV3_directWithMultipleLeaves(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result[attribute]",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito_positions": [
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
                        ],
                        "is_self_call": false
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSourceModelV3_directWithPortsOnLeaves(self) -> None:
        # (e.g, cross-repo),
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito_positions": [
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
                            "features": [ { "always-via": "direct-source" } ],
                            "extra_traces": [
                              {
                                "call": {
                                  "position": { "line": 59, "start": 32, "end": 34 },
                                  "resolves_to": [ "extra_trace.nested_transform_x" ],
                                  "port": "formal(arg)"
                                },
                                "leaf_kind": "TransformX:ExtraTraceSink",
                                "trace_kind": "tito_transform"
                              }
                            ]
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
                            "features": [ { "always-via": "cross-repo-source" } ],
                            "extra_traces": [
                              {
                                "call": {
                                  "position": { "line": 59, "start": 32, "end": 34 },
                                  "resolves_to": [ "extra_trace.nested_transform_x" ],
                                  "port": "formal(arg)"
                                },
                                "leaf_kind": "TransformX:ExtraTraceSink",
                                "trace_kind": "tito_transform"
                              }
                            ]
                          }
                        ],
                        "receiver_interval": [{ "lower": 26, "upper": 31 }],
                        "is_self_call": true
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
                    type_interval=ParseTypeInterval(
                        start=26, finish=31, preserves_type_context=True
                    ),
                    features=[],
                    annotations=[
                        ParseTraceAnnotation(
                            location=SourceLocation(
                                line_no=59, begin_column=33, end_column=34
                            ),
                            kind="tito_transform",
                            msg="",
                            leaf_kind="TransformX:ExtraTraceSink",
                            leaf_depth=0,
                            type_interval=None,
                            link=None,
                            trace_key=None,
                            titos=[],
                            subtraces=[
                                ParseTraceAnnotationSubtrace(
                                    callee="extra_trace.nested_transform_x",
                                    port="formal(arg)",
                                    position=SourceLocation(
                                        line_no=59, begin_column=33, end_column=34
                                    ),
                                )
                            ],
                        )
                    ],
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
                    leaves=[
                        ("Header", 0),
                        ("UserControlled", 0),
                    ],
                    caller_port="result",
                    callee_port="producer:1:result",
                    type_interval=ParseTypeInterval(
                        start=26, finish=31, preserves_type_context=True
                    ),
                    features=[],
                    annotations=[
                        ParseTraceAnnotation(
                            location=SourceLocation(
                                line_no=59, begin_column=33, end_column=34
                            ),
                            kind="tito_transform",
                            msg="",
                            leaf_kind="TransformX:ExtraTraceSink",
                            leaf_depth=0,
                            type_interval=None,
                            link=None,
                            trace_key=None,
                            titos=[],
                            subtraces=[
                                ParseTraceAnnotationSubtrace(
                                    callee="extra_trace.nested_transform_x",
                                    port="formal(arg)",
                                    position=SourceLocation(
                                        line_no=59, begin_column=33, end_column=34
                                    ),
                                )
                            ],
                        )
                    ],
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
                    type_interval=ParseTypeInterval(
                        start=26, finish=31, preserves_type_context=True
                    ),
                    features=[],
                    annotations=[
                        ParseTraceAnnotation(
                            location=SourceLocation(
                                line_no=59, begin_column=33, end_column=34
                            ),
                            kind="tito_transform",
                            msg="",
                            leaf_kind="TransformX:ExtraTraceSink",
                            leaf_depth=0,
                            type_interval=None,
                            link=None,
                            trace_key=None,
                            titos=[],
                            subtraces=[
                                ParseTraceAnnotationSubtrace(
                                    callee="extra_trace.nested_transform_x",
                                    port="formal(arg)",
                                    position=SourceLocation(
                                        line_no=59, begin_column=33, end_column=34
                                    ),
                                ),
                            ],
                        )
                    ],
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
                    type_interval=ParseTypeInterval(
                        start=26, finish=31, preserves_type_context=True
                    ),
                    features=[],
                    annotations=[
                        ParseTraceAnnotation(
                            location=SourceLocation(
                                line_no=59, begin_column=33, end_column=34
                            ),
                            kind="tito_transform",
                            msg="",
                            leaf_kind="TransformX:ExtraTraceSink",
                            leaf_depth=0,
                            type_interval=None,
                            link=None,
                            trace_key=None,
                            titos=[],
                            subtraces=[
                                ParseTraceAnnotationSubtrace(
                                    callee="extra_trace.nested_transform_x",
                                    port="formal(arg)",
                                    position=SourceLocation(
                                        line_no=59, begin_column=33, end_column=34
                                    ),
                                )
                            ],
                        )
                    ],
                ),
            ],
        )

    def testSourceModelV3_indirect(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result[field]",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result[attribute]"
                        },
                        "tito_positions": [
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
                        ],
                        "caller_interval": [
                          {
                            "lower": 11,
                            "upper": 12
                          },
                          {
                            "lower": 15,
                            "upper": 20
                          }
                        ],
                        "is_self_call": false
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
                    leaves=[
                        ("Header", 3),
                        ("UserControlled", 2),
                    ],
                    caller_port="result[field]",
                    callee_port="result[attribute]",
                    type_interval=ParseTypeInterval(
                        start=0, finish=sys.maxsize, preserves_type_context=False
                    ),
                    features=[],
                    annotations=[],
                )
            ],
        )

    def testSourceModelV3_indirectWithMultipleCallees(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "call": {
                          "position": {
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
                        "tito_positions": [
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
                        ],
                        "caller_interval": [
                          {
                            "lower": 12,
                            "upper": 13
                          }
                        ],
                        "is_self_call": true
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
                    type_interval=ParseTypeInterval(
                        start=0, finish=sys.maxsize, preserves_type_context=True
                    ),
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
                    type_interval=ParseTypeInterval(
                        start=0, finish=sys.maxsize, preserves_type_context=True
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSourceModelV3_directAndIndirect(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito_positions": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "direct-source" } ]
                          }
                        ],
                        "is_self_call": false
                      },
                      {
                        "call": {
                          "position": {
                            "line": 100,
                            "start": 101,
                            "end": 102
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result[attribute]"
                        },
                        "tito_positions": [
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
                        ],
                        "is_self_call": false
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSourceModelV3_userDeclaredParameter(self) -> None:
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
                        "declaration": null,
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

    def testSourceModelV3_implicit(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "kinds": [ { "kind": "UserControlled" } ],
                        "is_self_call": false
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSourceModelV3_directAndIndirectWithSameCalleeAndPort(self) -> None:
        # Note: Pysa would NOT actually emit this, it would emit a single "taint".
        # This is only for test purposes.
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result"
                        },
                        "tito_positions": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "indirect-source" } ]
                          }
                        ],
                        "is_self_call": false
                      },
                      {
                        "call": {
                          "position": {
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result"
                        },
                        "tito_positions": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 2,
                            "leaves": [ { "name": "_another_user_controlled" } ],
                            "features": [ { "always-via": "another-indirect-source" } ]
                          }
                        ],
                        "is_self_call": false
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
                    leaves=[
                        ("UserControlled", 1),
                        ("UserControlled", 2),
                    ],
                    caller_port="result",
                    callee_port="result",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSourceModelV3_differentSubtraces(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result"
                        },
                        "tito_positions": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "indirect-source" } ],
                            "extra_traces": [
                              {
                                "call": {
                                  "position": { "line": 16, "start": 17, "end": 18 },
                                  "resolves_to": [ "extra_trace.nested_transform_x" ],
                                  "port": "formal(arg)"
                                },
                                "leaf_kind": "TransformX:ExtraTraceSink",
                                "trace_kind": "tito_transform"
                              }
                            ]
                          },
                          {
                            "kind": "Header",
                            "length": 2,
                            "leaves": [ { "name": "_header" } ],
                            "features": [ { "always-via": "indirect-source" } ],
                            "extra_traces": [
                              {
                                "call": {
                                  "position": { "line": 19, "start": 20, "end": 21 },
                                  "resolves_to": [ "extra_trace.nested_transform_y" ],
                                  "port": "formal(arg)"
                                },
                                "leaf_kind": "TransformY:ExtraTraceSink",
                                "trace_kind": "tito_transform"
                              }
                            ]
                          }
                        ],
                        "is_self_call": false
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
                    leaves=[("UserControlled", 1)],
                    caller_port="result",
                    callee_port="result",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[
                        ParseTraceAnnotation(
                            location=SourceLocation(
                                line_no=16, begin_column=18, end_column=18
                            ),
                            kind="tito_transform",
                            msg="",
                            leaf_kind="TransformX:ExtraTraceSink",
                            leaf_depth=0,
                            type_interval=None,
                            link=None,
                            trace_key=None,
                            titos=[],
                            subtraces=[
                                ParseTraceAnnotationSubtrace(
                                    callee="extra_trace.nested_transform_x",
                                    port="formal(arg)",
                                    position=SourceLocation(
                                        line_no=16,
                                        begin_column=18,
                                        end_column=18,
                                    ),
                                )
                            ],
                        )
                    ],
                ),
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
                    leaves=[("Header", 2)],
                    caller_port="result",
                    callee_port="result",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[
                        ParseTraceAnnotation(
                            location=SourceLocation(
                                line_no=19, begin_column=21, end_column=21
                            ),
                            kind="tito_transform",
                            msg="",
                            leaf_kind="TransformY:ExtraTraceSink",
                            leaf_depth=0,
                            type_interval=None,
                            link=None,
                            trace_key=None,
                            titos=[],
                            subtraces=[
                                ParseTraceAnnotationSubtrace(
                                    callee="extra_trace.nested_transform_y",
                                    port="formal(arg)",
                                    position=SourceLocation(
                                        line_no=19,
                                        begin_column=21,
                                        end_column=21,
                                    ),
                                )
                            ],
                        )
                    ],
                ),
            ],
        )

    def testSourceModelV3_withAndWithoutSubtrace(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result"
                        },
                        "tito_positions": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "indirect-source" } ],
                            "extra_traces": [
                              {
                                "call": {
                                  "position": { "line": 16, "start": 17, "end": 18 },
                                  "resolves_to": [ "extra_trace.nested_transform_x" ],
                                  "port": "formal(arg)"
                                },
                                "leaf_kind": "TransformX:ExtraTraceSink",
                                "trace_kind": "tito_transform"
                              }
                            ]
                          },
                          {
                            "kind": "Header",
                            "length": 2,
                            "leaves": [ { "name": "_header" } ],
                            "features": [ { "always-via": "indirect-source" } ]
                          }
                        ],
                        "is_self_call": false
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
                    leaves=[("UserControlled", 1)],
                    caller_port="result",
                    callee_port="result",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[
                        ParseTraceAnnotation(
                            location=SourceLocation(
                                line_no=16, begin_column=18, end_column=18
                            ),
                            kind="tito_transform",
                            msg="",
                            leaf_kind="TransformX:ExtraTraceSink",
                            leaf_depth=0,
                            type_interval=None,
                            link=None,
                            trace_key=None,
                            titos=[],
                            subtraces=[
                                ParseTraceAnnotationSubtrace(
                                    callee="extra_trace.nested_transform_x",
                                    port="formal(arg)",
                                    position=SourceLocation(
                                        line_no=16,
                                        begin_column=18,
                                        end_column=18,
                                    ),
                                )
                            ],
                        )
                    ],
                ),
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
                    leaves=[("Header", 2)],
                    caller_port="result",
                    callee_port="result",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSourceModelV3_oldSubtraceSyntax(self) -> None:
        # Properly parse old subtrace syntax.
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result"
                        },
                        "tito_positions": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "indirect-source" } ]
                          },
                          {
                            "kind": "Header",
                            "length": 2,
                            "leaves": [ { "name": "_header" } ],
                            "features": [ { "always-via": "indirect-source" } ]
                          }
                        ],
                        "is_self_call": false,
                        "extra_traces": [
                          {
                            "call": {
                              "position": { "line": 16, "start": 17, "end": 18 },
                              "resolves_to": [ "extra_trace.nested_transform_x" ],
                              "port": "formal(arg)"
                            },
                            "leaf_kind": "TransformX:ExtraTraceSink",
                            "trace_kind": "tito_transform"
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
                    leaves=[
                        ("Header", 2),
                        ("UserControlled", 1),
                    ],
                    caller_port="result",
                    callee_port="result",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[
                        ParseTraceAnnotation(
                            location=SourceLocation(
                                line_no=16, begin_column=18, end_column=18
                            ),
                            kind="tito_transform",
                            msg="",
                            leaf_kind="TransformX:ExtraTraceSink",
                            leaf_depth=0,
                            type_interval=None,
                            link=None,
                            trace_key=None,
                            titos=[],
                            subtraces=[
                                ParseTraceAnnotationSubtrace(
                                    callee="extra_trace.nested_transform_x",
                                    port="formal(arg)",
                                    position=SourceLocation(
                                        line_no=16,
                                        begin_column=18,
                                        end_column=18,
                                    ),
                                )
                            ],
                        )
                    ],
                ),
            ],
        )

    def testSourceModelV3_combinedOldAndNewSubtraceSyntax(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result"
                        },
                        "tito_positions": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "indirect-source" } ]
                          },
                          {
                            "kind": "Header",
                            "length": 2,
                            "leaves": [ { "name": "_header" } ],
                            "features": [ { "always-via": "indirect-source" } ],
                            "extra_traces": [
                              {
                                "call": {
                                  "position": { "line": 19, "start": 20, "end": 21 },
                                  "resolves_to": [ "extra_trace.nested_transform_y" ],
                                  "port": "formal(arg)"
                                },
                                "leaf_kind": "TransformY:ExtraTraceSink",
                                "trace_kind": "tito_transform"
                              }
                            ]
                          }
                        ],
                        "is_self_call": false,
                        "extra_traces": [
                          {
                            "call": {
                              "position": { "line": 16, "start": 17, "end": 18 },
                              "resolves_to": [ "extra_trace.nested_transform_x" ],
                              "port": "formal(arg)"
                            },
                            "leaf_kind": "TransformX:ExtraTraceSink",
                            "trace_kind": "tito_transform"
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
                    leaves=[("UserControlled", 1)],
                    caller_port="result",
                    callee_port="result",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[
                        ParseTraceAnnotation(
                            location=SourceLocation(
                                line_no=16, begin_column=18, end_column=18
                            ),
                            kind="tito_transform",
                            msg="",
                            leaf_kind="TransformX:ExtraTraceSink",
                            leaf_depth=0,
                            type_interval=None,
                            link=None,
                            trace_key=None,
                            titos=[],
                            subtraces=[
                                ParseTraceAnnotationSubtrace(
                                    callee="extra_trace.nested_transform_x",
                                    port="formal(arg)",
                                    position=SourceLocation(
                                        line_no=16,
                                        begin_column=18,
                                        end_column=18,
                                    ),
                                )
                            ],
                        )
                    ],
                ),
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
                    leaves=[("Header", 2)],
                    caller_port="result",
                    callee_port="result",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[
                        ParseTraceAnnotation(
                            location=SourceLocation(
                                line_no=16, begin_column=18, end_column=18
                            ),
                            kind="tito_transform",
                            msg="",
                            leaf_kind="TransformX:ExtraTraceSink",
                            leaf_depth=0,
                            type_interval=None,
                            link=None,
                            trace_key=None,
                            titos=[],
                            subtraces=[
                                ParseTraceAnnotationSubtrace(
                                    callee="extra_trace.nested_transform_x",
                                    port="formal(arg)",
                                    position=SourceLocation(
                                        line_no=16,
                                        begin_column=18,
                                        end_column=18,
                                    ),
                                )
                            ],
                        ),
                        ParseTraceAnnotation(
                            location=SourceLocation(
                                line_no=19, begin_column=21, end_column=21
                            ),
                            kind="tito_transform",
                            msg="",
                            leaf_kind="TransformY:ExtraTraceSink",
                            leaf_depth=0,
                            type_interval=None,
                            link=None,
                            trace_key=None,
                            titos=[],
                            subtraces=[
                                ParseTraceAnnotationSubtrace(
                                    callee="extra_trace.nested_transform_y",
                                    port="formal(arg)",
                                    position=SourceLocation(
                                        line_no=19,
                                        begin_column=21,
                                        end_column=21,
                                    ),
                                )
                            ],
                        ),
                    ],
                ),
            ],
        )

    def testSourceModelV3_kindSpecificBreadcrumbs(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result"
                        },
                        "tito_positions": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "local_features": [
                            { "always-via": "shared-breadcrumb" },
                            { "always-via": "other-shared-breadcrumb" }
                        ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "indirect-source" } ],
                            "local_features": [ { "always-via": "user-controlled-breadcrumb" } ]
                          },
                          {
                            "kind": "Header",
                            "length": 2,
                            "leaves": [ { "name": "_header" } ],
                            "features": [ { "always-via": "indirect-source" } ],
                            "local_features": [ { "always-via": "header-breadcrumb" } ]
                          }
                        ],
                        "is_self_call": false
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
                    leaves=[("UserControlled", 1)],
                    caller_port="result",
                    callee_port="result",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[
                        ParseTraceFeature("always-via:other-shared-breadcrumb", []),
                        ParseTraceFeature("always-via:shared-breadcrumb", []),
                        ParseTraceFeature("always-via:user-controlled-breadcrumb", []),
                    ],
                    annotations=[],
                ),
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
                    leaves=[("Header", 2)],
                    caller_port="result",
                    callee_port="result",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[
                        ParseTraceFeature("always-via:header-breadcrumb", []),
                        ParseTraceFeature("always-via:other-shared-breadcrumb", []),
                        ParseTraceFeature("always-via:shared-breadcrumb", []),
                    ],
                    annotations=[],
                ),
            ],
        )

    def testSourceModelV3_duplicateLeaves(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "line": 14,
                            "start": 15,
                            "end": 16
                          },
                          "resolves_to": [
                            "foo.source"
                          ],
                          "port": "result"
                        },
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "length": 1,
                            "leaves": [
                              {
                                "name": "_user_controlled_a"
                              }
                            ]
                          },
                          {
                            "kind": "UserControlled",
                            "leaves": [
                              {
                                "name": "_user_controlled_b"
                              },
                              {
                                "name": "_user_controlled_c"
                              }
                            ]
                          }
                        ],
                        "is_self_call": false
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
                        line_no=14,
                        begin_column=16,
                        end_column=16,
                    ),
                    filename="foo.py",
                    titos=[],
                    leaves=[("UserControlled", 0), ("UserControlled", 1)],
                    caller_port="result",
                    callee_port="result",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSourceModelV3_duplicateTitos(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sources": [
                  {
                    "port": "result",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito_positions": [
                          { "line": 13, "start": 14, "end": 15 },
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 10, "start": 11, "end": 12 }
                        ],
                        "local_features": [ { "always-via": "source-local" } ],
                        "kinds": [
                          {
                            "kind": "UserControlled",
                            "leaves": [ { "name": "_user_controlled" } ],
                            "features": [ { "always-via": "direct-source" } ]
                          }
                        ],
                        "caller_interval": [{
                          "lower": 10,
                          "upper": 11
                        }],
                        "receiver_interval": [
                          { "lower": 25, "upper": 30 },
                          { "lower": 35, "upper": 40 }
                        ],
                        "is_self_call": false
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
                    leaves=[
                        ("UserControlled", 0),
                    ],
                    caller_port="result",
                    callee_port="source",
                    type_interval=ParseTypeInterval(
                        start=25, finish=40, preserves_type_context=False
                    ),
                    features=[ParseTraceFeature("always-via:source-local", [])],
                    annotations=[],
                )
            ],
        )

    def testSinkModelV3_userDeclared(self) -> None:
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
                        "declaration": null,
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

    def testSinkModelV3_direct(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito_positions": [
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
                        ],
                        "caller_interval": [
                          {
                            "lower": 13,
                            "upper": 14
                          }
                        ],
                        "receiver_interval": [{ "lower": 27, "upper": 32 }],
                        "is_self_call": false
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
                    leaves=[
                        ("RCE", 0),
                        ("SQL", 0),
                    ],
                    caller_port="formal(x)",
                    callee_port="sink",
                    type_interval=ParseTypeInterval(
                        start=27, finish=32, preserves_type_context=False
                    ),
                    features=[ParseTraceFeature("always-via:local-sink", [])],
                    annotations=[],
                )
            ],
        )

    def testSinkModelV3_directWithMultipleLeaves(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito_positions": [
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
                        ],
                        "is_self_call": false
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSinkModelV3_directWithPortsOnLeaves(self) -> None:
        # (e.g, cross-repo),
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sinks": [
                  {
                    "port": "formal(y)[attribute]",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito_positions": [
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
                        ],
                        "receiver_interval": [
                          { "lower": 28, "upper": 33 },
                          { "lower": 40, "upper": 53 }
                        ],
                        "is_self_call": false
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
                    type_interval=ParseTypeInterval(
                        start=28, finish=53, preserves_type_context=False
                    ),
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
                    type_interval=ParseTypeInterval(
                        start=28, finish=53, preserves_type_context=False
                    ),
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
                    type_interval=ParseTypeInterval(
                        start=28, finish=53, preserves_type_context=False
                    ),
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
                    type_interval=ParseTypeInterval(
                        start=28, finish=53, preserves_type_context=False
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSinkModelV3_indirect(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.sink"
                          ],
                          "port": "formal(y)[attribute]"
                        },
                        "tito_positions": [
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
                        ],
                        "caller_interval": [
                          {
                            "lower": 17,
                            "upper": 18
                          },
                          {
                            "lower": 20,
                            "upper": 28
                          }
                        ],
                        "is_self_call": false
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[],
                )
            ],
        )

    def testSinkModelV3_indirectWithMultipleCallees(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "call": {
                          "position": {
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
                        "tito_positions": [
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
                        ],
                        "is_self_call": true
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=True,
                    ),
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=True,
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSinkModelV3_directAndIndirect(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito_positions": [
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 13, "start": 14, "end": 15 }
                        ],
                        "kinds": [
                          {
                            "kind": "RCE",
                            "leaves": [ { "name": "_remote_code_execution" } ],
                            "features": [ { "always-via": "direct-sink" } ]
                          }
                        ],
                        "is_self_call": false
                      },
                      {
                        "call": {
                          "position": {
                            "line": 100,
                            "start": 101,
                            "end": 102
                          },
                          "resolves_to": [
                            "foo.sink"
                          ],
                          "port": "formal(y)[attribute]"
                        },
                        "tito_positions": [
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
                        ],
                        "is_self_call": false
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSinkModelV3_userDeclaredReturn(self) -> None:
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
                        "declaration": null,
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

    def testSinkModelV3_implicit(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "kinds": [ { "kind": "RCE" } ],
                        "is_self_call": false
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
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSinkModelV3_duplicateLeaves(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "call": {
                          "position": {
                            "line": 1,
                            "start": 2,
                            "end": 3
                          },
                          "resolves_to": [
                            "foo.sink"
                          ],
                          "port": "formal(y)[attribute]"
                        },
                        "kinds": [
                          {
                            "kind": "RCE",
                            "length": 1,
                            "leaves": [
                              {
                                "name": "_remote_code_execution_a"
                              }
                            ]
                          },
                          {
                            "kind": "RCE",
                            "leaves": [
                              {
                                "name": "_remote_code_execution_b"
                              },
                              {
                                "name": "_remote_code_execution_c"
                              }
                            ]
                          }
                        ],
                        "is_self_call": false
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
                    titos=[],
                    leaves=[("RCE", 0), ("RCE", 1)],
                    caller_port="formal(x)",
                    callee_port="formal(y)[attribute]",
                    type_interval=ParseTypeInterval(
                        start=0,
                        finish=sys.maxsize,
                        preserves_type_context=False,
                    ),
                    features=[],
                    annotations=[],
                ),
            ],
        )

    def testSinkModelV3_duplicateTitos(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "filename": "foo.py",
                "sinks": [
                  {
                    "port": "formal(x)",
                    "taint": [
                      {
                        "origin": {
                          "line": 1,
                          "start": 2,
                          "end": 3
                        },
                        "tito_positions": [
                          { "line": 13, "start": 14, "end": 15 },
                          { "line": 10, "start": 11, "end": 12 },
                          { "line": 10, "start": 11, "end": 12 }
                        ],
                        "local_features": [ { "always-via": "local-sink" } ],
                        "kinds": [
                          {
                            "kind": "SQL",
                            "leaves": [ { "name": "_sql" } ],
                            "features": [ { "always-via": "direct-sink" } ]
                          }
                        ],
                        "caller_interval": [
                          {
                            "lower": 13,
                            "upper": 14
                          }
                        ],
                        "receiver_interval": [{ "lower": 27, "upper": 32 }],
                        "is_self_call": false
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
                    leaves=[
                        ("SQL", 0),
                    ],
                    caller_port="formal(x)",
                    callee_port="sink",
                    type_interval=ParseTypeInterval(
                        start=27, finish=32, preserves_type_context=False
                    ),
                    features=[ParseTraceFeature("always-via:local-sink", [])],
                    annotations=[],
                )
            ],
        )

    def testIgnoreModelsV3_modes(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "modes": [ "Obscure" ]
              }
            }
            """,
            expected=[],
        )

    def testIgnoreModelsV3_sanitizers(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "global_sanitizer": { "sources": "All" }
              }
            }
            """,
            expected=[],
        )

    def testIgnoreModelsV3_tito(self) -> None:
        self.assertParsed(
            version=3,
            input="""
            {
              "kind": "model",
              "data": {
                "callable": "foo.bar",
                "tito": [
                  {
                    "port": "formal(value)",
                    "taint": [
                      {
                        "tito": null,
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
