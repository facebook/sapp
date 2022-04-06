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
    ParseTraceFeature,
    SourceLocation,
)
from ..base_parser import ParseType
from ..mariana_trench_parser import Parser


class TestParser(unittest.TestCase):
    def assertParsed(
        self,
        output: str,
        expected: Iterable[Union[ParseConditionTuple, ParseIssueTuple]],
    ) -> None:
        output = "".join(output.split("\n"))  # Flatten json-line.
        parser = Parser()
        analysis_output = AnalysisOutput(
            directory="/output/directory",
            filename_specs=["models.json"],
            file_handle=io.StringIO(output),
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

    def testEmptyModels(self) -> None:
        self.assertParsed(
            """
            {
              "method": "LClass;.method:()V",
              "position": {
                "line": 1,
                "path": "Class.java"
              }
            }
            """,
            [],
        )

    def testModelWithIssue(self) -> None:
        self.assertParsed(
            """
            {
              "method": "LClass;.flow:()V",
              "issues": [
                {
                  "rule": 1,
                  "position": {
                    "path": "Flow.java",
                    "line": 10,
                    "start": 11,
                    "end": 12
                  },
                  "sinks": [
                    {
                      "callee": "LSink;.sink:(LData;)V",
                      "callee_port": "Argument(1)",
                      "call_position": {
                        "path": "Flow.java",
                        "line": 10,
                        "start": 11,
                        "end": 12
                      },
                      "distance": 2,
                      "always_features": ["via-parameter-field"],
                      "kind": "TestSink",
                      "origins": ["LSink;.sink:(LData;)V"],
                      "local_positions": [{"line": 13, "start": 14, "end": 15}],
                      "local_features": { "always_features": ["via-parameter-field"] }
                    }
                  ],
                  "sources": [
                    {
                      "callee": "LSource;.source:()LData;",
                      "callee_port": "Return",
                      "call_position": {
                        "path": "Flow.java",
                        "line": 20,
                        "start": 21,
                        "end": 22
                      },
                      "distance": 3,
                      "may_features": ["via-obscure"],
                      "kind": "TestSource",
                      "origins": ["LSource;.source:(LData;)V"],
                      "local_positions": [
                        {"line": 23, "start": 24, "end": 25},
                        {"line": 26, "start": 27, "end": 28}
                      ]
                    }
                  ],
                  "may_features": ["via-obscure"],
                  "always_features": ["via-parameter-field"]
                }
              ],
              "position": {
                "line": 2,
                "path": "Flow.java"
              }
            }
            """,
            [
                ParseIssueTuple(
                    code=1,
                    message="TestRule: Test Rule Description",
                    callable="LClass;.flow:()V",
                    handle="LClass;.flow:()V:8|12|13:1:f75a532726260b3b",
                    filename="Flow.java",
                    callable_line=2,
                    line=10,
                    start=12,
                    end=13,
                    preconditions=[
                        ParseIssueConditionTuple(
                            callee="LSink;.sink:(LData;)V",
                            port="argument(1)",
                            location=SourceLocation(
                                line_no=10,
                                begin_column=12,
                                end_column=13,
                            ),
                            leaves=[("TestSink", 2)],
                            titos=[
                                SourceLocation(
                                    line_no=13, begin_column=15, end_column=16
                                )
                            ],
                            features=[
                                ParseTraceFeature("always-via-parameter-field", []),
                                ParseTraceFeature("via-parameter-field", []),
                            ],
                            type_interval=None,
                            annotations=[],
                        )
                    ],
                    postconditions=[
                        ParseIssueConditionTuple(
                            callee="LSource;.source:()LData;",
                            port="result",
                            location=SourceLocation(
                                line_no=20,
                                begin_column=22,
                                end_column=23,
                            ),
                            leaves=[("TestSource", 3)],
                            titos=[
                                SourceLocation(
                                    line_no=23, begin_column=25, end_column=26
                                ),
                                SourceLocation(
                                    line_no=26, begin_column=28, end_column=29
                                ),
                            ],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        )
                    ],
                    initial_sources={("LSource;.source:(LData;)V", "TestSource", 3)},
                    final_sinks={("LSink;.sink:(LData;)V", "TestSink", 2)},
                    features=[
                        "always-via-parameter-field",
                        "via-obscure",
                        "via-parameter-field",
                    ],
                    fix_info=None,
                )
            ],
        )
        self.assertParsed(
            """
            {
              "method": "LClass;.flow:()V",
              "issues": [
                {
                  "rule": 1,
                  "position": {
                    "path": "Flow.java",
                    "line": 10,
                    "start": 11,
                    "end": 12
                  },
                  "sinks": [
                    {
                      "callee": "LSink;.sink:(LData;)V",
                      "callee_port": "Argument(1)",
                      "call_position": {
                        "path": "Flow.java",
                        "line": 10,
                        "start": 11,
                        "end": 12
                      },
                      "distance": 2,
                      "always_features": ["via-parameter-field"],
                      "kind": "TestSink",
                      "origins": ["LSink;.sink:(LData;)V"],
                      "local_positions": [{"line": 13, "start": 14, "end": 15}]
                    },
                    {
                      "callee": "LSink;.sink:(LData;)V",
                      "callee_port": "Argument(1)",
                      "call_position": {
                        "path": "Flow.java",
                        "line": 20,
                        "start": 21,
                        "end": 22
                      },
                      "distance": 3,
                      "always_features": ["via-obscure"],
                      "kind": "TestSink",
                      "origins": ["LSink;.other_sink:(LData;)V"]
                    }
                  ],
                  "sources": [
                    {
                      "callee": "LSource;.source:()LData;",
                      "callee_port": "Return",
                      "call_position": {
                        "path": "Flow.java",
                        "line": 30,
                        "start": 31,
                        "end": 32
                      },
                      "distance": 3,
                      "kind": "TestSource",
                      "origins": ["LSource;.source:(LData;)V"],
                      "local_positions": [{"line": 33, "start": 34, "end": 35}]
                    }
                  ],
                  "may_features": ["via-obscure", "via-parameter-field"]
                }
              ],
              "position": {
                "line": 2,
                "path": "Flow.java"
              }
            }
            """,
            [
                ParseIssueTuple(
                    code=1,
                    message="TestRule: Test Rule Description",
                    callable="LClass;.flow:()V",
                    handle="LClass;.flow:()V:8|12|13:1:f75a532726260b3b",
                    filename="Flow.java",
                    callable_line=2,
                    line=10,
                    start=12,
                    end=13,
                    preconditions=[
                        ParseIssueConditionTuple(
                            callee="LSink;.sink:(LData;)V",
                            port="argument(1)",
                            location=SourceLocation(
                                line_no=10,
                                begin_column=12,
                                end_column=13,
                            ),
                            leaves=[("TestSink", 2)],
                            titos=[
                                SourceLocation(
                                    line_no=13, begin_column=15, end_column=16
                                )
                            ],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        ),
                        ParseIssueConditionTuple(
                            callee="LSink;.sink:(LData;)V",
                            port="argument(1)",
                            location=SourceLocation(
                                line_no=20,
                                begin_column=22,
                                end_column=23,
                            ),
                            leaves=[("TestSink", 3)],
                            titos=[],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    postconditions=[
                        ParseIssueConditionTuple(
                            callee="LSource;.source:()LData;",
                            port="result",
                            location=SourceLocation(
                                line_no=30,
                                begin_column=32,
                                end_column=33,
                            ),
                            leaves=[("TestSource", 3)],
                            titos=[
                                SourceLocation(
                                    line_no=33, begin_column=35, end_column=36
                                )
                            ],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        )
                    ],
                    initial_sources={("LSource;.source:(LData;)V", "TestSource", 3)},
                    final_sinks={
                        ("LSink;.sink:(LData;)V", "TestSink", 2),
                        ("LSink;.other_sink:(LData;)V", "TestSink", 3),
                    },
                    features=["via-obscure", "via-parameter-field"],
                    fix_info=None,
                )
            ],
        )
        self.assertParsed(
            """
            {
              "method": "LClass;.flow:()V",
              "issues": [
                {
                  "rule": 1,
                  "position": {
                    "path": "Flow.java",
                    "line": 10,
                    "start": 11,
                    "end": 12
                  },
                  "sinks": [
                    {
                      "callee": "LSink;.sink:(LData;)V",
                      "callee_port": "Argument(1)",
                      "call_position": {
                        "path": "Flow.java",
                        "line": 10,
                        "start": 11,
                        "end": 12
                      },
                      "distance": 2,
                      "always_features": ["via-parameter-field"],
                      "kind": "TestSink",
                      "origins": ["LSink;.sink:(LData;)V"],
                      "local_positions": [{"line": 13, "start": 14, "end": 15}]
                    }
                  ],
                  "sources": [
                    {
                      "callee_port": "Leaf",
                      "distance": 0,
                      "kind": "TestSource",
                      "field_origins": ["LSource;.sourceField:LData;"],
                      "local_positions": [{"line": 33, "start": 34, "end": 35}]
                    }
                  ],
                  "may_features": ["via-obscure", "via-parameter-field"]
                }
              ],
              "position": {
                "line": 2,
                "path": "Flow.java"
              }
            }
            """,
            [
                ParseIssueTuple(
                    code=1,
                    message="TestRule: Test Rule Description",
                    callable="LClass;.flow:()V",
                    handle="LClass;.flow:()V:8|12|13:1:f75a532726260b3b",
                    filename="Flow.java",
                    callable_line=2,
                    line=10,
                    start=12,
                    end=13,
                    preconditions=[
                        ParseIssueConditionTuple(
                            callee="LSink;.sink:(LData;)V",
                            port="argument(1)",
                            location=SourceLocation(
                                line_no=10,
                                begin_column=12,
                                end_column=13,
                            ),
                            leaves=[("TestSink", 2)],
                            titos=[
                                SourceLocation(
                                    line_no=13, begin_column=15, end_column=16
                                )
                            ],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        )
                    ],
                    postconditions=[
                        ParseIssueConditionTuple(
                            callee="leaf",
                            port="source",
                            location=SourceLocation(
                                line_no=2,
                                begin_column=1,
                                end_column=1,
                            ),
                            leaves=[("TestSource", 0)],
                            titos=[
                                SourceLocation(
                                    line_no=33, begin_column=35, end_column=36
                                )
                            ],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        )
                    ],
                    initial_sources={("LSource;.sourceField:LData;", "TestSource", 0)},
                    final_sinks={
                        ("LSink;.sink:(LData;)V", "TestSink", 2),
                    },
                    features=["via-obscure", "via-parameter-field"],
                    fix_info=None,
                )
            ],
        )

    def testModelPostconditions(self) -> None:
        # Leaf case.
        self.assertParsed(
            """
            {
              "method": "LSource;.source:()V",
              "generations": [
                {
                  "kind": "TestSource",
                  "caller_port": "Return",
                  "origins": ["LSource;.source:()V"],
                  "callee_port": "Leaf"
                }
              ],
              "position": {
                "line": 1,
                "path": "Source.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="LSource;.source:()V",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="Source.java",
                    titos=[],
                    leaves=[("TestSource", 0)],
                    caller_port="result",
                    callee_port="source",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )

        # Node case.
        self.assertParsed(
            """
            {
              "method": "LClass;.indirect_source:()V",
              "generations": [
                {
                  "callee": "LSource;.source:()LData;",
                  "callee_port": "Return",
                  "call_position": {
                    "path": "Class.java",
                    "line": 10,
                    "start": 11,
                    "end": 12
                  },
                  "distance": 1,
                  "kind": "TestSource",
                  "caller_port": "Return",
                  "origins": ["LSource;.source:()V"],
                  "local_positions": [
                    {"line": 13, "start": 14, "end": 15},
                    {"line": 16, "start": 17, "end": 18}
                  ]
                }
              ],
              "position": {
                "line": 1,
                "path": "Class.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="LClass;.indirect_source:()V",
                    callee="LSource;.source:()LData;",
                    callee_location=SourceLocation(
                        line_no=10,
                        begin_column=12,
                        end_column=13,
                    ),
                    filename="Class.java",
                    titos=[
                        SourceLocation(line_no=13, begin_column=15, end_column=16),
                        SourceLocation(line_no=16, begin_column=18, end_column=19),
                    ],
                    leaves=[("TestSource", 1)],
                    caller_port="result",
                    callee_port="result",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )

        # Test with a complex port.
        self.assertParsed(
            """
            {
              "method": "LSource;.source:()V",
              "generations": [
                {
                  "kind": "TestSource",
                  "caller_port": "Return.x.y",
                  "origins": ["LSource;.source:()V"],
                  "callee_port": "Leaf",
                  "local_features": {
                    "may_features": ["via-source"]
                  }
                }
              ],
              "position": {
                "line": 1,
                "path": "Source.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="LSource;.source:()V",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="Source.java",
                    titos=[],
                    leaves=[("TestSource", 0)],
                    caller_port="result.x.y",
                    callee_port="source",
                    type_interval=None,
                    features=[ParseTraceFeature("via-source", [])],
                    annotations=[],
                )
            ],
        )

        # Test with a parameter source.
        self.assertParsed(
            """
            {
              "method": "LSource;.source:()V",
              "generations": [
                {
                  "kind": "TestSource",
                  "callee_port": "Leaf",
                  "call_position": {
                    "path": "Source.java",
                    "line": 2,
                    "start": 3,
                    "end": 4
                  },
                  "caller_port": "Return",
                  "origins": ["LSource;.source:()V"]
                }
              ],
              "position": {
                "line": 1,
                "path": "Source.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="LSource;.source:()V",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=2,
                        begin_column=4,
                        end_column=5,
                    ),
                    filename="Source.java",
                    titos=[],
                    leaves=[("TestSource", 0)],
                    caller_port="result",
                    callee_port="source",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )

    def testModelPreconditions(self) -> None:
        # Leaf case.
        self.assertParsed(
            """
            {
              "method": "LSink;.sink:(LData;)V",
              "sinks": [
                {
                  "kind": "TestSink",
                  "caller_port": "Argument(1)",
                  "origins": ["LSink;.sink:(LData;)V"],
                  "callee_port": "Leaf"
                }
              ],
              "position": {
                "line": 1,
                "path": "Sink.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="LSink;.sink:(LData;)V",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="Sink.java",
                    titos=[],
                    leaves=[("TestSink", 0)],
                    caller_port="argument(1)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )

        # Node case.
        self.assertParsed(
            """
            {
              "method": "LClass;.indirect_sink:(LData;LData;)V",
              "sinks": [
                {
                  "callee": "LSink;.sink:(LData;)V",
                  "callee_port": "Argument(1)",
                  "call_position": {
                    "path": "Class.java",
                    "line": 10,
                    "start": 11,
                    "end": 12
                  },
                  "distance": 1,
                  "kind": "TestSink",
                  "origins": ["LSink;.sink:(LData;)V"],
                  "local_positions": [
                    {"line": 13, "start": 14, "end": 15},
                    {"line": 16, "start": 17, "end": 18}
                  ],
                  "caller_port": "Argument(2)"
                }
              ],
              "position": {
                "line": 1,
                "path": "Class.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="LClass;.indirect_sink:(LData;LData;)V",
                    callee="LSink;.sink:(LData;)V",
                    callee_location=SourceLocation(
                        line_no=10,
                        begin_column=12,
                        end_column=13,
                    ),
                    filename="Class.java",
                    titos=[
                        SourceLocation(line_no=13, begin_column=15, end_column=16),
                        SourceLocation(line_no=16, begin_column=18, end_column=19),
                    ],
                    leaves=[("TestSink", 1)],
                    caller_port="argument(2)",
                    callee_port="argument(1)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )

        # Test with a complex port.
        self.assertParsed(
            """
            {
              "method": "LSink;.sink:(LData;)V",
              "sinks": [
                {
                  "kind": "TestSink",
                  "caller_port": "Argument(1).x.y",
                  "origins": ["LSink;.sink:(LData;)V"],
                  "callee_port": "Leaf"
                }
              ],
              "position": {
                "line": 1,
                "path": "Sink.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="LSink;.sink:(LData;)V",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="Sink.java",
                    titos=[],
                    leaves=[("TestSink", 0)],
                    caller_port="argument(1).x.y",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )

        # Test with a return sink.
        self.assertParsed(
            """
            {
              "method": "LSink;.sink:(LData;)V",
              "sinks": [
                {
                  "kind": "TestSink",
                  "callee_port": "Leaf",
                  "call_position": {
                    "path": "Sink.java",
                    "line": 2,
                    "start": 3,
                    "end": 4
                  },
                  "origins": ["LSink;.sink:(LData;)V"],
                  "caller_port": "Argument(2)",
                  "local_features": {
                    "may_features": ["via-sink"]
                  }
                }
              ],
              "position": {
                "line": 1,
                "path": "Sink.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="LSink;.sink:(LData;)V",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=2,
                        begin_column=4,
                        end_column=5,
                    ),
                    filename="Sink.java",
                    titos=[],
                    leaves=[("TestSink", 0)],
                    caller_port="argument(2)",
                    callee_port="sink",
                    type_interval=None,
                    features=[ParseTraceFeature("via-sink", [])],
                    annotations=[],
                )
            ],
        )

    def testModelParameterTypeOverrides(self) -> None:
        self.assertParsed(
            """
            {
              "method": {
                "name": "LSink;.sink:(LData;)V",
                "parameter_type_overrides": [
                  {
                    "parameter": 0,
                    "type": "LAnonymous$0;"
                  },
                  {
                    "parameter": 1,
                    "type": "LAnonymous$1;"
                  }
                ]
              },
              "sinks": [
                {
                  "distance": 0,
                  "kind": "TestSink",
                  "caller_port": "Argument(1)",
                  "origins": [{
                    "name": "LSink;.sink:(LData;)V",
                    "parameter_type_overrides": [
                      {
                        "parameter": 0,
                        "type": "LAnonymous$0;"
                      },
                      {
                        "parameter": 1,
                        "type": "LAnonymous$1;"
                      }
                    ]
                  }],
                  "callee_port": "Leaf"
                }
              ],
              "position": {
                "line": 1,
                "path": "Sink.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="LSink;.sink:(LData;)V[0: LAnonymous$0;, 1: LAnonymous$1;]",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="Sink.java",
                    titos=[],
                    leaves=[("TestSink", 0)],
                    caller_port="argument(1)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )

    def testModelWithConnectionPointSink(self) -> None:
        self.assertParsed(
            """
            {
              "method": {
                "name": "Lcom/facebook/graphql/calls/SomeMutation;.setSomeField:(LData;)V"
              },
              "sinks": [
                {
                  "distance": 0,
                  "kind": "TestSink",
                  "caller_port": "Argument(1)",
                  "callee_port": "Anchor.Argument(0)",
                  "canonical_names": [ { "instantiated": "SomeMutation:some_field" } ]
                }
              ],
              "position": {
                "line": 1,
                "path": "SomeMutation.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="Lcom/facebook/graphql/calls/SomeMutation;.setSomeField:(LData;)V",
                    callee="SomeMutation:some_field",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="SomeMutation.java",
                    titos=[],
                    leaves=[("TestSink", 0)],
                    caller_port="argument(1)",
                    callee_port="anchor:formal(0)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )
        self.assertParsed(
            """
            {
              "method": {
                "name": "Lcom/facebook/graphql/calls/SomeMutation;.setSomeField:(LData;)V"
              },
              "sinks": [
                {
                  "distance": 0,
                  "kind": "TestSink",
                  "caller_port": "Argument(1)",
                  "callee_port": "Anchor.Argument(-1)",
                  "canonical_names": [ { "instantiated": "SomeMutation:some_field" } ]
                }
              ],
              "position": {
                "line": 1,
                "path": "SomeMutation.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="Lcom/facebook/graphql/calls/SomeMutation;.setSomeField:(LData;)V",
                    callee="SomeMutation:some_field",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="SomeMutation.java",
                    titos=[],
                    leaves=[("TestSink", 0)],
                    caller_port="argument(1)",
                    callee_port="anchor:formal(-1)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )
        self.assertParsed(
            """
            {
              "method": {
                "name": "Lcom/facebook/graphql/calls/SomeMutation;.setSomeField:(LData;)V"
              },
              "sinks": [
                {
                  "distance": 0,
                  "kind": "TestSink",
                  "caller_port": "Argument(1)",
                  "callee_port": "Anchor",
                  "canonical_names": [ { "template": "%programmatic_leaf_name%__%source_via_type_of%" } ]
                }
              ],
              "position": {
                "line": 1,
                "path": "SomeMutation.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="Lcom/facebook/graphql/calls/SomeMutation;.setSomeField:(LData;)V",
                    callee="Lcom/facebook/graphql/calls/SomeMutation;.setSomeField:(LData;)V__%source_via_type_of%",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="SomeMutation.java",
                    titos=[],
                    leaves=[("TestSink", 0)],
                    caller_port="argument(1)",
                    callee_port="anchor:formal(1)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )

    def testModelWithConnectionPointSource(self) -> None:
        self.assertParsed(
            """
            {
              "method": {
                "name": "Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V"
              },
              "generations": [
                {
                  "caller": "Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V",
                  "kind": "TestSource",
                  "caller_port": "Return",
                  "origins": [
                   "Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V"
                  ],
                  "callee_port": "Anchor.Return",
                  "canonical_names": [ { "instantiated": "TestEvent:field_a" } ]
                }
              ],
              "position": {
                "line": 1,
                "path": "TestEvent.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V",
                    callee="TestEvent:field_a",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="TestEvent.java",
                    titos=[],
                    leaves=[("TestSource", 0)],
                    caller_port="result",
                    callee_port="anchor:result",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )
        self.assertParsed(
            """
            {
              "method": {
                "name": "Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V"
              },
              "generations": [
                {
                  "caller": "Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V",
                  "kind": "TestSource",
                  "caller_port": "Return",
                  "origins": [
                   "Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V"
                  ],
                  "callee_port": "Producer.1234.Argument(2)",
                  "canonical_names": [ { "instantiated": "LClass;.method:(I)V" }]
                }
              ],
              "position": {
                "line": 1,
                "path": "TestEvent.java"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V",
                    callee="LClass;.method:(I)V",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="TestEvent.java",
                    titos=[],
                    leaves=[("TestSource", 0)],
                    caller_port="result",
                    callee_port="producer:1234:formal(2)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )

    def testNormalizedPath(self) -> None:
        self.assertParsed(
            """
            {
              "method": "LClass;.indirect_sink:(LData;LData;)V",
              "sinks": [
                {
                  "callee": "Lcom/facebook/Sink$4;.sink:(LData;)V",
                  "callee_port": "Argument(1)",
                  "call_position": {
                    "path": "unknown",
                    "line": 2,
                    "start": 3,
                    "end": 4
                  },
                  "distance": 1,
                  "kind": "TestSink",
                  "origins": ["Lcom/facebook/Sink$4;.sink:(LData;)V"],
                  "caller_port": "Argument(2)"
                }
              ],
              "position": {
                "line": 1,
                "path": "unknown"
              }
            }
            """,
            [
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="LClass;.indirect_sink:(LData;LData;)V",
                    callee="Lcom/facebook/Sink$4;.sink:(LData;)V",
                    callee_location=SourceLocation(
                        line_no=2,
                        begin_column=4,
                        end_column=5,
                    ),
                    filename="Class",
                    titos=[],
                    leaves=[("TestSink", 1)],
                    caller_port="argument(2)",
                    callee_port="argument(1)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )
