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
from ..mariana_trench_parser_v2 import Parser


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
                analysis_tool_version="0.2",
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
                      "call": {
                        "resolves_to": "LSink;.sink:(LData;)V",
                        "port": "Argument(1)",
                        "position": {
                          "path": "Flow.java",
                          "line": 10,
                          "start": 11,
                          "end": 12
                        }
                      },
                      "kinds": [
                        {
                          "distance": 2,
                          "always_features": ["via-parameter-field"],
                          "kind": "TestSink",
                          "origins": ["LSink;.sink:(LData;)V"],
                          "local_positions": [{"line": 13, "start": 14, "end": 15}],
                          "local_features": { "always_features": ["via-parameter-field"] }
                        }
                      ]
                    }
                  ],
                  "sources": [
                    {
                      "call": {
                        "resolves_to": "LSource;.source:()LData;",
                        "port": "Return",
                        "position": {
                          "path": "Flow.java",
                          "line": 20,
                          "start": 21,
                          "end": 22
                        }
                      },
                      "kinds": [
                        {
                          "distance": 3,
                          "may_features": ["via-obscure"],
                          "kind": "TestSource",
                          "origins": ["LSource;.source:(LData;)V"],
                          "local_positions": [
                            {"line": 23, "start": 24, "end": 25},
                            {"line": 26, "start": 27, "end": 28}
                          ]
                        }
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
                      "call": {
                        "resolves_to": "LSink;.sink:(LData;)V",
                        "port": "Argument(1)",
                        "position": {
                          "path": "Flow.java",
                          "line": 10,
                          "start": 11,
                          "end": 12
                        }
                      },
                      "kinds": [
                        {
                          "distance": 2,
                          "always_features": ["via-parameter-field"],
                          "kind": "TestSink",
                          "origins": ["LSink;.sink:(LData;)V"],
                          "local_positions": [{"line": 13, "start": 14, "end": 15}]
                        }
                      ]
                    },
                    {
                      "call": {
                        "resolves_to": "LSink;.sink:(LData;)V",
                        "port": "Argument(1)",
                        "position": {
                          "path": "Flow.java",
                          "line": 20,
                          "start": 21,
                          "end": 22
                        }
                      },
                      "kinds": [
                        {
                          "distance": 3,
                          "always_features": ["via-obscure"],
                          "kind": "TestSink",
                          "origins": ["LSink;.other_sink:(LData;)V"]
                        }
                      ]
                    }
                  ],
                  "sources": [
                    {
                      "call": {
                        "resolves_to": "LSource;.source:()LData;",
                        "port": "Return",
                        "position": {
                          "path": "Flow.java",
                          "line": 30,
                          "start": 31,
                          "end": 32
                        }
                      },
                      "kinds": [
                        {
                          "distance": 3,
                          "kind": "TestSource",
                          "origins": ["LSource;.source:(LData;)V"],
                          "local_positions": [{"line": 33, "start": 34, "end": 35}],
                          "local_features": {"always_features": ["via-obscure"]}
                        }
                      ]
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
                            features=[ParseTraceFeature("always-via-obscure", [])],
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
                      "call": {
                        "resolves_to": "LSink;.sink:(LData;)V",
                        "port": "Argument(1)",
                        "position": {
                          "path": "Flow.java",
                          "line": 10,
                          "start": 11,
                          "end": 12
                        }
                      },
                      "kinds": [
                        {
                          "distance": 2,
                          "always_features": ["via-parameter-field"],
                          "kind": "TestSink",
                          "origins": ["LSink;.sink:(LData;)V"],
                          "local_positions": [{"line": 13, "start": 14, "end": 15}]
                        }
                      ]
                    }
                  ],
                  "sources": [
                    {
                      "kinds": [
                        {
                          "distance": 0,
                          "kind": "TestSource",
                          "field_origins": ["LSource;.sourceField:LData;"],
                          "local_positions": [{"line": 33, "start": 34, "end": 35}]
                        }
                      ]
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

        # Multiple callees, local_positions/features and kinds
        # (and origins within kinds)
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
                      "call": {
                        "resolves_to": "LSink;.sink:(LData;)V",
                        "port": "Argument(1)",
                        "position": {
                          "path": "Flow.java",
                          "line": 10,
                          "start": 11,
                          "end": 12
                        }
                      },
                      "kinds": [
                        {
                          "distance": 2,
                          "always_features": ["via-parameter-field"],
                          "kind": "TestSink",
                          "origins": ["LSink;.sink:(LData;)V"],
                          "local_positions": [{"line": 13, "start": 14, "end": 15}]
                        }
                      ]
                    },
                    {
                      "call": {
                        "resolves_to": "LSink;.sink2:(LData;)V",
                        "port": "Argument(1)",
                        "position": {
                          "path": "Flow.java",
                          "line": 11,
                          "start": 11,
                          "end": 12
                        }
                      },
                      "kinds": [
                        {
                          "distance": 3,
                          "kind": "TestSink",
                          "origins": ["LSink;.sink:(LData;)V"],
                          "local_positions": [{"line": 14, "start": 14, "end": 15}]
                        },
                        {
                          "distance": 1,
                          "kind": "TestSink2",
                          "origins": ["LSink;.sink3:(LData;)V"],
                          "local_positions": [{"line": 14, "start": 14, "end": 15}]
                        }
                      ]
                    }
                  ],
                  "sources": [
                    {
                      "call": {
                        "resolves_to": "LSource;.source:()LData;",
                        "port": "Return",
                        "position": {
                          "path": "Flow.java",
                          "line": 30,
                          "start": 31,
                          "end": 32
                        }
                      },
                      "kinds": [
                        {
                          "distance": 3,
                          "kind": "TestSource",
                          "origins": ["LSource;.source:(LData;)V"],
                          "local_positions": [{"line": 33, "start": 34, "end": 35}],
                          "local_features": {"always_features": ["via-obscure"]}
                        }
                      ]
                    },
                    {
                      "call": {
                        "resolves_to": "LSource;.source2:()LData;",
                        "port": "Return",
                        "position": {
                          "path": "Flow.java",
                          "line": 31,
                          "start": 31,
                          "end": 32
                        }
                      },
                      "kinds": [
                        {
                          "distance": 4,
                          "kind": "TestSource",
                          "origins": ["LSource;.source:(LData;)V"]
                        },
                        {
                          "distance": 5,
                          "kind": "TestSource2",
                          "origins": ["LSource;.source3:(LData;)V"]
                        }
                      ]
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
                            callee="LSink;.sink2:(LData;)V",
                            port="argument(1)",
                            location=SourceLocation(
                                line_no=11,
                                begin_column=12,
                                end_column=13,
                            ),
                            leaves=[("TestSink", 3), ("TestSink2", 1)],
                            titos=[
                                SourceLocation(
                                    line_no=14, begin_column=15, end_column=16
                                )
                            ],
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
                            features=[ParseTraceFeature("always-via-obscure", [])],
                            type_interval=None,
                            annotations=[],
                        ),
                        ParseIssueConditionTuple(
                            callee="LSource;.source2:()LData;",
                            port="result",
                            location=SourceLocation(
                                line_no=31,
                                begin_column=32,
                                end_column=33,
                            ),
                            leaves=[("TestSource", 4), ("TestSource2", 5)],
                            titos=[],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        ),
                    ],
                    initial_sources={
                        ("LSource;.source:(LData;)V", "TestSource", 3),
                        ("LSource;.source:(LData;)V", "TestSource", 4),
                        ("LSource;.source3:(LData;)V", "TestSource2", 5),
                    },
                    final_sinks={
                        ("LSink;.sink:(LData;)V", "TestSink", 2),
                        ("LSink;.sink:(LData;)V", "TestSink", 3),
                        ("LSink;.sink3:(LData;)V", "TestSink2", 1),
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
                  "port": "Return",
                  "taint": [
                    {
                      "kinds": [
                        {
                          "always_features": ["via-parameter-field"],
                          "kind": "TestSource",
                          "origins": ["LSource;.source:()V"],
                          "local_features": {
                            "always_features": ["via-obscure"],
                            "may_features": ["via-taint-in-taint-out"]
                          }
                        }
                      ]
                    }
                  ]
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
                    features=[
                        ParseTraceFeature("always-via-obscure", []),
                        ParseTraceFeature("via-taint-in-taint-out", []),
                    ],
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
                  "port": "Return",
                  "taint": [
                    {
                      "call": {
                        "resolves_to": "LSource;.source:()LData;",
                        "port": "Return",
                        "position": {
                          "path": "Class.java",
                          "line": 10,
                          "start": 11,
                          "end": 12
                        }
                      },
                      "kinds": [
                        {
                          "distance": 1,
                          "kind": "TestSource",
                          "origins": ["LSource;.source:()V"],
                          "local_positions": [
                            {"line": 13, "start": 14, "end": 15},
                            {"line": 16, "start": 17, "end": 18}
                          ]
                        }
                      ]
                    }
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
                  "port": "Return.x.y",
                  "taint": [
                    {
                      "kinds": [
                        {
                          "kind": "TestSource",
                          "origins": ["LSource;.source:()V"],
                          "local_features": {
                            "may_features": ["via-source"]
                          }
                        }
                      ]
                    }
                  ]
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

        # Test with a parameter source (contains callee position but not callee/port).
        self.assertParsed(
            """
            {
              "method": "LSource;.source:()V",
              "generations": [
                {
                  "port": "Return",
                  "taint": [
                    {
                      "call": {
                        "position": {
                          "path": "Source.java",
                          "line": 2,
                          "start": 3,
                          "end": 4
                        }
                      },
                      "kinds": [
                        {
                          "kind": "TestSource",
                          "origins": ["LSource;.source:()V"]
                        }
                      ]
                    }
                  ]
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

        # Test multiple caller ports, callees and kinds (leaves)
        self.assertParsed(
            """
            {
              "method": "LSource;.source:(I)V",
              "generations": [
                {
                  "port": "Return",
                  "taint": [
                    {
                      "kinds": [
                        {
                          "kind": "TestSource"
                        },
                        {
                          "kind": "TestSource2"
                        }
                      ]
                    },
                    {
                      "call": {
                        "resolves_to": "LSource;.source1:()LData;",
                        "port": "Return",
                        "position": {
                          "path": "Class.java",
                          "line": 10,
                          "start": 11,
                          "end": 12
                        }
                      },
                      "kinds": [
                        {
                          "kind": "TestSource",
                          "distance": 1
                        },
                        {
                          "kind": "TestSource2",
                          "distance": 2
                        }
                      ]
                    }
                  ]
                },
                {
                  "port": "Argument(1)",
                  "taint": [
                    {
                      "call": {
                        "resolves_to": "LSource;.source2:()LData;",
                        "port": "Return",
                        "position": {
                          "path": "Class.java",
                          "line": 10,
                          "start": 11,
                          "end": 12
                        }
                      },
                      "kinds": [
                        {
                          "kind": "TestSource",
                          "distance": 3
                        }
                      ]
                    }
                  ]
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
                    caller="LSource;.source:(I)V",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="Source.java",
                    titos=[],
                    leaves=[("TestSource", 0), ("TestSource2", 0)],
                    caller_port="result",
                    callee_port="source",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="LSource;.source:(I)V",
                    callee="LSource;.source1:()LData;",
                    callee_location=SourceLocation(
                        line_no=10,
                        begin_column=12,
                        end_column=13,
                    ),
                    filename="Source.java",
                    titos=[],
                    leaves=[("TestSource", 1), ("TestSource2", 2)],
                    caller_port="result",
                    callee_port="result",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller="LSource;.source:(I)V",
                    callee="LSource;.source2:()LData;",
                    callee_location=SourceLocation(
                        line_no=10,
                        begin_column=12,
                        end_column=13,
                    ),
                    filename="Source.java",
                    titos=[],
                    leaves=[("TestSource", 3)],
                    caller_port="argument(1)",
                    callee_port="result",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
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
                  "port": "Argument(1)",
                  "taint": [
                    {
                      "kinds": [
                        {
                          "kind": "TestSink",
                          "origins": ["LSink;.sink:(LData;)V"],
                          "local_features": {"always_features": ["via-taint-in-taint-out"]},
                          "may_features": ["via-obscure"]
                        }
                      ]
                    }
                  ]
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
                    features=[ParseTraceFeature("always-via-taint-in-taint-out", [])],
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
                  "port": "Argument(2)",
                  "taint": [
                    {
                      "call": {
                        "resolves_to": "LSink;.sink:(LData;)V",
                        "port": "Argument(1)",
                        "position": {
                          "path": "Class.java",
                          "line": 10,
                          "start": 11,
                          "end": 12
                        }
                      },
                      "kinds": [
                        {
                          "distance": 1,
                          "kind": "TestSink",
                          "origins": ["LSink;.sink:(LData;)V"],
                          "local_positions": [
                            {"line": 13, "start": 14, "end": 15},
                            {"line": 16, "start": 17, "end": 18}
                          ]
                        }
                      ]
                    }
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
                  "port": "Argument(1).x.y",
                  "taint": [
                    {
                      "kinds": [
                        {
                          "kind": "TestSink",
                          "origins": ["LSink;.sink:(LData;)V"]
                        }
                      ]
                    }
                  ]
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

        # Test with a return sink (has callee position only).
        self.assertParsed(
            """
            {
              "method": "LSink;.sink:(LData;)V",
              "sinks": [
                {
                  "port": "Argument(2)",
                  "taint": [
                    {
                      "call": {
                        "position": {
                          "path": "Sink.java",
                          "line": 2,
                          "start": 3,
                          "end": 4
                        }
                      },
                      "kinds": [
                        {
                          "kind": "TestSink",
                          "origins": ["LSink;.sink:(LData;)V"],
                          "local_features": {
                            "may_features": ["via-sink"]
                          }
                        }
                      ]
                    }
                  ]
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

        # Test multiple caller ports, callees and kinds (leaves)
        self.assertParsed(
            """
            {
              "method": "LSink;.sink:(LData;LData;)V",
              "sinks": [
                {
                  "port": "Argument(2)",
                  "taint": [
                    {
                      "kinds": [
                        {
                          "kind": "TestSink"
                        },
                        {
                          "kind": "TestSink2"
                        }
                      ]
                    },
                    {
                      "call": {
                        "resolves_to": "LSink;.sink2:(LData;)V",
                        "port": "Argument(1)",
                        "position": {
                          "path": "Class.java",
                          "line": 10,
                          "start": 11,
                          "end": 12
                        }
                      },
                      "kinds": [
                        {
                          "kind": "TestSink",
                          "distance": 1
                        },
                        {
                          "kind": "TestSink2",
                          "distance": 2
                        }
                      ]
                    }
                  ]
                },
                {
                  "port": "Argument(1)",
                  "taint": [
                    {
                      "call": {
                        "resolves_to": "LSink;.sink3:(LData;)V",
                        "port": "Argument(0)",
                        "position": {
                          "path": "Class.java",
                          "line": 10,
                          "start": 5,
                          "end": 7
                        }
                      },
                      "kinds": [
                        {
                          "kind": "TestSink",
                          "distance": 3
                        }
                      ]
                    }
                  ]
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
                    caller="LSink;.sink:(LData;LData;)V",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="Sink.java",
                    titos=[],
                    leaves=[("TestSink", 0), ("TestSink2", 0)],
                    caller_port="argument(2)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="LSink;.sink:(LData;LData;)V",
                    callee="LSink;.sink2:(LData;)V",
                    callee_location=SourceLocation(
                        line_no=10,
                        begin_column=12,
                        end_column=13,
                    ),
                    filename="Sink.java",
                    titos=[],
                    leaves=[("TestSink", 1), ("TestSink2", 2)],
                    caller_port="argument(2)",
                    callee_port="argument(1)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="LSink;.sink:(LData;LData;)V",
                    callee="LSink;.sink3:(LData;)V",
                    callee_location=SourceLocation(
                        line_no=10,
                        begin_column=6,
                        end_column=8,
                    ),
                    filename="Sink.java",
                    titos=[],
                    leaves=[("TestSink", 3)],
                    caller_port="argument(1)",
                    callee_port="argument(0)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
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
                  "port": "Argument(1)",
                  "taint": [
                    {
                      "kinds": [
                        {
                          "kind": "TestSink",
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
                          }]
                        }
                      ]
                    }
                  ]
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

    def testModelWithConnectionPointSource(self) -> None:
        self.assertParsed(
            """
            {
              "method": {
                "name": "Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V"
              },
              "generations": [
                {
                  "port": "Return",
                  "taint": [
                    {
                      "call": {
                        "port": "Anchor.Return"
                      },
                      "kinds": [
                        {
                          "kind": "TestSource",
                          "origins": [
                            "Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V"
                          ],
                          "canonical_names": [ { "instantiated": "TestEvent:field_a" } ]
                        }
                      ]
                    }
                  ]
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
                  "port": "Return",
                  "taint": [
                    {
                      "call": {
                        "port": "Producer.1234.Argument(2)"
                      },
                      "kinds": [
                        {
                          "kind": "TestSource",
                          "origins": [
                           "Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V"
                          ],
                          "canonical_names": [ { "instantiated": "LClass;.method:(I)V" }]
                        }
                      ]
                    }
                  ]
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

    def testModelWithConnectionPointSink(self) -> None:
        self.assertParsed(
            """
            {
              "method": {
                "name": "Lcom/facebook/graphql/calls/SomeMutation;.setSomeField:(LData;)V"
              },
              "sinks": [
                {
                  "port": "Argument(1)",
                  "taint": [
                    {
                      "call": {
                        "port": "Anchor.Argument(0)"
                      },
                      "kinds": [
                        {
                          "kind": "TestSink",
                          "canonical_names": [ { "instantiated": "SomeMutation:some_field" } ]
                        }
                      ]
                    }
                  ]
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
                  "port": "Argument(1)",
                  "taint": [
                    {
                      "call": {
                        "port": "Anchor.Argument(-1)"
                      },
                      "kinds": [
                        {
                          "kind": "TestSink",
                          "canonical_names": [ { "instantiated": "SomeMutation:some_field" } ]
                        }
                      ]
                    }
                  ]
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
                  "port": "Argument(1)",
                  "taint": [
                    {
                      "call": {
                        "port": "Anchor"
                      },
                      "kinds": [
                        {
                          "kind": "TestSink",
                          "canonical_names": [ { "template": "%programmatic_leaf_name%__%source_via_type_of%" } ]
                        }
                      ]
                    }
                  ]
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

    def testNormalizedPath(self) -> None:
        self.assertParsed(
            """
            {
              "method": "LClass;.indirect_sink:(LData;LData;)V",
              "sinks": [
                {
                  "port": "Argument(2)",
                  "taint": [
                    {
                      "call": {
                        "resolves_to": "Lcom/facebook/Sink$4;.sink:(LData;)V",
                        "port": "Argument(1)",
                        "position": {
                          "path": "unknown",
                          "line": 2,
                          "start": 3,
                          "end": 4
                        }
                      },
                      "kinds": [
                        {
                          "distance": 1,
                          "kind": "TestSink",
                          "origins": ["Lcom/facebook/Sink$4;.sink:(LData;)V"]
                        }
                      ]
                    }
                  ]
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

    def testFieldCallee(self) -> None:
        # Model contains field callee only
        self.assertParsed(
            """
            {
              "method": "LClass;.indirect_sink:(LData;LData;)V",
              "sinks": [
                {
                  "port": "Argument(2)",
                  "taint": [
                    {
                      "kinds": [
                        {
                          "field_callee": "Lcom/facebook/SinkClass;.field:Ljava/lang/Object;",
                          "field_origins": ["Lcom/facebook/SinkClass;.field:Ljava/lang/Object;"],
                          "kind": "TestSink"
                        }
                      ]
                    }
                  ]
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
                    type=ParseType.PRECONDITION,
                    caller="LClass;.indirect_sink:(LData;LData;)V",
                    callee="Lcom/facebook/SinkClass;.field:Ljava/lang/Object;",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="TestEvent.java",
                    titos=[],
                    leaves=[("TestSink", 0)],
                    caller_port="argument(2)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                )
            ],
        )

        # Model contains field callees, non-field leaves, and other callees
        self.assertParsed(
            """
            {
              "method": "LClass;.indirect_sink:(LData;LData;)V",
              "sinks": [
                {
                  "port": "Argument(2)",
                  "taint": [
                    {
                      "kinds": [
                        {
                          "field_callee": "Lcom/facebook/SinkClass;.field:Ljava/lang/Object;",
                          "field_origins": ["Lcom/facebook/SinkClass;.field:Ljava/lang/Object;"],
                          "kind": "TestSink"
                        },
                        {
                          "field_callee": "Lcom/facebook/SinkClass;.field2:Ljava/lang/Object;",
                          "field_origins": ["Lcom/facebook/SinkClass;.field2:Ljava/lang/Object;"],
                          "kind": "TestSink2"
                        },
                        {
                          "origins": ["LSink;.sink:(LData;)V"],
                          "kind": "TestSink2"
                        }
                      ]
                    },
                    {
                      "call": {
                        "resolves_to": "LSink;.sink2:(LData;)V",
                        "port": "Argument(1)",
                        "position": {
                          "path": "TestEvent.java",
                          "line": 10,
                          "start": 11,
                          "end": 12
                        }
                      },
                      "kinds": [
                        {
                          "origins": ["LSink;.sink:(LData;)V"],
                          "field_origins": ["Lcom/facebook/SinkClass;.field2:Ljava/lang/Object;"],
                          "kind": "TestSink2",
                          "distance": 1
                        }
                      ]
                    }
                  ]
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
                    type=ParseType.PRECONDITION,
                    caller="LClass;.indirect_sink:(LData;LData;)V",
                    callee="Lcom/facebook/SinkClass;.field:Ljava/lang/Object;",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="TestEvent.java",
                    titos=[],
                    leaves=[("TestSink", 0)],
                    caller_port="argument(2)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="LClass;.indirect_sink:(LData;LData;)V",
                    callee="Lcom/facebook/SinkClass;.field2:Ljava/lang/Object;",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="TestEvent.java",
                    titos=[],
                    leaves=[("TestSink2", 0)],
                    caller_port="argument(2)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="LClass;.indirect_sink:(LData;LData;)V",
                    callee="leaf",
                    callee_location=SourceLocation(
                        line_no=1,
                        begin_column=1,
                        end_column=1,
                    ),
                    filename="TestEvent.java",
                    titos=[],
                    leaves=[("TestSink2", 0)],
                    caller_port="argument(2)",
                    callee_port="sink",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
                ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller="LClass;.indirect_sink:(LData;LData;)V",
                    callee="LSink;.sink2:(LData;)V",
                    callee_location=SourceLocation(
                        line_no=10,
                        begin_column=12,
                        end_column=13,
                    ),
                    filename="TestEvent.java",
                    titos=[],
                    leaves=[("TestSink2", 1)],
                    caller_port="argument(2)",
                    callee_port="argument(1)",
                    type_interval=None,
                    features=[],
                    annotations=[],
                ),
            ],
        )
