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

    def testModelPreconditions(self) -> None:
        # Leaf case.
        self.assertParsed(
            """
            {
              "method": "LSink;.sink:(LData;)V",
              "sinks": [
                {
                  "caller_port": "Argument(1)",
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
                  "caller_port": "Argument(2)",
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
                  "caller_port": "Argument(1).x.y",
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
                  "caller_port": "Argument(2)",
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
                  "caller_port": "Argument(2)",
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
                  "caller_port": "Argument(1)",
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
                  "caller_port": "Argument(1)",
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

    # TODO(T91357916): Add test and support for field_callee

    def testModelWithConnectionPointSink(self) -> None:
        self.assertParsed(
            """
            {
              "method": {
                "name": "Lcom/facebook/graphql/calls/SomeMutation;.setSomeField:(LData;)V"
              },
              "sinks": [
                {
                  "caller_port": "Argument(1)",
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
                  "caller_port": "Argument(1)",
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
                  "caller_port": "Argument(1)",
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
                  "caller_port": "Argument(2)",
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
