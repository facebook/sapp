# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import io
import unittest
from typing import Any, Dict, Iterable

from ...analysis_output import AnalysisOutput, Metadata
from ..base_parser import ParseType
from ..mariana_trench_parser import Parser


class TestParser(unittest.TestCase):
    def assertParsed(self, output: str, expected: Iterable[Dict[str, Any]]) -> None:
        output = "".join(output.split("\n"))  # Flatten json-line.
        parser = Parser()
        # pyre-fixme[35]: Target cannot be annotated.
        output: AnalysisOutput = AnalysisOutput(
            directory="/output/directory",
            filename_specs=["models.json"],
            file_handle=io.StringIO(output),
            metadata=Metadata(
                analysis_root="/analysis/root",
                rules={1: {"name": "TestRule", "description": "Test Rule Description"}},
            ),
        )
        self.assertEqual(
            sorted(parser.parse(output), key=lambda entry: entry["callable"]),
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
                {
                    "type": ParseType.ISSUE,
                    "code": 1,
                    "message": "TestRule: Test Rule Description",
                    "callable": "LClass;.flow:()V",
                    "handle": "LClass;.flow:()V:8|12|13:1:f75a532726260b3b",
                    "filename": "Flow.java",
                    "callable_line": 2,
                    "line": 10,
                    "start": 12,
                    "end": 13,
                    "preconditions": [
                        {
                            "callee": "LSink;.sink:(LData;)V",
                            "port": "argument(1)",
                            "location": {
                                "line": 10,
                                "start": 12,
                                "end": 13,
                                "filename": "Flow.java",
                            },
                            "leaves": [("TestSink", 2)],
                            "titos": [{"line": 13, "start": 15, "end": 16}],
                            "features": [
                                {"": "always-via-parameter-field"},
                                {"": "via-parameter-field"},
                            ],
                            "type_interval": {},
                        }
                    ],
                    "postconditions": [
                        {
                            "callee": "LSource;.source:()LData;",
                            "port": "result",
                            "location": {
                                "line": 20,
                                "start": 22,
                                "end": 23,
                                "filename": "Flow.java",
                            },
                            "leaves": [("TestSource", 3)],
                            "titos": [
                                {"line": 23, "start": 25, "end": 26},
                                {"line": 26, "start": 28, "end": 29},
                            ],
                            "features": [],
                            "type_interval": {},
                        }
                    ],
                    "initial_sources": {("LSource;.source:(LData;)V", "TestSource", 3)},
                    "final_sinks": {("LSink;.sink:(LData;)V", "TestSink", 2)},
                    "features": [
                        {"": "always-via-parameter-field"},
                        {"": "via-obscure"},
                        {"": "via-parameter-field"},
                    ],
                }
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
                {
                    "type": ParseType.ISSUE,
                    "code": 1,
                    "message": "TestRule: Test Rule Description",
                    "callable": "LClass;.flow:()V",
                    "handle": "LClass;.flow:()V:8|12|13:1:f75a532726260b3b",
                    "filename": "Flow.java",
                    "callable_line": 2,
                    "line": 10,
                    "start": 12,
                    "end": 13,
                    "preconditions": [
                        {
                            "callee": "LSink;.sink:(LData;)V",
                            "port": "argument(1)",
                            "location": {
                                "line": 10,
                                "start": 12,
                                "end": 13,
                                "filename": "Flow.java",
                            },
                            "leaves": [("TestSink", 2)],
                            "titos": [{"line": 13, "start": 15, "end": 16}],
                            "features": [],
                            "type_interval": {},
                        },
                        {
                            "callee": "LSink;.sink:(LData;)V",
                            "port": "argument(1)",
                            "location": {
                                "line": 20,
                                "start": 22,
                                "end": 23,
                                "filename": "Flow.java",
                            },
                            "leaves": [("TestSink", 3)],
                            "titos": [],
                            "features": [],
                            "type_interval": {},
                        },
                    ],
                    "postconditions": [
                        {
                            "callee": "LSource;.source:()LData;",
                            "port": "result",
                            "location": {
                                "line": 30,
                                "start": 32,
                                "end": 33,
                                "filename": "Flow.java",
                            },
                            "leaves": [("TestSource", 3)],
                            "titos": [{"line": 33, "start": 35, "end": 36}],
                            "features": [],
                            "type_interval": {},
                        }
                    ],
                    "initial_sources": {("LSource;.source:(LData;)V", "TestSource", 3)},
                    "final_sinks": {
                        ("LSink;.sink:(LData;)V", "TestSink", 2),
                        ("LSink;.other_sink:(LData;)V", "TestSink", 3),
                    },
                    "features": [{"": "via-obscure"}, {"": "via-parameter-field"}],
                }
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
                {
                    "type": ParseType.POSTCONDITION,
                    "callable": "LSource;.source:()V",
                    "caller": "LSource;.source:()V",
                    "callee": "leaf",
                    "callee_location": {
                        "line": 1,
                        "start": 1,
                        "end": 1,
                        "filename": "Source.java",
                    },
                    "filename": "Source.java",
                    "titos": [],
                    "sources": [("TestSource", 0)],
                    "caller_port": "result",
                    "callee_port": "source",
                    "type_interval": {},
                    "features": [],
                }
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
                {
                    "type": ParseType.POSTCONDITION,
                    "callable": "LClass;.indirect_source:()V",
                    "caller": "LClass;.indirect_source:()V",
                    "callee": "LSource;.source:()LData;",
                    "callee_location": {
                        "line": 10,
                        "start": 12,
                        "end": 13,
                        "filename": "Class.java",
                    },
                    "filename": "Class.java",
                    "titos": [
                        {"line": 13, "start": 15, "end": 16},
                        {"line": 16, "start": 18, "end": 19},
                    ],
                    "sources": [("TestSource", 1)],
                    "caller_port": "result",
                    "callee_port": "result",
                    "type_interval": {},
                    "features": [],
                }
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
                {
                    "type": ParseType.POSTCONDITION,
                    "callable": "LSource;.source:()V",
                    "caller": "LSource;.source:()V",
                    "callee": "leaf",
                    "callee_location": {
                        "line": 1,
                        "start": 1,
                        "end": 1,
                        "filename": "Source.java",
                    },
                    "filename": "Source.java",
                    "titos": [],
                    "sources": [("TestSource", 0)],
                    "caller_port": "result.x.y",
                    "callee_port": "source",
                    "type_interval": {},
                    "features": [{"": "via-source"}],
                }
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
                {
                    "type": ParseType.POSTCONDITION,
                    "callable": "LSource;.source:()V",
                    "caller": "LSource;.source:()V",
                    "callee": "leaf",
                    "callee_location": {
                        "line": 2,
                        "start": 4,
                        "end": 5,
                        "filename": "Source.java",
                    },
                    "filename": "Source.java",
                    "titos": [],
                    "sources": [("TestSource", 0)],
                    "caller_port": "result",
                    "callee_port": "source",
                    "type_interval": {},
                    "features": [],
                }
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
                {
                    "type": ParseType.PRECONDITION,
                    "callable": "LSink;.sink:(LData;)V",
                    "caller": "LSink;.sink:(LData;)V",
                    "callee": "leaf",
                    "callee_location": {
                        "line": 1,
                        "start": 1,
                        "end": 1,
                        "filename": "Sink.java",
                    },
                    "filename": "Sink.java",
                    "titos": [],
                    "sinks": [("TestSink", 0)],
                    "caller_port": "argument(1)",
                    "callee_port": "sink",
                    "type_interval": {},
                    "features": [],
                }
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
                {
                    "type": ParseType.PRECONDITION,
                    "callable": "LClass;.indirect_sink:(LData;LData;)V",
                    "caller": "LClass;.indirect_sink:(LData;LData;)V",
                    "callee": "LSink;.sink:(LData;)V",
                    "callee_location": {
                        "line": 10,
                        "start": 12,
                        "end": 13,
                        "filename": "Class.java",
                    },
                    "filename": "Class.java",
                    "titos": [
                        {"line": 13, "start": 15, "end": 16},
                        {"line": 16, "start": 18, "end": 19},
                    ],
                    "sinks": [("TestSink", 1)],
                    "caller_port": "argument(2)",
                    "callee_port": "argument(1)",
                    "type_interval": {},
                    "features": [],
                }
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
                {
                    "type": ParseType.PRECONDITION,
                    "callable": "LSink;.sink:(LData;)V",
                    "caller": "LSink;.sink:(LData;)V",
                    "callee": "leaf",
                    "callee_location": {
                        "line": 1,
                        "start": 1,
                        "end": 1,
                        "filename": "Sink.java",
                    },
                    "filename": "Sink.java",
                    "titos": [],
                    "sinks": [("TestSink", 0)],
                    "caller_port": "argument(1).x.y",
                    "callee_port": "sink",
                    "type_interval": {},
                    "features": [],
                }
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
                {
                    "type": ParseType.PRECONDITION,
                    "callable": "LSink;.sink:(LData;)V",
                    "caller": "LSink;.sink:(LData;)V",
                    "callee": "leaf",
                    "callee_location": {
                        "line": 2,
                        "start": 4,
                        "end": 5,
                        "filename": "Sink.java",
                    },
                    "filename": "Sink.java",
                    "titos": [],
                    "sinks": [("TestSink", 0)],
                    "caller_port": "argument(2)",
                    "callee_port": "sink",
                    "type_interval": {},
                    "features": [{"": "via-sink"}],
                }
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
                {
                    "type": ParseType.PRECONDITION,
                    "callable": "LSink;.sink:(LData;)V[0: LAnonymous$0;, 1: LAnonymous$1;]",
                    "caller": "LSink;.sink:(LData;)V[0: LAnonymous$0;, 1: LAnonymous$1;]",
                    "callee": "leaf",
                    "callee_location": {
                        "line": 1,
                        "start": 1,
                        "end": 1,
                        "filename": "Sink.java",
                    },
                    "filename": "Sink.java",
                    "titos": [],
                    "sinks": [("TestSink", 0)],
                    "caller_port": "argument(1)",
                    "callee_port": "sink",
                    "type_interval": {},
                    "features": [],
                }
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
                  "callee_port": "Anchor"
                }
              ],
              "position": {
                "line": 1,
                "path": "SomeMutation.java"
              }
            }
            """,
            [
                {
                    "type": ParseType.PRECONDITION,
                    "callable": "Lcom/facebook/graphql/calls/SomeMutation;.setSomeField:(LData;)V",
                    "caller": "Lcom/facebook/graphql/calls/SomeMutation;.setSomeField:(LData;)V",
                    "callee": "SomeMutation:some_field",
                    "callee_location": {
                        "line": 1,
                        "start": 1,
                        "end": 1,
                        "filename": "SomeMutation.java",
                    },
                    "filename": "SomeMutation.java",
                    "titos": [],
                    "sinks": [("TestSink", 0)],
                    "caller_port": "argument(1)",
                    "callee_port": "anchor:argument(1)",
                    "type_interval": {},
                    "features": [],
                }
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
                  "callee_port": "Anchor"
                }
              ],
              "position": {
                "line": 1,
                "path": "TestEvent.java"
              }
            }
            """,
            [
                {
                    "type": ParseType.POSTCONDITION,
                    "callable": "Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V",
                    "caller": "Lcom/facebook/analytics/structuredlogger/events/TestEvent;.setFieldA:(I)V",
                    "callee": "TestEvent:field_a",
                    "callee_location": {
                        "line": 1,
                        "start": 1,
                        "end": 1,
                        "filename": "TestEvent.java",
                    },
                    "filename": "TestEvent.java",
                    "titos": [],
                    "sources": [("TestSource", 0)],
                    "caller_port": "result",
                    "callee_port": "anchor:result",
                    "type_interval": {},
                    "features": [],
                }
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
                {
                    "type": ParseType.PRECONDITION,
                    "callable": "LClass;.indirect_sink:(LData;LData;)V",
                    "caller": "LClass;.indirect_sink:(LData;LData;)V",
                    "callee": "Lcom/facebook/Sink$4;.sink:(LData;)V",
                    "callee_location": {
                        "line": 2,
                        "start": 4,
                        "end": 5,
                        "filename": "com/facebook/Sink",
                    },
                    "filename": "Class",
                    "titos": [],
                    "sinks": [("TestSink", 1)],
                    "caller_port": "argument(2)",
                    "callee_port": "argument(1)",
                    "type_interval": {},
                    "features": [],
                }
            ],
        )
