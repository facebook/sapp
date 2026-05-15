# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import io
import unittest

from ...analysis_output import AnalysisOutput, Metadata, Rule
from .. import ParseConditionTuple, ParseIssueTuple, SourceLocation
from ..prophecy_parser import Parser


class TestProphecyParser(unittest.TestCase):
    def _parse(
        self,
        input: str,
        *,
        flatten: bool = True,
    ) -> tuple[
        list[ParseIssueTuple],
        list[ParseConditionTuple],
        list[ParseConditionTuple],
    ]:
        """Parse input NDJSON and return (issues, preconditions, postconditions).

        Args:
            input: NDJSON string. For single-entry tests, multi-line JSON is
                flattened into one line. For multi-entry tests, set flatten=False
                and provide pre-formatted single-line NDJSON.
            flatten: If True, collapse all newlines (for single-entry JSON
                spread across multiple lines). If False, preserve newlines as
                NDJSON record separators.
        """
        if flatten:
            input = "".join(input.split("\n"))  # Flatten json-line.
        parser = Parser()
        analysis_output = AnalysisOutput(
            directory="/output/directory",
            filename_specs=["prophecy-output.json"],
            file_handle=io.StringIO(input),
            metadata=Metadata(
                repo_roots={"/repo"},
                analysis_tool_version="1.0.0",
                rules={
                    9001: Rule(
                        name="Prophecy-RCE",
                        description="Remote Code Execution",
                    ),
                    9003: Rule(
                        name="Prophecy-XSS",
                        description="Cross-Site Scripting",
                    ),
                },
            ),
        )
        issues_and_frames = parser.parse_analysis_output(analysis_output)
        return (
            issues_and_frames.issues,
            list(issues_and_frames.preconditions.all_frames()),
            list(issues_and_frames.postconditions.all_frames()),
        )

    def testEmptyInput(self) -> None:
        issues, pre, post = self._parse("")
        self.assertEqual(issues, [])
        self.assertEqual(pre, [])
        self.assertEqual(post, [])

    def testBasicIssue(self) -> None:
        issues, _pre, _post = self._parse(
            """
            {
              "kind": "issue",
              "code": 9003,
              "callable": "src/handlers/user.ts::handleUserInput",
              "callable_line": 42,
              "filename": "src/handlers/user.ts",
              "position": {"line": 55, "start": 12, "end": 45},
              "description": "Data from [UserInput] may reach [InnerHTML]",
              "traces": [
                {
                  "forward": {
                    "trace_leaf": {
                      "position": {"line": 42, "start": 8, "end": 20}
                    },
                    "kind": "UserInput",
                    "leaves": [{"name": "req.body.name"}],
                    "local_trace": {"positions": []}
                  }
                },
                {
                  "backward": {
                    "trace_leaf": {
                      "position": {"line": 55, "start": 12, "end": 45}
                    },
                    "kind": "InnerHTML",
                    "leaves": [{"name": "document.innerHTML"}],
                    "local_trace": {"positions": []}
                  }
                }
              ],
              "features": [
                "prophecy-severity:high",
                "prophecy-category:xss"
              ]
            }
            """
        )

        self.assertEqual(len(issues), 1)
        issue = issues[0]

        # Core fields
        self.assertEqual(issue.code, 9003)
        self.assertEqual(issue.callable, "src/handlers/user.ts::handleUserInput")
        self.assertEqual(issue.filename, "src/handlers/user.ts")
        self.assertEqual(issue.line, 55)
        self.assertEqual(issue.start, 12)
        self.assertEqual(issue.end, 45)
        self.assertEqual(issue.callable_line, 42)
        self.assertEqual(issue.message, "Data from [UserInput] may reach [InnerHTML]")

        # Handle is computed via compute_master_handle
        self.assertIn("src/handlers/user.ts::handleUserInput", issue.handle)
        self.assertIn("9003", issue.handle)

        # Features
        self.assertIn("prophecy-severity:high", issue.features)
        self.assertIn("prophecy-category:xss", issue.features)

        # Postconditions (source side) — one entry for the source leaf
        postconditions = list(issue.postconditions)
        self.assertEqual(len(postconditions), 1)
        self.assertEqual(postconditions[0].callee, "req.body.name")
        self.assertEqual(postconditions[0].port, "source")
        self.assertEqual(postconditions[0].location, SourceLocation(42, 8, 20))
        self.assertEqual(postconditions[0].leaves, [("UserInput", 0)])

        # Preconditions (sink side) — one entry for the sink leaf
        preconditions = list(issue.preconditions)
        self.assertEqual(len(preconditions), 1)
        self.assertEqual(preconditions[0].callee, "document.innerHTML")
        self.assertEqual(preconditions[0].port, "sink")
        self.assertEqual(preconditions[0].location, SourceLocation(55, 12, 45))
        self.assertEqual(preconditions[0].leaves, [("InnerHTML", 0)])

        # Initial sources and final sinks
        initial_sources = set(issue.initial_sources)
        self.assertIn(("req.body.name", "UserInput", 0), initial_sources)
        final_sinks = set(issue.final_sinks)
        self.assertIn(("document.innerHTML", "InnerHTML", 0), final_sinks)

    def testIssueWithFixInfo(self) -> None:
        issues, _pre, _post = self._parse(
            """
            {
              "kind": "issue",
              "code": 9003,
              "callable": "src/app.ts::render",
              "filename": "src/app.ts",
              "position": {"line": 10, "start": 5, "end": 30},
              "description": "XSS vulnerability",
              "traces": [
                {
                  "forward": {
                    "trace_leaf": {
                      "position": {"line": 5, "start": 1, "end": 10}
                    },
                    "kind": "UserInput",
                    "leaves": [{"name": "input"}],
                    "local_trace": {"positions": []}
                  }
                },
                {
                  "backward": {
                    "trace_leaf": {
                      "position": {"line": 10, "start": 5, "end": 30}
                    },
                    "kind": "InnerHTML",
                    "leaves": [{"name": "el.innerHTML"}],
                    "local_trace": {"positions": []}
                  }
                }
              ],
              "fix_info": {
                "filePath": "src/app.ts",
                "original": "el.innerHTML = data",
                "replacement": "el.textContent = data",
                "applicability": "safe"
              },
              "features": []
            }
            """
        )

        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertIsNotNone(issue.fix_info)
        self.assertEqual(issue.fix_info["filePath"], "src/app.ts")
        self.assertEqual(issue.fix_info["original"], "el.innerHTML = data")
        self.assertEqual(issue.fix_info["replacement"], "el.textContent = data")
        self.assertEqual(issue.fix_info["applicability"], "safe")

    def testIssueWithoutFixInfo(self) -> None:
        issues, _pre, _post = self._parse(
            """
            {
              "kind": "issue",
              "code": 9001,
              "callable": "src/exec.ts::runCommand",
              "filename": "src/exec.ts",
              "position": {"line": 20, "start": 3, "end": 40},
              "description": "RCE vulnerability",
              "traces": [
                {
                  "forward": {
                    "trace_leaf": {
                      "position": {"line": 10, "start": 1, "end": 15}
                    },
                    "kind": "UserInput",
                    "leaves": [{"name": "req.query.cmd"}],
                    "local_trace": {"positions": []}
                  }
                },
                {
                  "backward": {
                    "trace_leaf": {
                      "position": {"line": 20, "start": 3, "end": 40}
                    },
                    "kind": "CommandExec",
                    "leaves": [{"name": "child_process.exec"}],
                    "local_trace": {"positions": []}
                  }
                }
              ],
              "features": ["prophecy-severity:critical"]
            }
            """
        )

        self.assertEqual(len(issues), 1)
        self.assertIsNone(issues[0].fix_info)

    def testPropagationStepsAsFeatures(self) -> None:
        issues, _pre, _post = self._parse(
            """
            {
              "kind": "issue",
              "code": 9003,
              "callable": "src/app.ts::process",
              "filename": "src/app.ts",
              "position": {"line": 30, "start": 5, "end": 25},
              "description": "XSS via assignment chain",
              "traces": [
                {
                  "forward": {
                    "trace_leaf": {
                      "position": {"line": 10, "start": 1, "end": 10}
                    },
                    "kind": "UserInput",
                    "leaves": [{"name": "data"}],
                    "local_trace": {"positions": []}
                  }
                },
                {
                  "backward": {
                    "trace_leaf": {
                      "position": {"line": 30, "start": 5, "end": 25}
                    },
                    "kind": "InnerHTML",
                    "leaves": [{"name": "el.innerHTML"}],
                    "local_trace": {"positions": []}
                  }
                }
              ],
              "features": [],
              "propagation_steps": [
                {
                  "kind": "assignment",
                  "location": {"line": 15, "start": 5, "end": 20},
                  "description": "Assigned to variable x"
                },
                {
                  "kind": "argument",
                  "location": {"line": 25, "start": 10, "end": 30},
                  "description": "Passed to render()"
                }
              ]
            }
            """
        )

        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertIn(
            "prophecy-step-0:assignment: Assigned to variable x",
            issue.features,
        )
        self.assertIn(
            "prophecy-step-1:argument: Passed to render()",
            issue.features,
        )

    def testMultipleIssues(self) -> None:
        issues, _pre, _post = self._parse(
            '{"kind": "issue", "code": 9001, "callable": "a.ts::foo", '
            '"filename": "a.ts", "position": {"line": 1, "start": 1, "end": 10}, '
            '"description": "RCE", "traces": [{"forward": {"trace_leaf": '
            '{"position": {"line": 1, "start": 1, "end": 10}}, "kind": "Src", '
            '"leaves": [{"name": "src"}], "local_trace": {"positions": []}}}, '
            '{"backward": {"trace_leaf": {"position": {"line": 1, "start": 1, '
            '"end": 10}}, "kind": "Snk", "leaves": [{"name": "snk"}], '
            '"local_trace": {"positions": []}}}], "features": []}\n'
            '{"kind": "issue", "code": 9003, "callable": "b.ts::bar", '
            '"filename": "b.ts", "position": {"line": 5, "start": 2, "end": 20}, '
            '"description": "XSS", "traces": [{"forward": {"trace_leaf": '
            '{"position": {"line": 3, "start": 1, "end": 10}}, "kind": "Src2", '
            '"leaves": [{"name": "src2"}], "local_trace": {"positions": []}}}, '
            '{"backward": {"trace_leaf": {"position": {"line": 5, "start": 2, '
            '"end": 20}}, "kind": "Snk2", "leaves": [{"name": "snk2"}], '
            '"local_trace": {"positions": []}}}], "features": []}\n',
            flatten=False,
        )

        self.assertEqual(len(issues), 2)
        codes = {issue.code for issue in issues}
        self.assertEqual(codes, {9001, 9003})

    def testIssueCallTraceAndStandaloneFrames(self) -> None:
        issues, pre, post = self._parse(
            '{"kind": "issue", "code": 9001, "callable": "src/exec.ts::run", '
            '"filename": "src/exec.ts", '
            '"position": {"line": 20, "start": 3, "end": 40}, '
            '"description": "RCE", "traces": [{"forward": {"call": {"position": '
            '{"line": 20, "start": 3, "end": 40}, '
            '"resolves_to": ["prophecy:t:source:root"], '
            '"port": "root"}, "kinds": [{"kind": "UserInput", "trace_len": 2}], '
            '"leaves": [{"name": "req.query.cmd"}], '
            '"local_trace": {"positions": []}}}, '
            '{"backward": {"call": {"position": '
            '{"line": 20, "start": 3, "end": 40}, '
            '"resolves_to": ["prophecy:t:sink:root"], "port": "root"}, '
            '"kinds": [{"kind": "CommandExec", "trace_len": 1}], '
            '"leaves": [{"name": "child_process.exec"}], '
            '"local_trace": {"positions": []}}}], '
            '"features": []}\n'
            '{"type": "postcondition", "caller": "prophecy:t:source:root", '
            '"caller_port": "root", "callee": "req.query.cmd", '
            '"callee_port": "source", '
            '"callee_location": {"line": 10, "start": 1, "end": 15}, '
            '"filename": "src/exec.ts", '
            '"sources": [{"kind": "UserInput", "depth": 0}], '
            '"type_interval": {}, '
            '"features": [{"name": "prophecy-source-kind:UserInput", '
            '"locations": [{"line": 10, "start": 1, "end": 15}]}]}\n'
            '{"type": "precondition", "caller": "prophecy:t:sink:root", '
            '"caller_port": "root", "callee": "child_process.exec", '
            '"callee_port": "sink", '
            '"callee_location": {"line": 20, "start": 3, "end": 40}, '
            '"filename": "src/exec.ts", '
            '"sinks": [{"kind": "CommandExec", "depth": 0}], '
            '"type_interval": {}, "features": []}\n',
            flatten=False,
        )

        self.assertEqual(len(issues), 1)
        issue = issues[0]
        issue_postconditions = list(issue.postconditions)
        issue_preconditions = list(issue.preconditions)
        self.assertEqual(issue_postconditions[0].callee, "prophecy:t:source:root")
        self.assertEqual(issue_postconditions[0].port, "root")
        self.assertEqual(issue_postconditions[0].leaves, [("UserInput", 2)])
        self.assertIn(("req.query.cmd", "UserInput", 2), set(issue.initial_sources))
        self.assertEqual(issue_preconditions[0].callee, "prophecy:t:sink:root")
        self.assertEqual(issue_preconditions[0].port, "root")
        self.assertEqual(issue_preconditions[0].leaves, [("CommandExec", 1)])
        self.assertIn(
            ("child_process.exec", "CommandExec", 1),
            set(issue.final_sinks),
        )

        self.assertEqual(len(post), 1)
        self.assertEqual(post[0].caller, "prophecy:t:source:root")
        self.assertEqual(post[0].caller_port, "root")
        self.assertEqual(post[0].callee, "req.query.cmd")
        self.assertEqual(post[0].callee_port, "source")
        self.assertEqual(post[0].leaves, [("UserInput", 0)])
        self.assertEqual(post[0].features[0].name, "prophecy-source-kind:UserInput")

        self.assertEqual(len(pre), 1)
        self.assertEqual(pre[0].caller, "prophecy:t:sink:root")
        self.assertEqual(pre[0].caller_port, "root")
        self.assertEqual(pre[0].callee, "child_process.exec")
        self.assertEqual(pre[0].callee_port, "sink")
        self.assertEqual(pre[0].leaves, [("CommandExec", 0)])

    def testAbsolutePathRelativization(self) -> None:
        parser = Parser(repo_dirs={"/repo"})
        analysis_output = AnalysisOutput(
            directory="/output",
            filename_specs=["output.json"],
            file_handle=io.StringIO(
                '{"kind": "issue", "code": 9001, "callable": "foo.ts::main", '
                '"filename": "/repo/src/foo.ts", "position": {"line": 1, '
                '"start": 1, "end": 10}, "description": "RCE", "traces": '
                '[{"forward": {"trace_leaf": {"position": {"line": 1, "start": '
                '1, "end": 10}}, "kind": "Src", "leaves": [{"name": "s"}], '
                '"local_trace": {"positions": []}}}, {"backward": {"trace_leaf":'
                ' {"position": {"line": 1, "start": 1, "end": 10}}, "kind": '
                '"Snk", "leaves": [{"name": "k"}], "local_trace": '
                '{"positions": []}}}], "features": []}\n'
            ),
            metadata=Metadata(repo_roots={"/repo"}),
        )
        issues_and_frames = parser.parse_analysis_output(analysis_output)
        self.assertEqual(len(issues_and_frames.issues), 1)
        self.assertEqual(issues_and_frames.issues[0].filename, "src/foo.ts")

    def testMultipleLeaves(self) -> None:
        issues, _pre, _post = self._parse(
            """
            {
              "kind": "issue",
              "code": 9004,
              "callable": "src/net.ts::fetch",
              "filename": "src/net.ts",
              "position": {"line": 20, "start": 5, "end": 30},
              "description": "SSRF vulnerability",
              "traces": [
                {
                  "forward": {
                    "trace_leaf": {
                      "position": {"line": 10, "start": 1, "end": 15}
                    },
                    "kind": "UserInput",
                    "leaves": [
                      {"name": "req.query.url"},
                      {"name": "req.body.target"}
                    ],
                    "local_trace": {"positions": []}
                  }
                },
                {
                  "backward": {
                    "trace_leaf": {
                      "position": {"line": 20, "start": 5, "end": 30}
                    },
                    "kind": "HttpRequest",
                    "leaves": [{"name": "fetch"}],
                    "local_trace": {"positions": []}
                  }
                }
              ],
              "features": []
            }
            """
        )

        self.assertEqual(len(issues), 1)
        issue = issues[0]
        # Two source leaves → two postcondition entries
        postconditions = list(issue.postconditions)
        self.assertEqual(len(postconditions), 2)
        callees = {p.callee for p in postconditions}
        self.assertEqual(callees, {"req.query.url", "req.body.target"})
        for p in postconditions:
            self.assertEqual(p.leaves, [("UserInput", 0)])

    def testNoLeavesDefaultsToKind(self) -> None:
        issues, _pre, _post = self._parse(
            """
            {
              "kind": "issue",
              "code": 9001,
              "callable": "src/exec.ts::run",
              "filename": "src/exec.ts",
              "position": {"line": 5, "start": 1, "end": 10},
              "description": "RCE",
              "traces": [
                {
                  "forward": {
                    "trace_leaf": {
                      "position": {"line": 1, "start": 1, "end": 5}
                    },
                    "kind": "TaintedInput",
                    "leaves": [],
                    "local_trace": {"positions": []}
                  }
                },
                {
                  "backward": {
                    "trace_leaf": {
                      "position": {"line": 5, "start": 1, "end": 10}
                    },
                    "kind": "Exec",
                    "leaves": [],
                    "local_trace": {"positions": []}
                  }
                }
              ],
              "features": []
            }
            """
        )

        self.assertEqual(len(issues), 1)
        issue = issues[0]
        # When no leaves, callee defaults to the kind name
        postconditions = list(issue.postconditions)
        self.assertEqual(len(postconditions), 1)
        self.assertEqual(postconditions[0].callee, "TaintedInput")

        preconditions = list(issue.preconditions)
        self.assertEqual(len(preconditions), 1)
        self.assertEqual(preconditions[0].callee, "Exec")

    def testIsSupported(self) -> None:
        self.assertTrue(Parser.is_supported(Metadata(tool="prophecy")))
        self.assertFalse(Parser.is_supported(Metadata(tool="pysa")))
        self.assertFalse(Parser.is_supported(Metadata(tool=None)))

    def testHandleStability(self) -> None:
        """Two identical issues should produce the same handle."""
        issue_json = (
            '{"kind": "issue", "code": 9003, "callable": "x.ts::f", '
            '"filename": "x.ts", "position": {"line": 10, "start": 5, '
            '"end": 20}, "description": "XSS", "traces": [{"forward": '
            '{"trace_leaf": {"position": {"line": 1, "start": 1, "end": 5}}, '
            '"kind": "Src", "leaves": [{"name": "s"}], "local_trace": '
            '{"positions": []}}}, {"backward": {"trace_leaf": {"position": '
            '{"line": 10, "start": 5, "end": 20}}, "kind": "Snk", "leaves": '
            '[{"name": "k"}], "local_trace": {"positions": []}}}], '
            '"features": []}\n'
        )
        issues1, _, _ = self._parse(issue_json, flatten=False)
        issues2, _, _ = self._parse(issue_json, flatten=False)
        self.assertEqual(issues1[0].handle, issues2[0].handle)

    def testEmptyTraces(self) -> None:
        """Issue with no traces should still parse."""
        issues, _pre, _post = self._parse(
            """
            {
              "kind": "issue",
              "code": 9001,
              "callable": "test.ts::main",
              "filename": "test.ts",
              "position": {"line": 1, "start": 1, "end": 10},
              "description": "Finding with no trace data",
              "traces": [],
              "features": []
            }
            """
        )
        self.assertEqual(len(issues), 1)
        self.assertEqual(list(issues[0].preconditions), [])
        self.assertEqual(list(issues[0].postconditions), [])

    def testLocalTracePositions(self) -> None:
        """Test that local_trace positions are captured as TITOs."""
        issues, _pre, _post = self._parse(
            """
            {
              "kind": "issue",
              "code": 9003,
              "callable": "src/app.ts::handler",
              "filename": "src/app.ts",
              "position": {"line": 30, "start": 5, "end": 25},
              "description": "XSS with TITOs",
              "traces": [
                {
                  "forward": {
                    "trace_leaf": {
                      "position": {"line": 10, "start": 1, "end": 10}
                    },
                    "kind": "UserInput",
                    "leaves": [{"name": "input"}],
                    "local_trace": {
                      "positions": [
                        {"line": 15, "start": 3, "end": 8},
                        {"line": 20, "start": 5, "end": 12}
                      ]
                    }
                  }
                },
                {
                  "backward": {
                    "trace_leaf": {
                      "position": {"line": 30, "start": 5, "end": 25}
                    },
                    "kind": "InnerHTML",
                    "leaves": [{"name": "el.innerHTML"}],
                    "local_trace": {"positions": []}
                  }
                }
              ],
              "features": []
            }
            """
        )

        self.assertEqual(len(issues), 1)
        postconditions = list(issues[0].postconditions)
        self.assertEqual(len(postconditions), 1)
        titos = list(postconditions[0].titos)
        self.assertEqual(len(titos), 2)
        self.assertEqual(titos[0], SourceLocation(15, 3, 8))
        self.assertEqual(titos[1], SourceLocation(20, 5, 12))
