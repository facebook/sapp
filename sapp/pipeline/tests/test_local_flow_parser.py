# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ...analysis_output import AnalysisOutput
from .. import ParseError, ParseIssueConditionTuple, ParseIssueTuple, SourceLocation
from ..local_flow_parser import LocalFlowParser, LocalFlowParserError


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class TestLocalFlowParser(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.directory = Path(temporary_directory.name)
        self.identity = {
            "source": {
                "callable": "source",
                "id": {"file": "src/source.ts", "line": 11},
            },
            "target": {
                "callable": "sink",
                "id": {"file": "src/sink.ts", "line": 29},
            },
            "path": ["field"],
        }
        self.identity_json = _canonical_json(self.identity)
        self.canonical_id = hashlib.sha256(self.identity_json.encode()).hexdigest()
        self.unavailable_payload: dict[str, object] = {
            "trace_status": "trace_unavailable",
            "reason": {"reason": "budget_exceeded", "limit": "compressed_bytes"},
        }

    def _available_payload(self) -> dict[str, object]:
        semantic_trace = {
            "schema_version": 6,
            "repository": "fbsource",
            "commit_hash": "0123456789abcdef",
            "tool": None,
            "title": "Source to sink",
            "description": "A local TypeScript flow",
            "source": "source",
            "target": "sink",
            "direction": "forward",
            "call_length": 1,
            "structure": "direct",
            "source_endpoint": {},
            "sink_endpoint": {},
            "auxiliary_events": [],
            "diagnostics": [],
            "display_trace": {"steps": []},
            "witness": {},
            "nodes": [],
            "call_labels": [],
            "frames": [],
            "presentation": {
                "version": 2,
                "nodes": [],
                "unplaced_steps": [],
            },
        }
        return {
            "trace_status": "available",
            "title": "Source to sink",
            "description": "A local TypeScript flow",
            "patrace": {"repository": "fbsource", "frames": []},
            "semantic_trace": semantic_trace,
        }

    def _row(
        self,
        *,
        canonical_id: str | None = None,
        identity_json: str | None = None,
        payload: object | None = None,
    ) -> str:
        return "\t".join(
            [
                canonical_id or self.canonical_id,
                identity_json or self.identity_json,
                _canonical_json(payload or self.unavailable_payload),
            ]
        )

    def _input(
        self, contents: str, rules: object, rule_codes: object | None = None
    ) -> AnalysisOutput:
        (self.directory / "canonical.tsv").write_text(contents, encoding="utf-8")
        (self.directory / "flows-to-rules.json").write_text(
            _canonical_json(rules), encoding="utf-8"
        )
        rule_codes_path = self.directory / "rule-codes.json"
        if rule_codes is None:
            rule_codes_path.unlink(missing_ok=True)
        else:
            rule_codes_path.write_text(_canonical_json(rule_codes), encoding="utf-8")
        (self.directory / "metadata.json").write_text(
            _canonical_json(
                {
                    "filename_spec": "canonical.tsv",
                    "root": str(self.directory),
                    "version": "test-version",
                    "tool": "ts-local-flow",
                }
            ),
            encoding="utf-8",
        )
        return AnalysisOutput.from_directory(str(self.directory))

    def _parse(
        self,
        contents: str,
        rules: object,
        *,
        project: str = "example-app",
        rule_codes: object | None = None,
    ) -> tuple[LocalFlowParser, list[ParseIssueTuple]]:
        parser = LocalFlowParser(repository="fbsource", project=project)
        result = parser.parse_analysis_output(self._input(contents, rules, rule_codes))
        self.assertEqual(result.preconditions.frame_count(), 0)
        self.assertEqual(result.postconditions.frame_count(), 0)
        return parser, list(result.issues)

    def test_parses_one_available_issue_with_all_rules(self) -> None:
        payload = self._available_payload()
        parser, issues = self._parse(
            self._row(payload=payload) + "\n",
            {self.canonical_id: ["a-rule", "z-rule"]},
        )

        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue.code, 20002)
        self.assertEqual(
            issue.handle,
            f"ts-local-flow:fbsource:example-app:v2:20002:{self.canonical_id}",
        )
        self.assertEqual(issue.message, "Local flow from source to sink")
        self.assertEqual(issue.callable, "sink")
        self.assertEqual(issue.filename, "src/sink.ts")
        self.assertEqual(issue.line, 29)
        self.assertEqual(
            issue.features,
            [
                "local-flow-rule:a-rule",
                "local-flow-rule:z-rule",
                "local-flow-trace:available",
            ],
        )
        self.assertEqual(list(issue.preconditions), [])
        self.assertEqual(list(issue.postconditions), [])
        self.assertEqual(list(issue.initial_sources), [("source", "", 0)])
        self.assertEqual(list(issue.final_sinks), [("sink", "", 0)])
        self.assertEqual(
            parser.trace_payloads_by_handle[issue.handle],
            _canonical_json(payload).encode(),
        )

    def test_imports_issue_facts_as_kinds_and_features(self) -> None:
        for payload, trace_feature in (
            (self._available_payload(), "local-flow-trace:available"),
            (dict(self.unavailable_payload), "local-flow-trace:unavailable"),
        ):
            payload["issue_facts"] = {
                "source_kinds": ["http-request", "request-input"],
                "sink_kinds": ["code-execution"],
                "features": ["via-callback:modeled-invocation"],
            }
            with self.subTest(trace_status=payload["trace_status"]):
                _parser, issues = self._parse(
                    self._row(payload=payload) + "\n", {self.canonical_id: ["rule"]}
                )

                issue = issues[0]
                location = SourceLocation(line_no=29, begin_column=1, end_column=1)
                self.assertEqual(
                    list(issue.postconditions),
                    [
                        ParseIssueConditionTuple(
                            callee="source",
                            port="source",
                            location=location,
                            leaves=[("http-request", 0), ("request-input", 0)],
                            titos=[],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        )
                    ],
                )
                self.assertEqual(
                    list(issue.preconditions),
                    [
                        ParseIssueConditionTuple(
                            callee="sink",
                            port="sink",
                            location=location,
                            leaves=[("code-execution", 0)],
                            titos=[],
                            features=[],
                            type_interval=None,
                            annotations=[],
                        )
                    ],
                )
                self.assertEqual(
                    list(issue.initial_sources),
                    [("source", "http-request", 0), ("source", "request-input", 0)],
                )
                self.assertEqual(
                    list(issue.final_sinks), [("sink", "code-execution", 0)]
                )
                self.assertEqual(
                    issue.features,
                    [
                        "local-flow-rule:rule",
                        "via-callback:modeled-invocation",
                        trace_feature,
                    ],
                )

    def test_unclassified_endpoints_keep_names_without_leaf_frames(self) -> None:
        payload = dict(self.unavailable_payload)
        payload["issue_facts"] = {
            "source_kinds": [],
            "sink_kinds": ["code-execution"],
            "features": [],
        }
        _parser, issues = self._parse(
            self._row(payload=payload) + "\n", {self.canonical_id: ["rule"]}
        )

        self.assertEqual(list(issues[0].postconditions), [])
        self.assertEqual(list(issues[0].initial_sources), [("source", "", 0)])
        self.assertEqual(len(list(issues[0].preconditions)), 1)

    def test_ignores_unknown_and_missing_issue_facts_fields(self) -> None:
        payload = dict(self.unavailable_payload)
        payload["issue_facts"] = {
            "sink_kinds": ["code-execution"],
            "added_by_a_later_lfe": True,
        }
        _parser, issues = self._parse(
            self._row(payload=payload) + "\n", {self.canonical_id: ["rule"]}
        )

        self.assertEqual(list(issues[0].initial_sources), [("source", "", 0)])
        self.assertEqual(list(issues[0].final_sinks), [("sink", "code-execution", 0)])
        self.assertEqual(issues[0].features[-1:], ["local-flow-trace:unavailable"])

    def test_rejects_malformed_issue_facts(self) -> None:
        for facts in (
            None,
            [],
            {"source_kinds": "http-request"},
            {"sink_kinds": [""]},
            {"sink_kinds": [1]},
            {"source_kinds": ["UserControlled@Transform"]},
            {"sink_kinds": ["Transform->Sink"]},
            {"sink_kinds": ["!Partial"]},
            {"features": [None]},
        ):
            payload = dict(self.unavailable_payload)
            payload["issue_facts"] = facts
            with (
                self.subTest(facts=facts),
                self.assertRaisesRegex(LocalFlowParserError, "issue_facts"),
            ):
                self._parse(
                    self._row(payload=payload) + "\n", {self.canonical_id: ["rule"]}
                )

    def test_splits_rules_into_one_issue_per_warning_code(self) -> None:
        parser, issues = self._parse(
            self._row() + "\n",
            {self.canonical_id: ["sql-rule", "exec-rule", "other-exec-rule"]},
            rule_codes={
                "exec-rule": 6019,
                "other-exec-rule": 6019,
                "sql-rule": 6026,
                "rule-without-flows": 20101,
            },
        )

        self.assertEqual([issue.code for issue in issues], [6019, 6026])
        self.assertEqual(
            [issue.handle for issue in issues],
            [
                f"ts-local-flow:fbsource:example-app:v2:6019:{self.canonical_id}",
                f"ts-local-flow:fbsource:example-app:v2:6026:{self.canonical_id}",
            ],
        )
        self.assertEqual(
            [issue.features for issue in issues],
            [
                [
                    "local-flow-rule:exec-rule",
                    "local-flow-rule:other-exec-rule",
                    "local-flow-trace:unavailable",
                ],
                ["local-flow-rule:sql-rule", "local-flow-trace:unavailable"],
            ],
        )
        self.assertEqual(
            parser.trace_payloads_by_handle,
            {
                issue.handle: _canonical_json(self.unavailable_payload).encode()
                for issue in issues
            },
        )

    def test_rules_without_a_code_use_the_generic_code(self) -> None:
        _parser, issues = self._parse(
            self._row() + "\n",
            {self.canonical_id: ["rule", "other-rule"]},
            rule_codes={"rule": 6019},
        )

        self.assertEqual([issue.code for issue in issues], [6019, 20002])

    def test_rejects_non_integer_rule_codes(self) -> None:
        for code in (True, "6019", 60.19, None):
            with (
                self.subTest(code=code),
                self.assertRaisesRegex(LocalFlowParserError, "integer code"),
            ):
                self._parse(
                    self._row() + "\n",
                    {self.canonical_id: ["rule"]},
                    rule_codes={"rule": code},
                )

    def test_rejects_malformed_rule_codes_file(self) -> None:
        for contents, message in (
            (b"[]", "rule-codes must be a JSON object"),
            (b"not JSON", "invalid rule-codes"),
            (b"\xff", "cannot read rule-codes file"),
        ):
            with self.subTest(contents=contents):
                input = self._input(self._row() + "\n", {self.canonical_id: ["rule"]})
                (self.directory / "rule-codes.json").write_bytes(contents)
                parser = LocalFlowParser(repository="fbsource", project="example-app")
                with self.assertRaisesRegex(LocalFlowParserError, message):
                    parser.parse_analysis_output(input)

    def test_rejects_handles_longer_than_sapp_allows(self) -> None:
        with self.assertRaisesRegex(LocalFlowParserError, "exceeds 255 characters"):
            self._parse(
                self._row() + "\n", {self.canonical_id: ["rule"]}, project="p" * 200
            )

    def test_retains_typed_unavailable_trace(self) -> None:
        parser, issues = self._parse(self._row() + "\n", {self.canonical_id: ["rule"]})

        self.assertEqual(
            parser.trace_payloads_by_handle[issues[0].handle],
            _canonical_json(self.unavailable_payload).encode(),
        )

    def test_rejects_duplicate_or_mismatched_canonical_id(self) -> None:
        with self.assertRaisesRegex(LocalFlowParserError, "duplicate canonical ID"):
            self._parse(
                self._row() + "\n" + self._row() + "\n",
                {self.canonical_id: ["rule"]},
            )

        for canonical_id in (
            "0" * 64,
            "g" * 64,
            self.canonical_id.upper(),
            "short",
            self.canonical_id + "0",
        ):
            with (
                self.subTest(canonical_id=canonical_id),
                self.assertRaisesRegex(LocalFlowParserError, "does not match"),
            ):
                self._parse(
                    self._row(canonical_id=canonical_id) + "\n",
                    {self.canonical_id: ["rule"]},
                )

    def test_rejects_noncanonical_identity_json(self) -> None:
        noncanonical = json.dumps(self.identity)
        with self.assertRaisesRegex(LocalFlowParserError, "canonical JSON encoding"):
            self._parse(
                self._row(
                    canonical_id=hashlib.sha256(noncanonical.encode()).hexdigest(),
                    identity_json=noncanonical,
                )
                + "\n",
                {self.canonical_id: ["rule"]},
            )

    def test_duplicate_identity_keys_fail_canonical_reserialization(self) -> None:
        duplicate_identity = self.identity_json.replace(
            '"path":["field"]', '"path":["obsolete"],"path":["field"]'
        )
        self.assertEqual(json.loads(duplicate_identity), self.identity)
        with self.assertRaisesRegex(LocalFlowParserError, "canonical JSON encoding"):
            self._parse(
                self._row(identity_json=duplicate_identity) + "\n",
                {self.canonical_id: ["rule"]},
            )

    def test_validation_errors_are_parse_errors(self) -> None:
        self.assertTrue(issubclass(LocalFlowParserError, ParseError))
        with self.assertRaises(ParseError):
            self._parse(
                self._row(canonical_id="0" * 64) + "\n",
                {self.canonical_id: ["rule"]},
            )

    def test_payload_json_uses_standard_decoding_and_preserves_bytes(self) -> None:
        payload = self._available_payload()
        payload["title"] = "Source → sink"
        payload["semantic_trace"] = {
            "schema_version": 999,
            "producer_metadata": {"label": "Source → sink", "revision": 2},
        }
        encoded = json.dumps(payload, ensure_ascii=False).replace(
            '"trace_status": "available"',
            '"trace_status": "obsolete", "trace_status": "available"',
        )
        row = "\t".join([self.canonical_id, self.identity_json, encoded])

        self.assertEqual(json.loads(encoded), payload)
        parser, issues = self._parse(row + "\n", {self.canonical_id: ["rule"]})
        self.assertEqual(
            parser.trace_payloads_by_handle[issues[0].handle], encoded.encode()
        )

    def test_rejects_nonstring_unavailable_reason_fields(self) -> None:
        for field in ("reason", "limit"):
            for invalid in (None, 3, float("nan"), [], {}):
                reason: dict[str, object] = {
                    "reason": "budget_exceeded",
                    "limit": "compressed_bytes",
                }
                reason[field] = invalid
                payload = {"trace_status": "trace_unavailable", "reason": reason}
                with (
                    self.subTest(field=field, value=invalid),
                    self.assertRaises(LocalFlowParserError),
                ):
                    self._parse(
                        self._row(payload=payload) + "\n",
                        {self.canonical_id: ["rule"]},
                    )

    def test_payloads_decode_independently_and_preserve_additive_fields(self) -> None:
        for payload in (self._available_payload(), dict(self.unavailable_payload)):
            payload["producer_metadata"] = {"version": 2}
            with self.subTest(status=payload["trace_status"]):
                encoded = _canonical_json(payload).encode()
                parser, issues = self._parse(
                    self._row(payload=payload) + "\n",
                    {self.canonical_id: ["rule"]},
                )
                self.assertEqual(
                    parser.trace_payloads_by_handle[issues[0].handle], encoded
                )

    def test_rejects_malformed_trace_status_variants(self) -> None:
        available = self._available_payload()
        del available["title"]
        unavailable = dict(self.unavailable_payload)
        unavailable["reason"] = {"reason": "budget_exceeded"}
        for payload, message in (
            (available, "title and description"),
            (unavailable, "unavailable reason"),
        ):
            with (
                self.subTest(status=payload["trace_status"]),
                self.assertRaisesRegex(LocalFlowParserError, message),
            ):
                self._parse(
                    self._row(payload=payload) + "\n",
                    {self.canonical_id: ["rule"]},
                )

    def test_accepts_forward_compatible_unavailable_reasons(self) -> None:
        for reason in (
            {"reason": "budget_exceeded", "limit": "frames"},
            {"reason": "new_reason", "limit": "new_limit", "details": [1]},
            {"reason": "", "limit": ""},
        ):
            payload = {"trace_status": "trace_unavailable", "reason": reason}
            with self.subTest(reason=reason):
                parser, issues = self._parse(
                    self._row(payload=payload) + "\n",
                    {self.canonical_id: ["rule"]},
                )
                self.assertEqual(
                    parser.trace_payloads_by_handle[issues[0].handle],
                    _canonical_json(payload).encode(),
                )

    def test_accepts_opaque_semantic_trace_contents(self) -> None:
        for semantic_trace in (
            {},
            {"schema_version": 999, "new_field": [1, 2]},
            {"presentation": "future presentation format"},
            {"presentation": {"version": 999, "nodes": None, "extra": True}},
        ):
            payload = self._available_payload()
            payload["semantic_trace"] = semantic_trace
            with self.subTest(semantic_trace=semantic_trace):
                encoded = _canonical_json(payload).encode()
                parser, issues = self._parse(
                    self._row(payload=payload) + "\n",
                    {self.canonical_id: ["rule"]},
                )
                self.assertEqual(
                    parser.trace_payloads_by_handle[issues[0].handle], encoded
                )

    def test_requires_valid_available_envelope_fields(self) -> None:
        for field in ("title", "description", "patrace", "semantic_trace"):
            for invalid in (None, 1, []):
                payload = self._available_payload()
                payload[field] = invalid
                with (
                    self.subTest(field=field, value=invalid),
                    self.assertRaises(LocalFlowParserError),
                ):
                    self._parse(
                        self._row(payload=payload) + "\n",
                        {self.canonical_id: ["rule"]},
                    )

    def test_requires_nonempty_unique_string_rules(self) -> None:
        for rules in ([], ["a", "a"], [""], [1], ["a", None], "rule"):
            with self.subTest(rules=rules), self.assertRaises(LocalFlowParserError):
                self._parse(self._row() + "\n", {self.canonical_id: rules})

    def test_normalizes_rule_order(self) -> None:
        parser, issues = self._parse(
            self._row() + "\n", {self.canonical_id: ["z-rule", "a-rule"]}
        )
        self.assertEqual(parser.flows_to_rules[self.canonical_id], ["a-rule", "z-rule"])
        self.assertEqual(
            issues[0].features[:2], ["local-flow-rule:a-rule", "local-flow-rule:z-rule"]
        )

    def test_requires_exact_rule_membership(self) -> None:
        with self.assertRaisesRegex(LocalFlowParserError, "exactly match"):
            self._parse(self._row() + "\n", {})

        with self.assertRaisesRegex(LocalFlowParserError, "exactly match"):
            self._parse(
                self._row() + "\n",
                {self.canonical_id: ["rule"], "not-a-flow-id": ["other-rule"]},
            )

    def test_accepts_unsorted_canonical_rows(self) -> None:
        other_identity = {
            "source": {
                "callable": "other-source",
                "id": {"file": "src/other.ts", "line": 3},
            },
            "target": self.identity["target"],
            "path": ["other-field"],
        }
        other_identity_json = _canonical_json(other_identity)
        other_id = hashlib.sha256(other_identity_json.encode()).hexdigest()
        other_payload = {
            "trace_status": "trace_unavailable",
            "reason": {"reason": "budget_exceeded", "limit": "raw_bytes"},
        }
        rows = sorted(
            [
                (self.canonical_id, self._row()),
                (
                    other_id,
                    self._row(
                        canonical_id=other_id,
                        identity_json=other_identity_json,
                        payload=other_payload,
                    ),
                ),
            ],
            reverse=True,
        )

        parser, issues = self._parse(
            "\n".join(row for _flow_id, row in rows) + "\n",
            {self.canonical_id: ["rule"], other_id: ["other-rule"]},
        )
        self.assertEqual(
            [issue.handle for issue in issues],
            [
                f"ts-local-flow:fbsource:example-app:v2:20002:{flow_id}"
                for flow_id, _row in rows
            ],
        )
        self.assertEqual(len(parser.trace_payloads_by_handle), 2)

    def test_consumes_one_row_at_a_time_and_publishes_only_on_exhaustion(self) -> None:
        other_identity = dict(self.identity, path=["other-field"])
        other_json = _canonical_json(other_identity)
        other_id = hashlib.sha256(other_json.encode()).hexdigest()
        first_row = self._row() + "\n"
        second_row = self._row(canonical_id=other_id, identity_json=other_json) + "\n"
        parser = LocalFlowParser(repository="fbsource", project="example-app")
        payloads = parser.trace_payloads_by_handle
        payloads["stale"] = b"previous run"
        input = self._input(
            first_row + second_row,
            {self.canonical_id: ["rule"], other_id: ["rule"]},
        )
        parsed = iter(parser.parse(input))
        first = next(parsed)
        self.assertEqual(payloads, {})
        second = next(parsed)
        self.assertEqual(payloads, {})
        with self.assertRaises(StopIteration):
            next(parsed)
        self.assertIs(parser.trace_payloads_by_handle, payloads)
        self.assertEqual(
            payloads,
            {
                first.handle: _canonical_json(self.unavailable_payload).encode(),
                second.handle: _canonical_json(self.unavailable_payload).encode(),
            },
        )

        parsed = iter(
            parser.parse(
                self._input(
                    first_row + "invalid second row\n", {self.canonical_id: ["rule"]}
                )
            )
        )
        self.assertEqual(next(parsed).handle, first.handle)
        self.assertEqual(payloads, {})
        with self.assertRaisesRegex(LocalFlowParserError, "three tab-separated fields"):
            next(parsed)
        self.assertEqual(payloads, {})

    def test_late_errors_prevent_parse_analysis_output_from_returning(self) -> None:
        for contents, rules, message in (
            (
                self._row() + "\n" + self._row() + "\n",
                {self.canonical_id: ["rule"]},
                "duplicate canonical ID",
            ),
            (
                self._row() + "\n",
                {self.canonical_id: ["rule"], "f" * 64: ["missing-rule"]},
                "exactly match",
            ),
        ):
            with self.subTest(message=message):
                parser = LocalFlowParser(repository="fbsource", project="example-app")
                payloads = parser.trace_payloads_by_handle
                with self.assertRaisesRegex(LocalFlowParserError, message):
                    parser.parse_analysis_output(self._input(contents, rules))
                self.assertIs(parser.trace_payloads_by_handle, payloads)
                self.assertEqual(payloads, {})

    def test_reused_parser_keeps_payload_dictionary_reference(self) -> None:
        parser, first = self._parse(self._row() + "\n", {self.canonical_id: ["rule"]})
        payloads = parser.trace_payloads_by_handle
        self.assertEqual(
            payloads[first[0].handle],
            _canonical_json(self.unavailable_payload).encode(),
        )
        duplicate_rows = self._row() + "\n" + self._row() + "\n"
        with self.assertRaisesRegex(LocalFlowParserError, "duplicate canonical ID"):
            parser.parse_analysis_output(
                self._input(duplicate_rows, {self.canonical_id: ["rule"]})
            )
        self.assertIs(parser.trace_payloads_by_handle, payloads)
        self.assertEqual(payloads, {})

        available = self._available_payload()
        result = parser.parse_analysis_output(
            self._input(
                self._row(payload=available) + "\n", {self.canonical_id: ["rule"]}
            )
        )
        self.assertEqual(len(result.issues), 1)
        self.assertIs(parser.trace_payloads_by_handle, payloads)
        self.assertEqual(
            payloads, {first[0].handle: _canonical_json(available).encode()}
        )

    def test_handle_is_deterministic_and_project_scoped(self) -> None:
        _first_parser, first = self._parse(
            self._row() + "\n", {self.canonical_id: ["rule"]}
        )
        _repeat_parser, repeat = self._parse(
            self._row() + "\n", {self.canonical_id: ["rule"]}
        )
        _other_parser, other = self._parse(
            self._row() + "\n",
            {self.canonical_id: ["rule"]},
            project="other-app",
        )

        self.assertEqual(first[0].handle, repeat[0].handle)
        self.assertNotEqual(first[0].handle, other[0].handle)

    def test_keeps_trace_payload_mapping_reference_stable(self) -> None:
        parser = LocalFlowParser(repository="fbsource", project="example-app")
        payloads = parser.trace_payloads_by_handle

        parser.parse_analysis_output(
            self._input(self._row() + "\n", {self.canonical_id: ["rule"]})
        )

        self.assertIs(parser.trace_payloads_by_handle, payloads)
        self.assertEqual(len(payloads), 1)

    def test_loads_rule_mapping_with_standard_json_duplicate_keys(self) -> None:
        input = self._input(self._row() + "\n", {self.canonical_id: ["rule"]})
        parser = LocalFlowParser(repository="fbsource", project="example-app")
        first = parser.parse_analysis_output(input).issues
        self.assertIn("local-flow-rule:rule", first[0].features)

        encoded_id = json.dumps(self.canonical_id)
        (self.directory / "flows-to-rules.json").write_text(
            f'{{{encoded_id}:["a"],{encoded_id}:["b"]}}', encoding="utf-8"
        )
        second = parser.parse_analysis_output(input).issues
        self.assertIn("local-flow-rule:b", second[0].features)
        self.assertNotIn("local-flow-rule:a", second[0].features)

    def test_sidecar_failure_clears_existing_payload_mapping(self) -> None:
        for contents in (None, b"invalid JSON", b"[]", b"\xff", b'{"id": []}'):
            with self.subTest(contents=contents):
                input = self._input(self._row() + "\n", {self.canonical_id: ["rule"]})
                parser = LocalFlowParser(repository="fbsource", project="example-app")
                parser.parse_analysis_output(input)
                payloads = parser.trace_payloads_by_handle
                self.assertEqual(len(payloads), 1)
                rules_path = self.directory / "flows-to-rules.json"
                if contents is None:
                    rules_path.unlink()
                else:
                    rules_path.write_bytes(contents)

                with self.assertRaises(LocalFlowParserError):
                    parser.parse_analysis_output(input)
                self.assertIs(parser.trace_payloads_by_handle, payloads)
                self.assertEqual(payloads, {})

    def test_file_input_failure_clears_existing_payload_mapping(self) -> None:
        input = self._input(self._row() + "\n", {self.canonical_id: ["rule"]})
        parser = LocalFlowParser(repository="fbsource", project="example-app")
        parser.parse_analysis_output(input)
        payloads = parser.trace_payloads_by_handle
        self.assertEqual(len(payloads), 1)

        with self.assertRaisesRegex(
            LocalFlowParserError, "requires a results directory"
        ):
            parser.parse_analysis_output(
                AnalysisOutput.from_file(str(self.directory / "canonical.tsv"))
            )
        self.assertIs(parser.trace_payloads_by_handle, payloads)
        self.assertEqual(payloads, {})
