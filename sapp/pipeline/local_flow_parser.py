# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast, IO

from ..analysis_output import AnalysisOutput
from ..models import HANDLE_LENGTH
from . import (
    ParseError,
    ParseIssueConditionTuple,
    ParseIssueLeaf,
    ParseIssueTuple,
    SourceLocation,
)
from .base_parser import BaseParser


# Rules without a code in rule-codes.json import under this generic code.
TS_LOCAL_FLOW_WARNING_CODE: int = 20002
# SAPP reads these markers in leaf kinds as taint transforms.
_KIND_TRANSFORM_MARKERS: tuple[str, ...] = ("->", "@", "!")


class LocalFlowParserError(ParseError):
    pass


@dataclass(frozen=True)
class _Endpoint:
    callable: str
    file: str
    line: int


@dataclass(frozen=True)
class _IssueFacts:
    source_kinds: tuple[str, ...] = ()
    sink_kinds: tuple[str, ...] = ()
    features: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ParsedFlow:
    canonical_id: str
    issues: list[ParseIssueTuple]
    payload: bytes


def _decode_object(value: str, context: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as error:
        raise LocalFlowParserError(f"invalid {context}: {error}") from error

    if not isinstance(decoded, dict):
        raise LocalFlowParserError(f"{context} must be a JSON object")
    return decoded


def _require_fields(value: dict[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise LocalFlowParserError(
            f"invalid {context} fields: expected {sorted(expected)}, "
            f"got {sorted(value)}"
        )


def _parse_endpoint(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise LocalFlowParserError(f"{context} must be an object")
    _require_fields(value, {"callable", "id"}, context)
    callable_name = value["callable"]
    endpoint_id = value["id"]

    if not isinstance(callable_name, str) or not callable_name:
        raise LocalFlowParserError(f"{context}.callable must be a nonempty string")

    if not isinstance(endpoint_id, dict):
        raise LocalFlowParserError(f"{context}.id must be an object")

    _require_fields(endpoint_id, {"file", "line"}, f"{context}.id")
    filename = endpoint_id["file"]
    line = endpoint_id["line"]

    if not isinstance(filename, str) or not filename:
        raise LocalFlowParserError(f"{context}.id.file must be a nonempty string")

    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise LocalFlowParserError(f"{context}.id.line must be a positive integer")

    return {
        "callable": callable_name,
        "id": {"file": filename, "line": line},
    }


def _parse_identity(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise LocalFlowParserError("canonical flow must be an object")

    _require_fields(value, {"source", "target", "path"}, "canonical flow")
    source = _parse_endpoint(value["source"], "canonical flow source")
    target = _parse_endpoint(value["target"], "canonical flow target")

    path = value["path"]
    if not isinstance(path, list) or not all(isinstance(label, str) for label in path):
        raise LocalFlowParserError("canonical flow path must be a string list")

    return {"source": source, "target": target, "path": path}


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _validate_identity(canonical_id: str, identity_json: str) -> dict[str, object]:
    identity = _parse_identity(_decode_object(identity_json, "canonical flow identity"))
    canonical_json = _canonical_json(identity)
    if identity_json != canonical_json:
        raise LocalFlowParserError(
            "canonical flow must use the canonical JSON encoding"
        )

    expected_id = hashlib.sha256(canonical_json.encode()).hexdigest()
    if canonical_id != expected_id:
        raise LocalFlowParserError(
            f"canonical flow ID `{canonical_id}` does not match its identity"
        )

    return identity


def _validate_payload(payload: dict[str, Any]) -> bool:
    """Validates the trace envelope and returns whether the trace is available."""
    status = payload.get("trace_status")
    if status == "available":
        if not isinstance(payload.get("title"), str) or not isinstance(
            payload.get("description"), str
        ):
            raise LocalFlowParserError("trace title and description must be strings")
        if not isinstance(payload.get("patrace"), dict):
            raise LocalFlowParserError("patrace must be an object")
        if not isinstance(payload.get("semantic_trace"), dict):
            raise LocalFlowParserError("semantic_trace must be an object")
        return True
    if status == "trace_unavailable":
        reason = payload.get("reason")
        if not isinstance(reason, dict):
            raise LocalFlowParserError("trace-unavailable reason must be an object")
        if not isinstance(reason.get("reason"), str) or not isinstance(
            reason.get("limit"), str
        ):
            raise LocalFlowParserError(
                "trace-unavailable reason and limit must be strings"
            )
        return False
    raise LocalFlowParserError(f"unsupported trace status `{status}`")


def _parse_strings(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise LocalFlowParserError(f"{context} must be nonempty strings")
    return tuple(cast(list[str], value))


def _parse_kinds(value: object, context: str) -> tuple[str, ...]:
    kinds = _parse_strings(value, context)
    if any(marker in kind for kind in kinds for marker in _KIND_TRANSFORM_MARKERS):
        raise LocalFlowParserError(f"{context} must not use SAPP transform syntax")
    return kinds


def _parse_issue_facts(payload: dict[str, Any]) -> _IssueFacts:
    # Payloads from LFE versions without issue facts carry none, and fields that
    # later LFE versions add are ignored.
    facts = payload.get("issue_facts", {})
    if not isinstance(facts, dict):
        raise LocalFlowParserError("issue_facts must be an object")
    return _IssueFacts(
        source_kinds=_parse_kinds(
            facts.get("source_kinds", []), "issue_facts.source_kinds"
        ),
        sink_kinds=_parse_kinds(facts.get("sink_kinds", []), "issue_facts.sink_kinds"),
        features=_parse_strings(facts.get("features", []), "issue_facts.features"),
    )


def _endpoint(identity: dict[str, object], name: str) -> _Endpoint:
    endpoint = cast(dict[str, object], identity[name])
    endpoint_id = cast(dict[str, object], endpoint["id"])
    return _Endpoint(
        callable=cast(str, endpoint["callable"]),
        file=cast(str, endpoint_id["file"]),
        line=cast(int, endpoint_id["line"]),
    )


def _validate_rule_mapping(
    flows_to_rules: Mapping[str, Iterable[str]],
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for flow_id, rule_values in flows_to_rules.items():
        if isinstance(rule_values, str):
            raise LocalFlowParserError(
                "flows-to-rules must map IDs to unique nonempty rule names"
            )
        rules = list(rule_values)
        if (
            not rules
            or any(not isinstance(rule, str) or not rule for rule in rules)
            or len(set(rules)) != len(rules)
        ):
            raise LocalFlowParserError(
                "flows-to-rules must map IDs to unique nonempty rule names"
            )
        result[flow_id] = sorted(rules)

    return result


class LocalFlowParser(BaseParser):
    def __init__(
        self,
        repository: str,
        project: str,
    ) -> None:
        super().__init__()
        if not repository or not project:
            raise LocalFlowParserError("repository and project must be nonempty")
        self.repository = repository
        self.project = project
        self.flows_to_rules: dict[str, list[str]] = {}
        self.rule_codes: dict[str, int] = {}
        self.trace_payloads_by_handle: dict[str, bytes] = {}

    def parse(self, input: AnalysisOutput) -> Iterable[ParseIssueTuple]:
        self.trace_payloads_by_handle.clear()
        directory = _results_directory(input)
        self.flows_to_rules = _load_flows_to_rules(directory)
        self.rule_codes = _load_rule_codes(directory)
        yield from self._parse_handles(input.file_handles())

    def _parse_handles(self, handles: Iterable[IO[str]]) -> Iterable[ParseIssueTuple]:
        seen: set[str] = set()
        payloads: dict[str, bytes] = {}

        for handle in handles:
            for line_number, row in enumerate(handle, 1):
                flow = self._parse_row(row.removesuffix("\n"), line_number)
                if flow.canonical_id in seen:
                    raise LocalFlowParserError(
                        f"duplicate canonical ID `{flow.canonical_id}`"
                    )
                seen.add(flow.canonical_id)
                for issue in flow.issues:
                    payloads[issue.handle] = flow.payload
                    yield issue

        if seen != set(self.flows_to_rules):
            raise LocalFlowParserError(
                "canonical rows and flows-to-rules do not exactly match"
            )

        self.trace_payloads_by_handle.update(payloads)

    def _parse_row(self, row: str, line_number: int) -> _ParsedFlow:
        # LFE export_canonical emits headerless TSV rows:
        # SHA-256 flow ID, canonical identity JSON, and trace payload JSON.
        # Sandcastle also reads these rows for combination and diff analysis;
        # this adapter converts them into SAPP issues and retains payload bytes.
        fields = row.split("\t")
        if len(fields) != 3 or not fields[0]:
            raise LocalFlowParserError(
                f"row {line_number} must contain exactly three tab-separated fields"
            )

        canonical_id, identity_json, payload_json = fields
        identity = _validate_identity(canonical_id, identity_json)
        payload = _decode_object(payload_json, "canonical trace payload")
        trace_available = _validate_payload(payload)
        facts = _parse_issue_facts(payload)
        rules = self.flows_to_rules.get(canonical_id)

        if rules is None:
            raise LocalFlowParserError(
                "canonical rows and flows-to-rules do not exactly match"
            )

        rules_by_code: dict[int, list[str]] = {}
        for rule in rules:
            code = self.rule_codes.get(rule, TS_LOCAL_FLOW_WARNING_CODE)
            rules_by_code.setdefault(code, []).append(rule)
        shared_features = [
            *facts.features,
            "local-flow-trace:available"
            if trace_available
            else "local-flow-trace:unavailable",
        ]
        source = _endpoint(identity, "source")
        target = _endpoint(identity, "target")
        # Canonical endpoints contain a line number, but no columns.
        location = SourceLocation(line_no=target.line, begin_column=1, end_column=1)
        preconditions = _leaf_frames(
            target.callable, "sink", facts.sink_kinds, location
        )
        postconditions = _leaf_frames(
            source.callable, "source", facts.source_kinds, location
        )
        initial_sources = _issue_leaves(source.callable, facts.source_kinds)
        final_sinks = _issue_leaves(target.callable, facts.sink_kinds)

        return _ParsedFlow(
            canonical_id=canonical_id,
            payload=payload_json.encode(),
            issues=[
                ParseIssueTuple(
                    code=code,
                    message=f"Local flow from {source.callable} to {target.callable}",
                    callable=target.callable,
                    handle=self._issue_handle(code, canonical_id),
                    filename=target.file,
                    line=target.line,
                    start=location.begin_column,
                    end=location.end_column,
                    preconditions=preconditions,
                    postconditions=postconditions,
                    initial_sources=initial_sources,
                    final_sinks=final_sinks,
                    features=[f"local-flow-rule:{rule}" for rule in code_rules]
                    + shared_features,
                    callable_line=target.line,
                    fix_info=None,
                )
                for code, code_rules in sorted(rules_by_code.items())
            ],
        )

    def _issue_handle(self, code: int, canonical_id: str) -> str:
        handle = (
            f"ts-local-flow:{self.repository}:{self.project}:v2:{code}:{canonical_id}"
        )
        if len(handle) > HANDLE_LENGTH:
            raise LocalFlowParserError(
                f"issue handle `{handle}` exceeds {HANDLE_LENGTH} characters"
            )
        return handle


def _leaf_frames(
    callee: str, port: str, kinds: tuple[str, ...], location: SourceLocation
) -> list[ParseIssueConditionTuple]:
    # SAPP derives an issue's Source and Sink kinds only from the leaves of its
    # trace frames, so each classified endpoint becomes one leaf frame. The
    # canonical identity has no call site, so the frame uses the issue location.
    if not kinds:
        return []
    return [
        ParseIssueConditionTuple(
            callee=callee,
            port=port,
            location=location,
            leaves=[(kind, 0) for kind in kinds],
            titos=[],
            features=[],
            type_interval=None,
            annotations=[],
        )
    ]


def _issue_leaves(endpoint: str, kinds: tuple[str, ...]) -> list[ParseIssueLeaf]:
    # SAPP shows these callables as the issue's source and sink names, so an
    # endpoint without kinds still contributes its name.
    return [(endpoint, kind, 0) for kind in kinds or ("",)]


def _results_directory(input: AnalysisOutput) -> Path:
    if input.directory is None:
        raise LocalFlowParserError("TS Local Flow import requires a results directory")
    return Path(input.directory)


def _load_flows_to_rules(directory: Path) -> dict[str, list[str]]:
    path = directory / "flows-to-rules.json"
    try:
        contents = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise LocalFlowParserError(
            f"cannot read flows-to-rules file `{path}`"
        ) from error
    return _validate_rule_mapping(_decode_flows_to_rules(contents))


def _load_rule_codes(directory: Path) -> dict[str, int]:
    path = directory / "rule-codes.json"
    try:
        contents = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        # Bundles written before rules declared codes have no rule-codes file.
        return {}
    except (OSError, UnicodeError) as error:
        raise LocalFlowParserError(f"cannot read rule-codes file `{path}`") from error

    rule_codes = _decode_object(contents, "rule-codes")
    for rule, code in rule_codes.items():
        if not isinstance(code, int) or isinstance(code, bool):
            raise LocalFlowParserError(f"rule `{rule}` must map to an integer code")
    return cast(dict[str, int], rule_codes)


def _decode_flows_to_rules(contents: str) -> dict[str, list[str]]:
    decoded = _decode_object(contents, "flows-to-rules")

    result: dict[str, list[str]] = {}
    for flow_id, rules in decoded.items():
        if not isinstance(rules, list) or any(
            not isinstance(rule, str) for rule in rules
        ):
            raise LocalFlowParserError(
                f"rules for canonical ID `{flow_id}` must be a string list"
            )
        result[flow_id] = rules

    return result
