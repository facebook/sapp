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
from . import ParseError, ParseIssueTuple
from .base_parser import BaseParser


# TODO: Assign distinct SAPP warning codes to individual LFE rules in a follow-up.
# Until then, specific rule identifiers are retained in issue messages and features.
TS_LOCAL_FLOW_WARNING_CODE: int = 20002


class LocalFlowParserError(ParseError):
    pass


@dataclass(frozen=True)
class _ParsedFlow:
    canonical_id: str
    issue: ParseIssueTuple
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


def _validate_payload(payload: dict[str, Any]) -> None:
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
    elif status == "trace_unavailable":
        reason = payload.get("reason")
        if not isinstance(reason, dict):
            raise LocalFlowParserError("trace-unavailable reason must be an object")
        if not isinstance(reason.get("reason"), str) or not isinstance(
            reason.get("limit"), str
        ):
            raise LocalFlowParserError(
                "trace-unavailable reason and limit must be strings"
            )
    else:
        raise LocalFlowParserError(f"unsupported trace status `{status}`")


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
        self.trace_payloads_by_handle: dict[str, bytes] = {}

    def parse(self, input: AnalysisOutput) -> Iterable[ParseIssueTuple]:
        self.trace_payloads_by_handle.clear()
        self.flows_to_rules = _load_flows_to_rules(input)
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
                payloads[flow.issue.handle] = flow.payload
                yield flow.issue

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
        _validate_payload(payload)

        target = cast(dict[str, object], identity["target"])
        source = cast(dict[str, object], identity["source"])
        target_id = cast(dict[str, object], target["id"])
        target_callable = cast(str, target["callable"])
        source_callable = cast(str, source["callable"])
        target_file = cast(str, target_id["file"])
        target_line = cast(int, target_id["line"])
        rules = self.flows_to_rules.get(canonical_id)

        if rules is None:
            raise LocalFlowParserError(
                "canonical rows and flows-to-rules do not exactly match"
            )

        issue_handle = self._issue_handle(canonical_id)

        return _ParsedFlow(
            canonical_id=canonical_id,
            payload=payload_json.encode(),
            issue=ParseIssueTuple(
                code=TS_LOCAL_FLOW_WARNING_CODE,
                message=(
                    f"Local flow from {source_callable} to {target_callable} "
                    f"({', '.join(rules)})"
                ),
                callable=target_callable,
                handle=issue_handle,
                filename=target_file,
                line=target_line,
                # Canonical endpoints contain a line number, but no columns.
                start=1,
                end=1,
                preconditions=[],
                postconditions=[],
                initial_sources=[],
                final_sinks=[],
                features=[f"local-flow-canonical-id:{canonical_id}"]
                + [f"local-flow-rule:{rule}" for rule in rules],
                callable_line=target_line,
                fix_info=None,
            ),
        )

    def _issue_handle(self, canonical_id: str) -> str:
        return f"ts-local-flow:{self.repository}:{self.project}:v1:{canonical_id}"


def _load_flows_to_rules(input: AnalysisOutput) -> dict[str, list[str]]:
    if input.directory is None:
        raise LocalFlowParserError("TS Local Flow import requires a results directory")
    path = Path(input.directory) / "flows-to-rules.json"
    try:
        contents = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise LocalFlowParserError(
            f"cannot read flows-to-rules file `{path}`"
        ) from error
    return _validate_rule_mapping(_decode_flows_to_rules(contents))


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
