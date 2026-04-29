# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""Parser for Prophecy static analysis output.

Prophecy is a taint analysis tool for TypeScript/JavaScript. It is planned for
open-source release.

Prophecy produces findings in NDJSON format.
Each line is a JSON object with kind="issue". The parser converts these into
SAPP's ParseIssueTuple/ParseConditionTuple types for ingestion into the
SAPP database.

Trace strategy (v1): Single-hop traces. Each issue gets one postcondition
(source leaf) and one precondition (sink leaf). Propagation chain details
are stored as features. This follows the Fontainebleau parser pattern.
"""

import json
import logging
from typing import Any, Dict, IO, Iterable, Optional, Set, Union

from ..analysis_output import AnalysisOutput, Metadata
from . import (
    ParseConditionTuple,
    ParseIssueConditionTuple,
    ParseIssueLeaf,
    ParseIssueTuple,
    SourceLocation,
)
from .base_parser import BaseParser

log: logging.Logger = logging.getLogger("sapp")


class Parser(BaseParser):
    """Parser for Prophecy taint analysis output.

    Input format: NDJSON (one JSON object per line), no header line.
    Each line has kind="issue" with traces in Fontainebleau-compatible format.
    """

    def parse(
        self, input: AnalysisOutput
    ) -> Iterable[Union[ParseConditionTuple, ParseIssueTuple]]:
        for handle in input.file_handles():
            yield from self.parse_handle(handle)

    def parse_handle(
        self, handle: IO[str]
    ) -> Iterable[Union[ParseConditionTuple, ParseIssueTuple]]:
        for entry, _position in self._parse(handle):
            yield from self._parse_by_type(entry)

    def _parse(
        self, handle: IO[str]
    ) -> Iterable[tuple[Dict[str, Any], Dict[str, Any]]]:
        """Parse NDJSON: one JSON object per line, no header."""
        offset, line = handle.tell(), handle.readline()
        while line:
            line = line.strip()
            if line:
                entry = json.loads(line)
                if entry:
                    position = {"shard": 0, "offset": offset}
                    yield entry, position
            offset, line = handle.tell(), handle.readline()

    def _parse_by_type(
        self, entry: Dict[str, Any]
    ) -> Iterable[Union[ParseConditionTuple, ParseIssueTuple]]:
        kind = entry.get("kind")
        if kind == "issue":
            yield from self._parse_issue(entry)
        # No "model" entries in v1 — single-hop traces only.

    def _parse_issue(self, json: Dict[str, Any]) -> Iterable[ParseIssueTuple]:
        code = json["code"]
        position = json["position"]
        callable_name = json["callable"]
        filename = self._extract_filename(json["filename"])

        # Parse traces following Fontainebleau's format
        preconditions, final_sinks = self._parse_issue_traces(
            json.get("traces", []), "backward", "sink"
        )
        postconditions, initial_sources = self._parse_issue_traces(
            json.get("traces", []), "forward", "source"
        )

        # Collect features
        features: list[str] = list(json.get("features", []))

        # Add propagation step descriptions as features for visibility
        for i, step in enumerate(json.get("propagation_steps", [])):
            description = step.get("description", "")
            step_kind = step.get("kind", "unknown")
            if description:
                features.append(f"prophecy-step-{i}:{step_kind}: {description}")

        # fix_info passed through directly (serialized to JSON by ModelGenerator)
        fix_info: Optional[Dict[str, Any]] = json.get("fix_info")

        yield ParseIssueTuple(
            code=code,
            line=position["line"],
            callable_line=json.get("callable_line"),
            start=position["start"],
            end=position["end"],
            callable=callable_name,
            handle=self.compute_master_handle(
                callable=callable_name,
                line=position["line"],
                start=position["start"],
                end=position["end"],
                code=code,
            ),
            message=json["description"],
            filename=filename,
            preconditions=preconditions,
            final_sinks=final_sinks,
            postconditions=postconditions,
            initial_sources=initial_sources,
            fix_info=fix_info,
            features=features,
        )

    def _parse_issue_traces(
        self,
        traces: list[Dict[str, Any]],
        direction: str,
        leaf_port: str,
    ) -> tuple[list[ParseIssueConditionTuple], Set[ParseIssueLeaf]]:
        """Parse traces from an issue entry.

        Args:
            traces: List of trace objects, each with a "forward" or "backward" key.
            direction: "forward" (postconditions/sources) or "backward"
                (preconditions/sinks).
            leaf_port: "source" or "sink" — the port name for the leaf.

        Returns:
            Tuple of (conditions for first-hop trace frames, leaf set).
        """
        conditions: list[ParseIssueConditionTuple] = []
        leaves: Set[ParseIssueLeaf] = set()

        for trace in traces:
            trace_data = trace.get(direction)
            if trace_data is None:
                continue

            if "trace_leaf" in trace_data:
                # Leaf trace — the source or sink origin
                leaf_kind = trace_data["kind"]
                leaf_position = trace_data["trace_leaf"]["position"]
                callee_location = self._get_location(leaf_position)

                leaf_names = [leaf["name"] for leaf in trace_data.get("leaves", [])]
                if not leaf_names:
                    leaf_names = [leaf_kind]

                titos = [
                    self._get_location(pos)
                    for pos in trace_data.get("local_trace", {}).get("positions", [])
                ]

                for leaf_name in leaf_names:
                    conditions.append(
                        ParseIssueConditionTuple(
                            callee=leaf_name,
                            port=leaf_port,
                            location=callee_location,
                            leaves=[(leaf_kind, 0)],
                            titos=titos,
                            features=[],
                            type_interval=None,
                            annotations=[],
                        )
                    )
                    leaves.add((leaf_name, leaf_kind, 0))

            elif "call" in trace_data:
                # Call trace — intermediate call edge (for future v2 support)
                call = trace_data["call"]
                callee_port = call["port"]
                callee_location = self._get_location(call["position"])

                titos = [
                    self._get_location(pos)
                    for pos in trace_data.get("local_trace", {}).get("positions", [])
                ]

                for flow_details in trace_data.get("kinds", []):
                    trace_length = flow_details.get("trace_len", 0)
                    kind = flow_details["kind"]
                    parse_leaves = [(kind, trace_length)]

                    for resolved_name in call.get("resolves_to", []):
                        conditions.append(
                            ParseIssueConditionTuple(
                                callee=resolved_name,
                                port=callee_port,
                                location=callee_location,
                                leaves=parse_leaves,
                                titos=titos,
                                features=[],
                                type_interval=None,
                                annotations=[],
                            )
                        )
                        leaves.add((None, kind, trace_length))

        return conditions, leaves

    def _get_location(self, entry: Optional[Dict[str, Any]]) -> SourceLocation:
        if entry is None:
            return SourceLocation(0, 0, 0)
        return SourceLocation(
            line_no=entry.get("line", 0),
            begin_column=entry.get("start", 0),
            end_column=entry.get("end", 0),
        )

    def _extract_filename(self, complete_filename: str) -> str:
        if complete_filename == "":
            return ""
        if not complete_filename.startswith("/"):
            # Already relative
            return complete_filename
        for repo_dir in self.repo_dirs:
            if not repo_dir:
                continue
            repo_dir = repo_dir.rstrip("/")
            if repo_dir != "" and complete_filename.startswith(repo_dir):
                return complete_filename[len(repo_dir) + 1 :]
        return complete_filename

    @staticmethod
    def is_supported(metadata: Metadata) -> bool:
        return metadata.tool == "prophecy"
