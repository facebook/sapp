# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Parse Pysa/Taint output for Zoncolan processing"""

import logging
import sys
from collections import defaultdict
from typing import (
    Any,
    Dict,
    IO,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    Union,
    cast,
)

import ujson as json

from .. import errors
from ..analysis_output import AnalysisOutput, Metadata
from . import (
    ParseConditionTuple,
    ParseFeature,
    ParseIssueCondition,
    ParseIssueConditionTuple,
    ParseIssueLeaf,
    ParseIssueTuple,
    ParsePosition,
    ParseTypeInterval,
    SourceLocation,
    flatten_features,
)
from .base_parser import (
    BaseParser,
    EntryPosition,
    ParseType,
    log_trace_keyerror_in_generator,
)

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict


log: logging.Logger = logging.getLogger("sapp")


class LeafWithPort(NamedTuple):
    name: Optional[str]
    kind: str
    port: Optional[str]


class LeafWithDistance(NamedTuple):
    name: Optional[str]
    kind: str
    distance: int


class TraceFragment(TypedDict):
    callee: str
    port: str
    location: ParsePosition
    leaves: Iterable[LeafWithDistance]
    titos: Iterable[ParsePosition]
    features: Iterable[ParseFeature]
    type_interval: Optional[ParseTypeInterval]


class Parser(BaseParser):
    """The parser takes a json file as input, and provides a simplified output
    for the Processor.
    """

    def parse(
        self, input: AnalysisOutput
    ) -> Iterable[Union[ParseConditionTuple, ParseIssueTuple]]:
        for handle in input.file_handles():
            for entry in self.parse_handle(handle):
                yield entry

    def parse_handle(
        self, handle: IO[str]
    ) -> Iterable[Union[ParseConditionTuple, ParseIssueTuple]]:
        for entry, _ in self._parse_entries(handle):
            yield from self._parse_by_type(entry)

    # Instead of returning the actual json from the AnalysisOutput, we return
    # location information so it can be retrieved later.
    def get_json_file_offsets(self, input: AnalysisOutput) -> Iterable[EntryPosition]:
        for handle in input.file_handles():
            for entry, position in self._parse_entries(handle):
                callable = self._get_callable(entry["data"].get("callable")).lstrip(
                    "\\"
                )
                yield EntryPosition(
                    callable=callable,
                    shard=position["shard"],
                    offset=position["offset"],
                )

    # Given a path and an offset, return the json in mostly-raw form.
    def get_json_from_file_offset(self, path: str, offset: int) -> Dict[str, Any]:
        with open(path) as fh:
            fh.seek(offset)
            return json.loads(fh.readline())

    def _parse_entries(
        self, handle: IO[str]
    ) -> Iterable[Tuple[Dict[str, Any], Dict[str, int]]]:
        """Parse analysis in jsonlines format:
        { "file_version": 2, "config": <json> }
        { <error1> }
        { <error2> }
        ...
        """
        file_version = self._parse_file_version(handle)
        if file_version < 2:
            raise AssertionError(
                f"File version `{file_version}` is no longer supported."
            )
        if file_version > 2:
            raise AssertionError(f"Unknown file version `{file_version}`.")

        offset, line = handle.tell(), handle.readline()
        while line:
            entry = json.loads(line)
            if entry:
                position = {"shard": 0, "offset": offset}
                yield entry, position
            offset, line = handle.tell(), handle.readline()

    def _parse_file_version(self, handle: IO[str]) -> int:
        first_line = handle.readline().strip()
        try:
            json_first_line = json.loads(first_line)
            version = json_first_line["file_version"]
        except ValueError:
            raise AssertionError(
                f"First line is not valid JSON.\nReceived: `{first_line}`"
            )
        except KeyError:
            raise AssertionError(
                "First entry must have a `file_version` attribute.\n"
                f"Received: `{first_line}`"
            )

        return version

    def _parse_by_type(
        self, entry: Dict[str, Any]
    ) -> Iterable[Union[ParseConditionTuple, ParseIssueTuple]]:
        if entry["kind"] == "model":
            yield from self._parse_model(entry["data"])
        elif entry["kind"] == "issue":
            yield from self._parse_issue(entry["data"])

    @staticmethod
    def _get_callable(callable: str) -> str:
        return callable

    @log_trace_keyerror_in_generator
    def _parse_model(self, json: Dict[str, Any]) -> Iterable[ParseConditionTuple]:
        callable = json["callable"]
        yield from self._parse_model_sources(callable, json.get("sources", []))
        yield from self._parse_model_sinks(callable, json.get("sinks", []))

    def _parse_model_sources(
        self, callable: str, source_traces: List[Dict[str, Any]]
    ) -> Iterable[ParseConditionTuple]:
        for source_trace in source_traces:
            port = source_trace["port"]
            for fragment in self._parse_trace_fragments(
                "source", source_trace["taint"]
            ):
                yield ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller=callable,
                    callee=fragment["callee"],
                    callee_location=SourceLocation.from_typed_dict(
                        fragment["location"]
                    ),
                    filename=fragment["location"]["filename"],
                    titos=list(map(SourceLocation.from_typed_dict, fragment["titos"])),
                    leaves=[(leaf.kind, leaf.distance) for leaf in fragment["leaves"]],
                    caller_port=port,
                    callee_port=fragment["port"],
                    type_interval=None,
                    features=[],
                    annotations=[],
                )

    def _parse_model_sinks(
        self, callable: str, sink_traces: List[Dict[str, Any]]
    ) -> Iterable[ParseConditionTuple]:
        for sink_trace in sink_traces:
            port = sink_trace["port"]
            for fragment in self._parse_trace_fragments("sink", sink_trace["taint"]):
                yield ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller=callable,
                    callee=fragment["callee"],
                    callee_location=SourceLocation.from_typed_dict(
                        fragment["location"]
                    ),
                    filename=fragment["location"]["filename"],
                    titos=list(map(SourceLocation.from_typed_dict, fragment["titos"])),
                    leaves=[(leaf.kind, leaf.distance) for leaf in fragment["leaves"]],
                    caller_port=port,
                    callee_port=fragment["port"],
                    type_interval=None,
                    features=[],
                    annotations=[],
                )

    @log_trace_keyerror_in_generator
    def _parse_issue(self, json: Dict[str, Any]) -> Iterable[ParseIssueTuple]:
        (
            preconditions,
            final_sinks,
        ) = self._parse_issue_traces(json["traces"], "backward", "sink")
        (
            postconditions,
            initial_sources,
        ) = self._parse_issue_traces(json["traces"], "forward", "source")

        yield ParseIssueTuple(
            code=json["code"],
            line=json["line"],
            callable_line=json["callable_line"],
            start=json["start"],
            end=json["end"],
            callable=json["callable"],
            handle=self._generate_issue_master_handle(json),
            message=json["message"],
            filename=self._extract_filename(json["filename"]),
            preconditions=preconditions,
            final_sinks=final_sinks,
            postconditions=postconditions,
            initial_sources=initial_sources,
            fix_info=None,
            features=flatten_features(json["features"]),
        )

    def _generate_issue_master_handle(self, issue: Dict[str, Any]) -> str:
        line = issue["line"] - issue["callable_line"]
        return self.compute_master_handle(
            callable=issue["callable"],
            line=line,
            start=issue["start"],
            end=issue["end"],
            code=issue["code"],
        )

    def _extract_filename(self, complete_filename: str) -> str:
        repo_dirs = self.repo_dirs
        if not repo_dirs:
            return complete_filename
        if not complete_filename.startswith("/"):
            # already relative
            return complete_filename
        for repo_dir in repo_dirs:
            repo_dir = repo_dir.rstrip("/")
            if repo_dir != "" and complete_filename.startswith(repo_dir):
                return complete_filename[len(repo_dir) + 1 :]

        raise errors.AIException(
            "Expected filename ({}) to start with repo_dir ({}). "
            "Check the --repo-dir option.".format(complete_filename, repo_dirs)
        )

    def _parse_issue_traces(
        self, traces: List[Dict[str, Any]], name: str, leaf_port: str
    ) -> Tuple[List[ParseIssueConditionTuple], Set[ParseIssueLeaf]]:
        for trace in traces:
            if trace["name"] == name:
                return self._parse_issue_trace_fragments(leaf_port, trace["roots"])

        raise AssertionError(f"Could not find `{name}` in trace.\nReceived: `{traces}`")

    def _parse_issue_trace_fragments(
        self, leaf_port: str, traces: List[Dict[str, Any]]
    ) -> Tuple[List[ParseIssueConditionTuple], Set[ParseIssueLeaf]]:
        fragments = []
        leaf_distances = set()

        for trace in traces:
            for fragment in self._parse_trace_fragment(leaf_port, trace):
                # Stripping the leaf_detail away for areas that
                #   only expect (leaf_kind, depth)
                leaves = fragment["leaves"]
                new_fragment = cast(ParseIssueCondition, fragment.copy())
                new_fragment["leaves"] = [(leaf.kind, leaf.distance) for leaf in leaves]
                fragments.append(ParseIssueConditionTuple.from_typed_dict(new_fragment))
                # Leaf distances should be represented as:
                #   (leaf_detail, leaf_kind, depth)
                leaf_distances.update(leaves)

        return (fragments, leaf_distances)

    def _parse_trace_fragments(
        self, leaf_port: str, traces: List[Dict[str, Any]]
    ) -> Iterable[TraceFragment]:
        for trace in traces:
            yield from self._parse_trace_fragment(leaf_port, trace)

    def _parse_trace_fragment(
        self, leaf_port: str, trace: Dict[str, Any]
    ) -> Iterable[TraceFragment]:
        # For now we don't have leaf distances.
        leaves = self._parse_leaves(trace.get("leaves", []))
        if "root" in trace:
            leaf_name_and_port_to_leaves = defaultdict(list)
            for leaf in leaves:
                port = leaf.port or leaf_port
                callee_name = leaf.name or "leaf"
                leaf_name_and_port_to_leaves[(callee_name, port)].append(leaf)

            for ((callee_name, port), leaves) in leaf_name_and_port_to_leaves.items():
                fragment: TraceFragment = {
                    "callee": callee_name,
                    "port": port,
                    "location": self._adjust_location(trace["root"]),
                    "leaves": [
                        LeafWithDistance(name=leaf.name, kind=leaf.kind, distance=0)
                        for leaf in leaves
                    ],
                    "titos": list(map(self._adjust_location, trace.get("tito", []))),
                    "features": trace.get("features", []),
                    "type_interval": None,
                }
                yield fragment
        elif "call" in trace:
            call = trace["call"]
            port = call["port"]
            resolves_to = call.get("resolves_to", [])
            length = call.get("length", 0)
            leaves = [
                LeafWithDistance(name=leaf.name, kind=leaf.kind, distance=length)
                for leaf in leaves
            ]

            for resolved in resolves_to:
                fragment: TraceFragment = {
                    "callee": resolved,
                    "port": port,
                    "location": self._adjust_location(call["position"]),
                    "leaves": leaves,
                    "titos": list(map(self._adjust_location, trace.get("tito", []))),
                    "features": trace.get("features", []),
                    "type_interval": None,
                }
                yield fragment
        elif "decl" in trace:
            pass  # User-declared fragment.
        else:
            raise AssertionError(f"Unexpected trace fragment.\nReceived: `{trace}`")

    def _adjust_location(self, location: ParsePosition) -> ParsePosition:
        return {**location, "start": location["start"] + 1}  # pyre-ignore[7]

    def _parse_leaves(self, leaves: List[Dict[str, Any]]) -> List[LeafWithPort]:
        return [
            LeafWithPort(
                name=leaf.get("name", None),
                kind=leaf["kind"],
                port=leaf.get("port", None),
            )
            for leaf in leaves
        ]

    @staticmethod
    def is_supported(metadata: Metadata) -> bool:
        return metadata.tool == "pysa"
