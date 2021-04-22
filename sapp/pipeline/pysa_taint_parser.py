# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Parse Pysa/Taint output for Zoncolan processing"""

import logging
import sys
from collections import defaultdict
from typing import (
    cast,
    IO,
    Any,
    Dict,
    Iterable,
    List,
    Set,
    Optional,
    Tuple,
    Union,
)

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

import ujson as json

from .. import errors
from ..analysis_output import AnalysisOutput, Metadata
from . import (
    flatten_features,
    ParseFeature,
    ParsePosition,
    ParseTypeInterval,
    ParseConditionTuple,
    ParseIssueCondition,
    ParseIssueConditionTuple,
    ParseIssueLeaf,
    ParseIssueTuple,
    SourceLocation,
)
from .base_parser import (
    BaseParser,
    EntryPosition,
    ParseType,
    log_trace_keyerror_in_generator,
)


log: logging.Logger = logging.getLogger("sapp")


class TraceFragment(TypedDict):
    callee: str
    port: str
    location: ParsePosition
    leaves: Iterable[ParseIssueLeaf]
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
        for entry in self._parse_basic(handle):
            yield from self._parse_by_type(entry)

    # Instead of returning the actual json from the AnalysisOutput, we return
    # location information so it can be retrieved later.
    def get_json_file_offsets(self, input: AnalysisOutput) -> Iterable[EntryPosition]:
        for handle in input.file_handles():
            for entry, position in self._parse_v2(handle):
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

    def _parse_basic(self, handle: IO[str]) -> Iterable[Dict[str, Any]]:
        file_version = self._guess_file_version(handle)
        if file_version == 2:
            for entry, _ in self._parse_v2(handle):
                yield entry
        else:
            yield from self._parse_v1(handle)

    def _parse_v1(self, handle: IO[str]) -> Iterable[Dict[str, Any]]:
        data = json.load(handle)
        config = data["config"]
        self.repo_dirs = [config["repo"]]
        results = data["results"]
        return results

    def _parse_v2(
        self, handle: IO[str]
    ) -> Iterable[Tuple[Dict[str, Any], Dict[str, int]]]:
        """Parse analysis in jsonlines format:
        { "file_version": 2, "config": <json> }
        { <error1> }
        { <error2> }
        ...
        """
        header = json.loads(handle.readline())
        assert header["file_version"] == 2

        shard = 0

        offset, line = handle.tell(), handle.readline()
        while line:
            entry = json.loads(line)
            if entry:
                position = {"shard": shard, "offset": offset}
                yield entry, position
            offset, line = handle.tell(), handle.readline()

    def _guess_file_version(self, handle: IO[str]) -> int:
        first_line = handle.readline()
        try:
            json_first_line = json.loads(first_line)
            version = json_first_line["file_version"]
        # Falling back on v1 for expected errors
        except KeyError as e:
            if e.args[0] != "file_version":
                raise
            version = 1
        except ValueError:
            version = 1
            pass

        handle.seek(0)
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
        yield from self._parse_model_sources(callable, json["sources"])
        yield from self._parse_model_sinks(callable, json["sinks"])

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
                    titos=[],
                    leaves=[
                        (kind, distance) for (_, kind, distance) in fragment["leaves"]
                    ],
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
                    leaves=[
                        (kind, distance) for (_, kind, distance) in fragment["leaves"]
                    ],
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
            bw_features,
        ) = self._parse_issue_traces(json["traces"], "backward", "sink")
        (
            postconditions,
            initial_sources,
            fw_features,
        ) = self._parse_issue_traces(json["traces"], "forward", "source")

        if "features" in json:
            features: Iterable[ParseFeature] = json["features"]
        else:
            features: Iterable[ParseFeature] = bw_features + fw_features  # legacy

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
            features=flatten_features(features),
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
    ) -> Tuple[List[ParseIssueConditionTuple], Set[ParseIssueLeaf], List[ParseFeature]]:
        for trace in traces:
            if trace["name"] == name:
                return self._parse_issue_trace_fragments(leaf_port, trace["roots"])
        return ([], set(), [])

    def _parse_issue_trace_fragments(
        self, leaf_port: str, traces: List[Dict[str, Any]]
    ) -> Tuple[List[ParseIssueConditionTuple], Set[ParseIssueLeaf], List[ParseFeature]]:
        fragments = []
        leaf_distances = set()
        all_features = []

        for trace in traces:
            for fragment in self._parse_trace_fragment(leaf_port, trace):
                # Stripping the leaf_detail away for areas that
                #   only expect (leaf_kind, depth)
                leaves = fragment["leaves"]
                new_fragment = cast(ParseIssueCondition, fragment.copy())
                new_fragment["leaves"] = [
                    (kind, length) for (_, kind, length) in leaves
                ]
                fragments.append(ParseIssueConditionTuple.from_typed_dict(new_fragment))
                # Leaf distances should be represented as:
                #   (leaf_detail, leaf_kind, depth)
                leaf_distances.update(leaves)
                all_features.extend(fragment["features"])

        return (fragments, leaf_distances, all_features)

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
            for leaf_name, leaf_kind, distance, port in leaves:
                port = port or leaf_port
                callee_name = "leaf"
                if leaf_name is not None:
                    callee_name = leaf_name
                leaf_name_and_port_to_leaves[(callee_name, port)].append(
                    (leaf_name, leaf_kind, distance)
                )

            for ((callee_name, port), leaves) in leaf_name_and_port_to_leaves.items():
                fragment: TraceFragment = {
                    "callee": callee_name,
                    "port": port,
                    "location": self._adjust_location(trace["root"]),
                    "leaves": leaves,
                    "titos": trace.get("tito", []),
                    "features": trace.get("features", []),
                    "type_interval": None,
                }
                yield fragment
        elif "call" in trace:
            call = trace["call"]
            location = self._adjust_location(call["position"])
            port = call["port"]
            resolves_to = call.get("resolves_to", [])
            length = call.get("length", 0)
            leaves = [(name, kind, length) for (name, kind, _, _) in leaves]

            for resolved in resolves_to:
                fragment: TraceFragment = {
                    "callee": resolved,
                    "port": port,
                    "location": location,
                    "leaves": leaves,
                    "titos": [
                        self._adjust_location(tito) for tito in trace.get("tito", [])
                    ],
                    "features": trace.get("features", []),
                    "type_interval": None,
                }
                yield fragment

    def _adjust_location(self, location: ParsePosition) -> ParsePosition:
        return {**location, "start": location["start"] + 1}  # pyre-ignore[7]

    def _leaf_name(self, leaf: Dict[str, Any]) -> str:
        return leaf.get("name", None)

    def _leaf_port(self, leaf: Dict[str, Any]) -> str:
        return leaf.get("port", None)

    def _parse_leaves(
        self, leaves: List[Dict[str, Any]]
    ) -> List[Tuple[str, str, int, Optional[str]]]:
        """
        Returns a list of tuples ((leaf_name, leaf_kind, distance, port)).
        We only return a port in the case that exactly one matches the leaf for the
        trace frame.
        """
        return [
            (self._leaf_name(leaf), leaf["kind"], 0, self._leaf_port(leaf))
            for leaf in leaves
        ]

    @staticmethod
    def is_supported(metadata: Metadata) -> bool:
        return metadata.tool == "pysa"
