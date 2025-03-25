# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""Parse Pysa/Taint output for Zoncolan processing"""

import functools
import json
import logging
import sys
from collections import defaultdict
from typing import (
    Any,
    Dict,
    FrozenSet,
    IO,
    Iterable,
    List,
    Literal,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    Union,
)

from .. import errors
from ..analysis_output import AnalysisOutput, Metadata
from . import (
    flatten_features_to_parse_trace_feature,
    ParseConditionTuple,
    ParseError,
    ParseIssueConditionTuple,
    ParseIssueLeaf,
    ParseIssueTuple,
    ParseTraceAnnotation,
    ParseTraceAnnotationSubtrace,
    ParseTraceFeature,
    ParseTypeInterval,
    SourceLocation,
)
from .base_parser import BaseParser, EntryPosition, ParseType

log: logging.Logger = logging.getLogger("sapp")


class TraceFeature(NamedTuple):
    name: str

    def to_parse_feature(self) -> ParseTraceFeature:
        return ParseTraceFeature(name=self.name, locations=[])


class LeafWithDistance(NamedTuple):
    name: Optional[str]
    kind: str
    distance: int


class LeafWithPortDistance(NamedTuple):
    name: Optional[str]
    kind: str
    port: Optional[str]
    distance: int

    def discard_port(self) -> LeafWithDistance:
        return LeafWithDistance(name=self.name, kind=self.kind, distance=self.distance)


class TraceFragmentKey(NamedTuple):
    callee: str
    port: str
    location: SourceLocation
    type_interval: Optional[ParseTypeInterval]
    features: FrozenSet[TraceFeature]
    trace_annotations: FrozenSet[ParseTraceAnnotation]


# Represents a trace frame (source or sink) in a format similar to SAPP.
class TraceFragment(NamedTuple):
    callee: str
    port: str
    location: SourceLocation
    leaves: List[LeafWithDistance]
    titos: List[SourceLocation]
    features: FrozenSet[TraceFeature]
    type_interval: Optional[ParseTypeInterval]
    trace_annotations: FrozenSet[ParseTraceAnnotation]

    def key(self) -> TraceFragmentKey:
        return TraceFragmentKey(
            callee=self.callee,
            port=self.port,
            location=self.location,
            type_interval=self.type_interval,
            features=self.features,
            trace_annotations=self.trace_annotations,
        )

    @staticmethod
    def merge(a: "TraceFragment", b: "TraceFragment") -> "TraceFragment":
        if a.key() != b.key():
            raise AssertionError("Trace fragments cannot be merged")
        return TraceFragment(
            callee=a.callee,
            port=a.port,
            location=a.location,
            leaves=sorted(set(a.leaves) | set(b.leaves)),
            titos=sorted(set(a.titos) | set(b.titos)),
            features=a.features,
            type_interval=a.type_interval,
            trace_annotations=a.trace_annotations,
        )


class Parser(BaseParser):
    """The parser takes a json file as input, and provides a simplified output
    for the Processor.
    """

    _file_version: Optional[int] = None

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
        { "file_version": 3, "config": <json> }
        { <error1> }
        { <error2> }
        ...
        """
        file_version = self._parse_file_version(handle)
        if file_version < 3:
            raise ParseError(f"File version `{file_version}` is no longer supported.")
        if file_version > 3:
            raise ParseError(f"Unknown file version `{file_version}`.")
        self._file_version = file_version

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
        except ValueError as e:
            raise ParseError(
                "First line is not valid JSON.", received=first_line
            ) from e
        except KeyError as e:
            raise ParseError(
                "First entry must have a `file_version` attribute.", received=first_line
            ) from e

        return version

    def _parse_by_type(
        self, entry: Dict[str, Any]
    ) -> Iterable[Union[ParseConditionTuple, ParseIssueTuple]]:
        if entry["kind"] == "model":
            yield from self._parse_model(entry["data"])
        elif entry["kind"] == "issue":
            yield from self._parse_issue(entry["data"])
        else:
            raise ParseError("Unexpected kind in entry", received=entry["kind"])

    @staticmethod
    def _get_callable(callable: str) -> str:
        return callable

    def _parse_model(self, json: Dict[str, Any]) -> Iterable[ParseConditionTuple]:
        callable = json["callable"]
        filename = json.get("filename")
        yield from self._parse_model_sources(
            callable, filename, json.get("sources", [])
        )
        yield from self._parse_model_sinks(callable, filename, json.get("sinks", []))

    def _parse_model_sources(
        self,
        callable: str,
        filename: Optional[str],
        source_traces: List[Dict[str, Any]],
    ) -> Iterable[ParseConditionTuple]:
        for source_trace in source_traces:
            port = source_trace["port"]
            for fragment in self._parse_trace_fragments(
                "source", source_trace["taint"]
            ):
                if filename is None:
                    raise ParseError(
                        f"Model for `{callable}` has a source but no filename"
                    )
                yield ParseConditionTuple(
                    type=ParseType.POSTCONDITION,
                    caller=callable,
                    callee=fragment.callee,
                    callee_location=fragment.location,
                    filename=filename,
                    titos=fragment.titos,
                    leaves=[(leaf.kind, leaf.distance) for leaf in fragment.leaves],
                    caller_port=port,
                    callee_port=fragment.port,
                    type_interval=fragment.type_interval,
                    features=[
                        feature.to_parse_feature()
                        for feature in sorted(fragment.features)
                    ],
                    annotations=sorted(fragment.trace_annotations),
                )

    def _parse_model_sinks(
        self, callable: str, filename: Optional[str], sink_traces: List[Dict[str, Any]]
    ) -> Iterable[ParseConditionTuple]:
        for sink_trace in sink_traces:
            port = sink_trace["port"]
            for fragment in self._parse_trace_fragments("sink", sink_trace["taint"]):
                if filename is None:
                    raise ParseError(
                        f"Model for `{callable}` has a sink but no filename"
                    )
                yield ParseConditionTuple(
                    type=ParseType.PRECONDITION,
                    caller=callable,
                    callee=fragment.callee,
                    callee_location=fragment.location,
                    filename=filename,
                    titos=fragment.titos,
                    leaves=[(leaf.kind, leaf.distance) for leaf in fragment.leaves],
                    caller_port=port,
                    callee_port=fragment.port,
                    type_interval=fragment.type_interval,
                    features=[
                        feature.to_parse_feature()
                        for feature in sorted(fragment.features)
                    ],
                    annotations=sorted(fragment.trace_annotations),
                )

    def _parse_issue(self, json: Dict[str, Any]) -> Iterable[ParseIssueTuple]:
        (
            preconditions,
            final_sinks,
        ) = self._parse_issue_traces(json["traces"], "backward", "sink")
        (
            postconditions,
            initial_sources,
        ) = self._parse_issue_traces(json["traces"], "forward", "source")

        location = self._parse_location(json)
        features = self._parse_features(json["features"])

        yield ParseIssueTuple(
            code=json["code"],
            line=location.line_no,
            callable_line=json["callable_line"],
            start=location.begin_column,
            end=location.end_column,
            callable=json["callable"],
            handle=self._generate_issue_master_handle(json),
            message=json["message"],
            filename=self._extract_filename(json["filename"]),
            preconditions=preconditions,
            final_sinks=final_sinks,
            postconditions=postconditions,
            initial_sources=initial_sources,
            fix_info=None,
            features=sorted(feature.name for feature in features),
        )

    def _generate_issue_master_handle(self, issue: Dict[str, Any]) -> str:
        if "master_handle" in issue:
            return issue["master_handle"]

        # For backward compatibility.
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
            if not repo_dir:
                continue
            repo_dir = repo_dir.rstrip("/")
            if repo_dir != "" and complete_filename.startswith(repo_dir):
                return complete_filename[len(repo_dir) + 1 :]

        raise errors.AIException(
            "Expected filename ({}) to start with repo_dir ({}). "
            "Check the --repo-dir option.".format(complete_filename, repo_dirs)
        )

    def _parse_issue_traces(
        self,
        traces: List[Dict[str, Any]],
        name: Union[Literal["forward"], Literal["backward"]],
        leaf_port: Union[Literal["source"], Literal["sink"]],
    ) -> Tuple[List[ParseIssueConditionTuple], Set[ParseIssueLeaf]]:
        for trace in traces:
            if trace["name"] == name:
                return self._parse_issue_trace_fragments(leaf_port, trace["roots"])

        raise ParseError(f"Could not find `{name}` in trace.", received=traces)

    def _parse_issue_trace_fragments(
        self,
        leaf_port: Union[Literal["source"], Literal["sink"]],
        traces: List[Dict[str, Any]],
    ) -> Tuple[List[ParseIssueConditionTuple], Set[ParseIssueLeaf]]:
        fragments: List[ParseIssueConditionTuple] = []
        leaf_distances: Set[ParseIssueLeaf] = set()

        for fragment in self._parse_trace_fragments(leaf_port, traces):
            leaves = fragment.leaves
            fragments.append(
                ParseIssueConditionTuple(
                    callee=fragment.callee,
                    port=fragment.port,
                    location=fragment.location,
                    leaves=[(leaf.kind, leaf.distance) for leaf in leaves],
                    titos=fragment.titos,
                    features=[
                        feature.to_parse_feature()
                        for feature in sorted(fragment.features)
                    ],
                    type_interval=fragment.type_interval,
                    annotations=sorted(fragment.trace_annotations),
                )
            )
            leaf_distances.update(
                (leaf.name, leaf.kind, leaf.distance) for leaf in leaves
            )

        return (fragments, leaf_distances)

    def _parse_trace_fragments(
        self,
        leaf_port: Union[Literal["source"], Literal["sink"]],
        traces: List[Dict[str, Any]],
    ) -> Iterable[TraceFragment]:
        # We could emit each fragment as a different trace frame, but we want to emit
        # a single frame for all fragments with the same key, to save database space.
        fragments_by_key: defaultdict[TraceFragmentKey, List[TraceFragment]] = (
            defaultdict(list)
        )

        for trace in traces:
            for fragment in self._parse_trace_fragment(leaf_port, trace):
                fragments_by_key[fragment.key()].append(fragment)

        for fragments_with_same_key in fragments_by_key.values():
            yield functools.reduce(TraceFragment.merge, fragments_with_same_key)

    def _parse_trace_fragment(
        self,
        leaf_port: Union[Literal["source"], Literal["sink"]],
        trace: Dict[str, Any],
    ) -> Iterable[TraceFragment]:
        tito_positions = [
            self._parse_location(location)
            for location in trace.get("tito_positions", [])
        ]
        shared_local_features = self._parse_features(trace.get("local_features", []))
        type_interval = self._parse_type_interval(trace)
        # The old syntax would store `extra_traces` here. We preserve this for backward compatibility.
        shared_trace_annotations = self._parse_extra_traces(trace)

        if "origin" in trace:
            location = self._parse_location(trace["origin"])

            # Turn leaves into direct callees and group by (callee, port)
            for flow_details in trace.get("kinds", []):
                kind = flow_details["kind"]
                distance = flow_details.get("length", 0)
                local_features = shared_local_features | self._parse_features(
                    flow_details.get("local_features", [])
                )
                trace_annotations = (
                    self._parse_extra_traces(flow_details) | shared_trace_annotations
                )
                for leaf in self._parse_leaves(kind, distance, flow_details):
                    yield TraceFragment(
                        callee=leaf.name or "leaf",
                        port=leaf.port or leaf_port,
                        location=location,
                        leaves=[leaf.discard_port()],
                        titos=tito_positions,
                        features=local_features,
                        type_interval=type_interval,
                        trace_annotations=trace_annotations,
                    )
        elif "call" in trace:
            call = trace["call"]
            port = call["port"]
            location = self._parse_location(call["position"])
            resolves_to = call.get("resolves_to", [])

            for flow_details in trace.get("kinds", []):
                kind = flow_details["kind"]
                distance = flow_details.get("length", 0)
                local_features = shared_local_features | self._parse_features(
                    flow_details.get("local_features", [])
                )
                trace_annotations = (
                    self._parse_extra_traces(flow_details) | shared_trace_annotations
                )
                leaves: List[LeafWithDistance] = [
                    leaf.discard_port()
                    for leaf in self._parse_leaves(kind, distance, flow_details)
                ]

                for resolved in resolves_to:
                    yield TraceFragment(
                        callee=resolved,
                        port=port,
                        location=location,
                        leaves=leaves,
                        titos=tito_positions,
                        features=local_features,
                        type_interval=type_interval,
                        trace_annotations=trace_annotations,
                    )
        elif "declaration" in trace:
            pass  # User-declared fragment.
        else:
            raise ParseError("Unexpected trace fragment.", received=trace)

    def _parse_type_interval(self, trace: Dict[str, Any]) -> ParseTypeInterval:
        receiver_interval = trace.get("receiver_interval")
        start, finish = 0, sys.maxsize
        if receiver_interval is not None:
            start = min(interval["lower"] for interval in receiver_interval)
            finish = max(interval["upper"] for interval in receiver_interval)
        preserves_type_context = trace.get("is_self_call", False)
        type_interval = ParseTypeInterval(
            start=start,
            finish=finish,
            preserves_type_context=preserves_type_context,
        )
        return type_interval

    def _parse_extra_traces(
        self, trace: Dict[str, Any]
    ) -> FrozenSet[ParseTraceAnnotation]:
        trace_annotations = []
        for extra_trace in trace.get("extra_traces", []):
            if "call" in extra_trace:
                call = extra_trace["call"]
                first_hops = [
                    ParseTraceAnnotationSubtrace(
                        callee=resolved,
                        port=call["port"],
                        position=self._parse_location(call["position"]),
                    )
                    for resolved in call["resolves_to"]
                ]
                if len(first_hops) == 0:
                    continue
                location = call["position"]
            elif "origin" in extra_trace:
                location = extra_trace["origin"]
                first_hops = []  # There is no subtrace to show
            else:
                raise ParseError('Expect key "call" or "origin" in "extra_traces".')
            source_location = self._parse_location(location)
            # The default values are used for backwards compatibility
            trace_kind = extra_trace.get("trace_kind", "tito_transform")
            leaf_kind = extra_trace.get("leaf_kind", extra_trace.get("kind"))
            trace_annotations.append(
                ParseTraceAnnotation(
                    location=source_location,
                    kind=trace_kind,
                    msg=extra_trace.get("message", ""),
                    leaf_kind=leaf_kind,
                    leaf_depth=0,
                    type_interval=None,
                    link=None,
                    trace_key=None,
                    titos=[],
                    subtraces=first_hops,
                )
            )

        return frozenset(trace_annotations)

    def _parse_features(self, json: List[Dict[str, Any]]) -> FrozenSet[TraceFeature]:
        return frozenset(
            TraceFeature(name=feature.name)
            for feature in flatten_features_to_parse_trace_feature(json)
        )

    def _parse_location(self, json: Dict[str, Any]) -> SourceLocation:
        return SourceLocation(
            line_no=json["line"],
            begin_column=self._adjust_start_location(json["start"]),
            end_column=json["end"],
        )

    def _adjust_start_location(self, start: int) -> int:
        return start + 1

    def _parse_leaves(
        self, kind: str, distance: int, flow_details: Dict[str, Any]
    ) -> List[LeafWithPortDistance]:
        leaves: List[LeafWithPortDistance] = []
        for leaf in flow_details.get("leaves", [{}]):
            leaves.append(
                LeafWithPortDistance(
                    name=leaf.get("name", None),
                    kind=kind,
                    port=leaf.get("port", None),
                    distance=distance,
                )
            )
        return leaves

    @staticmethod
    def is_supported(metadata: Metadata) -> bool:
        return metadata.tool == "pysa"
